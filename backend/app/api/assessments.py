import json
import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.assessment import Assessment
from app.models.project import Project
from app.services.assessment_reports import build_report_snapshot, render_html, render_markdown
from app.services.security_audit import write_audit_log

router = APIRouter(prefix="/projects/{project_id}/assessments", tags=["Assessments & Reports"])
STATUSES = {"draft", "in_progress", "completed", "archived"}
AssessmentStatus = Literal["draft", "in_progress", "completed", "archived"]
TRANSITIONS = {"draft": {"in_progress", "archived"},
               "in_progress": {"completed", "archived"},
               "completed": {"archived"}, "archived": set()}

class AssessmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)

    @field_validator("name")
    @classmethod
    def name_must_contain_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Assessment name cannot be blank.")
        return value

class AssessmentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=10000)
    status: AssessmentStatus | None = None

    @field_validator("name")
    @classmethod
    def name_must_contain_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("Assessment name cannot be blank.")
        return value

class AssessmentResponse(BaseModel):
    id: int
    project_id: int
    name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    model_config = {"from_attributes": True}

async def _project(db: AsyncSession, project_id: int):
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(404, "Project not found.")
    return project

async def _assessment(db: AsyncSession, project_id: int, assessment_id: int):
    await _project(db, project_id)
    assessment = await db.scalar(select(Assessment).where(
        Assessment.id == assessment_id, Assessment.project_id == project_id))
    if assessment is None:
        raise HTTPException(404, "Assessment not found in this project.")
    return assessment

async def _report(db: AsyncSession, assessment: Assessment, action="assessment_report_generated"):
    await write_audit_log(db, project_id=assessment.project_id, user="local-user", action=action,
        entity_type="assessment", entity_id=assessment.id,
        details={"status": assessment.status, "snapshot_source": "stored_project_records"})
    await db.flush()
    report = await build_report_snapshot(db, assessment)
    await db.commit()
    return report

@router.post("", response_model=AssessmentResponse, status_code=201)
async def create_assessment(project_id: int, data: AssessmentCreate, db: AsyncSession = Depends(get_db)):
    await _project(db, project_id)
    assessment = Assessment(project_id=project_id, name=data.name.strip(),
                            description=data.description.strip() if data.description else None,
                            status="draft")
    db.add(assessment)
    await db.flush()
    await write_audit_log(db, project_id=project_id, user="local-user", action="assessment_created",
        entity_type="assessment", entity_id=assessment.id, details={"status": assessment.status})
    await db.commit()
    await db.refresh(assessment)
    return assessment

@router.get("", response_model=list[AssessmentResponse])
async def list_assessments(project_id: int, db: AsyncSession = Depends(get_db)):
    await _project(db, project_id)
    return list((await db.scalars(select(Assessment).where(
        Assessment.project_id == project_id).order_by(Assessment.created_at, Assessment.id))).all())

@router.get("/{assessment_id}", response_model=AssessmentResponse)
async def get_assessment(project_id: int, assessment_id: int, db: AsyncSession = Depends(get_db)):
    return await _assessment(db, project_id, assessment_id)

@router.patch("/{assessment_id}", response_model=AssessmentResponse)
async def update_assessment(project_id: int, assessment_id: int, data: AssessmentUpdate,
                            db: AsyncSession = Depends(get_db)):
    assessment = await _assessment(db, project_id, assessment_id)
    changes = data.model_dump(exclude_unset=True)
    new_status = changes.pop("status", None)
    if assessment.status == "archived" and changes:
        raise HTTPException(409, "Archived assessments cannot be edited.")
    for key, value in changes.items():
        setattr(assessment, key, value.strip() if isinstance(value, str) else value)
    if new_status is not None:
        if new_status not in STATUSES:
            raise HTTPException(422, "Unsupported assessment status.")
        if new_status != assessment.status and new_status not in TRANSITIONS[assessment.status]:
            raise HTTPException(409, f"Assessment cannot transition from {assessment.status} to {new_status}.")
        assessment.status = new_status
        if new_status == "completed":
            assessment.completed_at = datetime.now(timezone.utc)
    await write_audit_log(db, project_id=project_id, user="local-user", action="assessment_updated",
        entity_type="assessment", entity_id=assessment.id,
        details={"status": assessment.status, "changed_fields": sorted(data.model_dump(exclude_unset=True))})
    await db.commit()
    await db.refresh(assessment)
    return assessment

@router.get("/{assessment_id}/report")
async def get_report(project_id: int, assessment_id: int, db: AsyncSession = Depends(get_db)):
    assessment = await _assessment(db, project_id, assessment_id)
    return await _report(db, assessment)

@router.get("/{assessment_id}/report/statistics")
async def get_report_statistics(project_id: int, assessment_id: int, db: AsyncSession = Depends(get_db)):
    assessment = await _assessment(db, project_id, assessment_id)
    report = await _report(db, assessment, "assessment_report_statistics_generated")
    return report["risk_overview"]

def _filename(assessment: Assessment, extension: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_-]+", "_", assessment.name).strip("_")[:60] or "assessment"
    return f"assessment_{assessment.id}_{stem}.{extension}"

@router.get("/{assessment_id}/export/json")
async def export_json(project_id: int, assessment_id: int, db: AsyncSession = Depends(get_db)):
    assessment = await _assessment(db, project_id, assessment_id)
    report = await _report(db, assessment, "assessment_report_exported_json")
    return Response(content=json.dumps(report, ensure_ascii=False, indent=2), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{_filename(assessment, "json")}"'})

@router.get("/{assessment_id}/export/markdown")
async def export_markdown(project_id: int, assessment_id: int, db: AsyncSession = Depends(get_db)):
    assessment = await _assessment(db, project_id, assessment_id)
    report = await _report(db, assessment, "assessment_report_exported_markdown")
    return Response(content=render_markdown(report), media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_filename(assessment, "md")}"'})

@router.get("/{assessment_id}/export/html")
async def export_html(project_id: int, assessment_id: int, db: AsyncSession = Depends(get_db)):
    assessment = await _assessment(db, project_id, assessment_id)
    report = await _report(db, assessment, "assessment_report_exported_html")
    return Response(content=render_html(report), media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_filename(assessment, "html")}"'})
