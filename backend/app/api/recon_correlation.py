"""Read-only deterministic links between stored, authorized reconnaissance data."""
import hashlib

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.asset import Asset
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.project import Project
from app.models.scope import Scope
from app.models.security_result import SecurityResult

router = APIRouter(tags=["Recon Correlation"])


def _observed_hosts(result: SecurityResult) -> list[str]:
    data = result.normalized_data or {}
    values = [data.get(key) for key in ("hostname", "host", "candidate_hostname")]
    if result.result_type == "endpoint":
        values.append(data.get("url"))
    hosts = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        candidate = value.strip().lower().rstrip(".")
        if "://" in candidate:
            from urllib.parse import urlsplit
            candidate = urlsplit(candidate).hostname or ""
        if candidate and candidate not in hosts:
            hosts.append(candidate)
    return hosts


@router.get("/projects/{project_id}/recon/correlation")
async def get_recon_correlation(project_id: int, db: AsyncSession = Depends(get_db)):
    if await db.get(Project, project_id) is None:
        raise HTTPException(status_code=404, detail="Project not found.")
    assets = list((await db.scalars(select(Asset).where(
        Asset.project_id == project_id).order_by(Asset.id))).all())
    scopes = list((await db.scalars(select(Scope).where(
        Scope.project_id == project_id).order_by(Scope.id))).all())
    results = list((await db.scalars(select(SecurityResult).where(
        SecurityResult.project_id == project_id).order_by(SecurityResult.id))).all())
    groups: dict[str, dict] = {}
    for asset in assets:
        host = asset.value.strip().lower().rstrip(".")
        group = groups.setdefault(host, {"hostname": host, "assets": [], "observations": [], "findings": []})
        group["assets"].append({"id": asset.id, "type": asset.asset_type, "source": asset.source})
    for result in results:
        for host in _observed_hosts(result):
            group = groups.setdefault(host, {"hostname": host, "assets": [], "observations": [], "findings": []})
            group["observations"].append({"id": result.id, "result_type": result.result_type,
                "title": result.title, "job_id": result.job_id, "tool_id": result.tool_id,
                "created_at": result.created_at})
    asset_hosts = {asset.id: asset.value.strip().lower().rstrip(".") for asset in assets}
    findings = list((await db.scalars(select(Finding).where(
        Finding.project_id == project_id, Finding.canonical_finding_id.is_(None)).order_by(Finding.id))).all())
    evidence_rows = list((await db.scalars(select(Evidence).where(
        Evidence.project_id == project_id).order_by(Evidence.id))).all())
    evidence_by_job: dict[int, list[int]] = {}
    for evidence in evidence_rows:
        if evidence.job_id is not None:
            evidence_by_job.setdefault(evidence.job_id, []).append(evidence.id)
    for finding in findings:
        host = asset_hosts.get(finding.asset_id)
        if not host and finding.endpoint:
            from urllib.parse import urlsplit
            host = urlsplit(finding.endpoint if "://" in finding.endpoint else "https://" + finding.endpoint).hostname
        if host:
            host = host.lower().rstrip(".")
            group = groups.setdefault(host, {"hostname": host, "assets": [], "observations": [], "findings": []})
            group["findings"].append({"id": finding.id, "title": finding.title,
                                      "severity": finding.severity, "job_id": finding.job_id,
                                      "identity": finding.identity_fingerprint})
    output = []
    for host, group in sorted(groups.items()):
        key = hashlib.sha256(f"{project_id}:{host}".encode("utf-8")).hexdigest()[:24]
        group["id"] = key
        group["scopes"] = [{"id": scope.id, "value": scope.value, "included": scope.included}
                           for scope in scopes
                           if host == scope.value.strip().lower().rstrip(".") or
                           host.endswith("." + scope.value.strip().lower().rstrip("."))]
        for observation in group["observations"]:
            observation["evidence_ids"] = evidence_by_job.get(observation["job_id"], [])
        group["observations"].sort(key=lambda item: item["id"])
        group["findings"].sort(key=lambda item: item["id"])
        output.append(group)
    return {"project_id": project_id, "groups": output}
