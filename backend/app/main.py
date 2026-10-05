from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.projects import router as projects_router
from app.api.scopes import router as scopes_router
from app.api.scope_check import router as scope_check_router
from app.api.assets import router as assets_router
from app.api.findings import router as findings_router
from app.api.assessment_catalog import router as assessment_catalog_router
from app.api.security_jobs import router as security_jobs_router
from app.api.security_data import router as security_data_router
from app.api.security_assessment import router as security_assessment_router
from app.api.finding_risk import router as finding_risk_router
from app.api.assessments import router as assessments_router
from app.api.recon_correlation import router as recon_correlation_router
from app.api.advanced_assessment import router as advanced_assessment_router

from app.core.database import engine, verify_database_schema
from app.core.request_limits import RequestBodyLimitMiddleware
from app.services import recon_execution


@asynccontextmanager
async def lifespan(app: FastAPI):
    await verify_database_schema()
    await recon_execution.recover_interrupted_jobs()
    try:
        yield
    finally:
        await recon_execution.stop_all_jobs()
        await engine.dispose()


app = FastAPI(
    title="Bug Bounty Workbench",
    version="1.0.0",
    description="Scope-aware security assessment platform",
    lifespan=lifespan,
)
app.add_middleware(RequestBodyLimitMiddleware, max_request_bytes=2 * 1024 * 1024)

app.include_router(projects_router)
app.include_router(scopes_router)
app.include_router(scope_check_router)
app.include_router(assets_router)
app.include_router(findings_router)
app.include_router(assessment_catalog_router)
app.include_router(security_jobs_router)
app.include_router(security_data_router)
app.include_router(security_assessment_router)
app.include_router(finding_risk_router)
app.include_router(assessments_router)
app.include_router(recon_correlation_router)
app.include_router(advanced_assessment_router)


@app.get("/")
async def root():
    return {
        "name": "Bug Bounty Workbench",
        "version": "1.0.0",
        "status": "online",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "backend",
    }
