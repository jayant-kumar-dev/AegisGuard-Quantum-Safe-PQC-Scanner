"""
AegisGuard — Enterprise Reporting Routes
Executive, on-demand, history, schedule, and export endpoints.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Body, HTTPException, Query, Response
from pydantic import BaseModel, Field

from services.report_service import (
    generate_executive_report,
    generate_on_demand_report,
    get_report_history,
    get_scan_history,
    get_report_by_id,
    generate_report_pdf_bytes,
)
from services.scheduler_service import create_schedule, list_schedules, get_schedule

router = APIRouter(tags=["reporting"])
logger = logging.getLogger("AegisGuard.ReportingRoutes")


class ExecutiveReportRequest(BaseModel):
    domains: List[str] = Field(..., min_length=1, description="Domains/hosts to include")
    generated_by: str = Field(default="api")


class OnDemandReportRequest(BaseModel):
    domains: List[str] = Field(default_factory=list)
    scan_ids: List[int] = Field(default_factory=list)
    generated_by: str = Field(default="api")


class ScheduleRequest(BaseModel):
    report_type: str = Field(default="executive")
    frequency: str = Field(default="daily", description="hourly|daily|weekly|monthly")
    targets: List[str] = Field(..., min_length=1)
    email: str = Field(default="")
    timezone: str = Field(default="UTC")


class LegacyGenerateRequest(BaseModel):
    report_type: str = Field(default="executive")
    targets: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    scan_ids: List[int] = Field(default_factory=list)
    generated_by: str = Field(default="legacy-api")
    include_sections: List[str] = Field(default_factory=list)


@router.post("/report/executive")
def create_executive_report(payload: ExecutiveReportRequest):
    logger.info("[API] /report/executive request: domains=%s generated_by=%s", len(payload.domains), payload.generated_by)
    report = generate_executive_report(payload.domains, generated_by=payload.generated_by)
    logger.info("[API] /report/executive response metrics: %s", report.get("metrics", {}))
    return report


@router.post("/report/on-demand")
def create_on_demand_report(payload: OnDemandReportRequest):
    if not payload.domains and not payload.scan_ids:
        raise HTTPException(status_code=400, detail="Provide domains and/or scan_ids for on-demand report")
    logger.info(
        "[API] /report/on-demand request: domains=%s scan_ids=%s generated_by=%s",
        len(payload.domains),
        len(payload.scan_ids),
        payload.generated_by,
    )
    report = generate_on_demand_report(payload.domains, payload.scan_ids, generated_by=payload.generated_by)
    logger.info("[API] /report/on-demand response metrics: %s", report.get("metrics", {}))
    return report


@router.post("/report/generate")
def generate_report_compat(payload: LegacyGenerateRequest):
    """Backward-compatible endpoint — returns the full executive or on-demand report."""
    domains = payload.domains or payload.targets

    if payload.scan_ids:
        if not domains and not payload.scan_ids:
            raise HTTPException(status_code=400, detail="Provide domains and/or scan_ids")
        logger.info("[API] /report/generate on-demand: domains=%s scan_ids=%s", len(domains), len(payload.scan_ids))
        return generate_on_demand_report(domains or [], payload.scan_ids, generated_by=payload.generated_by)

    if not domains:
        raise HTTPException(status_code=400, detail="At least one target/domain is required")

    logger.info("[API] /report/generate executive: targets=%s", len(domains))
    return generate_executive_report(domains, generated_by=payload.generated_by)


@router.post("/report/schedule")
def create_report_schedule(
    payload: Optional[ScheduleRequest] = Body(default=None),
    report_type: Optional[str] = Query(default=None),
    frequency: Optional[str] = Query(default=None),
    targets: List[str] = Query(default_factory=list),
    email: Optional[str] = Query(default=None),
    timezone: Optional[str] = Query(default=None),
    date: Optional[str] = Query(default=None),
    time_val: Optional[str] = Query(default=None),
    include_sections: List[str] = Query(default_factory=list),
):
    # date/time/include_sections are accepted for compatibility with legacy clients.
    _ = (date, time_val, include_sections)

    if payload is None:
        normalized_targets = [t.strip() for t in targets if (t or "").strip()]
        if not normalized_targets:
            raise HTTPException(status_code=400, detail="Targets are required")
        payload = ScheduleRequest(
            report_type=report_type or "executive",
            frequency=frequency or "weekly",
            targets=normalized_targets,
            email=email or "",
            timezone=timezone or "UTC",
        )

    return create_schedule(
        report_type=payload.report_type,
        frequency=payload.frequency,
        targets=payload.targets,
        email=payload.email,
        timezone=payload.timezone,
    )


@router.get("/report/schedules")
def report_schedules(active_only: bool = Query(default=False)):
    return {"schedules": list_schedules(active_only=active_only)}


@router.get("/report/schedule/{schedule_id}")
def report_schedule_detail(schedule_id: int):
    return get_schedule(schedule_id)


@router.get("/report/history")
def report_history(limit: int = Query(default=50, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    return get_report_history(limit=limit, offset=offset)


@router.get("/report/scans")
def report_scans(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    return get_scan_history(limit=limit, offset=offset)


@router.get("/report/{report_id}")
def report_detail(report_id: int):
    return get_report_by_id(report_id)


@router.get("/report/{report_id}/json")
def report_detail_json(report_id: int):
    return get_report_by_id(report_id)


@router.get("/report/{report_id}/pdf")
def report_detail_pdf(report_id: int):
    wrapped = get_report_by_id(report_id)
    report = wrapped.get("report") or {}
    content = generate_report_pdf_bytes(report)

    headers = {"Content-Disposition": f'attachment; filename="aegisguard-report-{report_id}.pdf"'}
    return Response(content=content, media_type="application/pdf", headers=headers)
