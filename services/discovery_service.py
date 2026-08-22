"""Discovery job manager with bounded workers and cached status snapshots."""

from __future__ import annotations

import asyncio
import datetime
import logging
import time
import uuid
from copy import deepcopy
from typing import Any, Dict, Optional

from scanner.discovery_engine import DISCOVERY_GLOBAL_TIMEOUT_SECONDS, DiscoveryEngine

logger = logging.getLogger("AegisGuard.DiscoveryService")

DISCOVERY_JOB_TTL_SECONDS = 3600
DISCOVERY_WORKER_COUNT = 2
DISCOVERY_QUEUE_MAXSIZE = 256

_TERMINAL_STATUSES = {
    "completed",
    "completed_partial",
    "partial_success",
    "failed",
    "timed_out",
    "timedout",
    "cancelled",
}


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _now_epoch() -> float:
    return time.time()


class DiscoveryJobManager:
    def __init__(self, engine: Optional[DiscoveryEngine] = None) -> None:
        self.engine = engine or DiscoveryEngine()
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._jobs_lock = asyncio.Lock()
        self._queue: asyncio.Queue[str] = asyncio.Queue(maxsize=DISCOVERY_QUEUE_MAXSIZE)
        self._workers: list[asyncio.Task[Any]] = []
        self._cleanup_task: Optional[asyncio.Task[Any]] = None
        self._watchdog_task: Optional[asyncio.Task[Any]] = None
        self._started = False
        self._stopping = False
        self._active_by_fingerprint: Dict[str, str] = {}
        # per-source cache (extended TTL for crt.sh)
        self._crtsh_cache: Dict[str, Dict[str, Any]] = {}

    async def start(self) -> None:
        async with self._jobs_lock:
            if self._started:
                return
            self._started = True
            self._stopping = False

        self._workers = [asyncio.create_task(self._worker_loop(index)) for index in range(DISCOVERY_WORKER_COUNT)]
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        # Watchdog to prevent stuck jobs from hanging indefinitely
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())
        logger.info("[DISCOVERY] Worker pool started workers=%s", DISCOVERY_WORKER_COUNT)

    async def stop(self) -> None:
        async with self._jobs_lock:
            if not self._started:
                return
            self._stopping = True
            self._started = False

        for task in self._workers:
            task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._watchdog_task:
            self._watchdog_task.cancel()

        await asyncio.gather(*self._workers, return_exceptions=True)
        if self._cleanup_task:
            await asyncio.gather(self._cleanup_task, return_exceptions=True)
        if self._watchdog_task:
            await asyncio.gather(self._watchdog_task, return_exceptions=True)

        self._workers = []
        self._cleanup_task = None
        logger.info("[DISCOVERY] Worker pool stopped")

    def _fingerprint(self, domain: str, scan_subdomains: bool, dry_run: bool) -> str:
        return f"{domain.lower()}|{int(scan_subdomains)}|{int(dry_run)}"

    def _public_job(self, job: Dict[str, Any], include_result: bool = True) -> Dict[str, Any]:
        payload = {
            key: deepcopy(value)
            for key, value in job.items()
            if key not in {"cancel_event", "fingerprint"}
        }
        if not include_result:
            payload["result"] = None
        return payload

    async def submit(self, domain: str, scan_subdomains: bool = True, dry_run: bool = False) -> Dict[str, Any]:
        await self.start()
        fingerprint = self._fingerprint(domain, scan_subdomains, dry_run)

        async with self._jobs_lock:
            existing_id = self._active_by_fingerprint.get(fingerprint)
            if existing_id:
                existing = self._jobs.get(existing_id)
                if existing and existing.get("status") not in _TERMINAL_STATUSES:
                    snapshot = self._public_job(existing, include_result=False)
                    snapshot["duplicate_of"] = existing_id
                    return snapshot

            now = _now_iso()
            job_id = uuid.uuid4().hex
            job = {
                "job_id": job_id,
                "fingerprint": fingerprint,
                "status": "queued",
                "created_at": now,
                "updated_at": now,
                "finished_at": None,
                "updated_at_epoch": _now_epoch(),
                "request": {
                    "domain": domain,
                    "scan_subdomains": scan_subdomains,
                    "dry_run": dry_run,
                },
                "progress": {
                    "stage": "queued",
                    "counts": {
                        "discovered": 0,
                        "reachable": 0,
                    },
                },
                "result": None,
                "error": None,
                "cancel_event": asyncio.Event(),
            }
            self._jobs[job_id] = job
            self._active_by_fingerprint[fingerprint] = job_id

        await self._queue.put(job_id)
        snapshot = self._public_job(job, include_result=False)
        snapshot["status_url"] = f"/status/{job_id}"
        snapshot["result_url"] = f"/discover/result/{job_id}"
        return snapshot

    async def _set_progress(self, job_id: str, payload: Dict[str, Any]) -> None:
        async with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job or job.get("status") in _TERMINAL_STATUSES:
                return

            job["progress"] = {
                **(job.get("progress") or {}),
                **payload,
            }
            if payload.get("result") is not None:
                job["result"] = payload.get("result")

            if payload.get("stage") not in ("queued", "complete"):
                job["status"] = "running"

            job["updated_at"] = _now_iso()
            job["updated_at_epoch"] = _now_epoch()

    async def _finalize_job(self, job_id: str, status: str, *, result: Any = None, error: Optional[str] = None) -> None:
        async with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job:
                return

            job["status"] = status
            job["updated_at"] = _now_iso()
            job["updated_at_epoch"] = _now_epoch()
            job["finished_at"] = _now_iso()
            if result is not None:
                job["result"] = result
            if error is not None:
                job["error"] = error
            self._active_by_fingerprint.pop(job.get("fingerprint", ""), None)

    async def _run_job(self, job_id: str) -> None:
        async with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "running"
            job["updated_at"] = _now_iso()
            job["updated_at_epoch"] = _now_epoch()
            domain = str((job.get("request") or {}).get("domain") or "")
            scan_subdomains = bool((job.get("request") or {}).get("scan_subdomains", True))
            cancel_event = job["cancel_event"]

        logger.info("[DISCOVERY] Job started job_id=%s domain=%s", job_id, domain)
        final_result: Optional[Dict[str, Any]] = None

        def progress_callback(payload: Dict[str, Any]) -> None:
            nonlocal final_result
            if payload.get("result") is not None and isinstance(payload["result"], dict):
                final_result = payload["result"]
            asyncio.create_task(self._set_progress(job_id, payload))

        try:
            if cancel_event.is_set():
                await self._finalize_job(job_id, "cancelled", error="Discovery job cancelled before start")
                return

            result = await asyncio.wait_for(
                self.engine.discover(
                    domain=domain,
                    scan_subdomains=scan_subdomains,
                    progress_cb=progress_callback,
                    global_timeout_seconds=DISCOVERY_GLOBAL_TIMEOUT_SECONDS,
                ),
                timeout=DISCOVERY_GLOBAL_TIMEOUT_SECONDS + 5,
            )

            if cancel_event.is_set():
                await self._finalize_job(job_id, "cancelled", result=result, error="Discovery job cancelled")
                return

            await self._finalize_job(job_id, "completed", result=result)
            logger.info("[DISCOVERY] Job completed job_id=%s domain=%s", job_id, domain)
        except asyncio.TimeoutError:
            partial = final_result
            async with self._jobs_lock:
                job = self._jobs.get(job_id)
                if job and not partial:
                    partial = job.get("result") if isinstance(job.get("result"), dict) else None

            if partial:
                await self._finalize_job(
                    job_id,
                    "completed_partial",
                    result=partial,
                    error="Discovery reached the global timeout and returned partial results",
                )
            else:
                await self._finalize_job(
                    job_id,
                    "timed_out",
                    error=f"Discovery deadline ({DISCOVERY_GLOBAL_TIMEOUT_SECONDS}s) reached with no results",
                )
            logger.warning("[DISCOVERY] Job timed out job_id=%s domain=%s partial=%s", job_id, domain, bool(partial))
        except asyncio.CancelledError:
            await self._finalize_job(job_id, "cancelled", error="Discovery worker cancelled")
            raise
        except Exception as exc:
            await self._finalize_job(job_id, "failed", error=str(exc))
            logger.exception("[DISCOVERY] Job failed job_id=%s domain=%s error=%s", job_id, domain, exc)
        finally:
            # Ensure we never leave a job in a non-terminal state if the worker exits unexpectedly
            async with self._jobs_lock:
                job = self._jobs.get(job_id)
                current_status = job.get("status") if job else None
            if job and current_status not in _TERMINAL_STATUSES:
                await self._finalize_job(job_id, "failed", error="Discovery worker exited unexpectedly")

    async def _worker_loop(self, worker_index: int) -> None:
        while True:
            job_id = await self._queue.get()
            try:
                if self._stopping:
                    continue
                await self._run_job(job_id)
            finally:
                self._queue.task_done()

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(300)
            cutoff = _now_epoch() - DISCOVERY_JOB_TTL_SECONDS
            async with self._jobs_lock:
                to_delete = [job_id for job_id, job in self._jobs.items() if job.get("updated_at_epoch", 0.0) < cutoff and job.get("status") in _TERMINAL_STATUSES]
                for job_id in to_delete:
                    job = self._jobs.pop(job_id, None)
                    if job:
                        self._active_by_fingerprint.pop(job.get("fingerprint", ""), None)

    async def _watchdog_loop(self) -> None:
        """Monitor running jobs and mark them timed_out if stuck beyond threshold."""
        while True:
            await asyncio.sleep(10)
            cutoff = _now_epoch() - 90
            async with self._jobs_lock:
                running = [(jid, j) for jid, j in self._jobs.items() if j.get("status") not in _TERMINAL_STATUSES]
            for jid, j in running:
                try:
                    updated_epoch = float(j.get("updated_at_epoch", 0.0) or 0.0)
                except Exception:
                    updated_epoch = 0.0
                if updated_epoch < cutoff:
                    logger.warning("[DISCOVERY.WATCHDOG] Job %s appears stuck (last_update=%s). Marking timed out.", jid, j.get("updated_at"))
                    await self._finalize_job(jid, "timed_out", result=j.get("result"), error="Watchdog: job exceeded allowed runtime and was timed out")

    async def get_status(self, job_id: str) -> Dict[str, Any]:
        # Non-blocking read: avoid acquiring locks so status requests never block.
        job = self._jobs.get(job_id)
        if not job:
            raise KeyError(job_id)
        snapshot = self._public_job(job, include_result=False)
        result = job.get("result")
        result_summary = None
        if isinstance(result, dict):
            result_summary = {
                "domain": result.get("domain"),
                "scan_time_ms": result.get("scan_time_ms"),
                "summary": result.get("summary"),
            }
        snapshot["result"] = result_summary
        return snapshot

    async def get_result(self, job_id: str) -> Dict[str, Any]:
        async with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            snapshot = self._public_job(job, include_result=True)
            return snapshot

    async def cancel(self, job_id: str) -> Dict[str, Any]:
        async with self._jobs_lock:
            job = self._jobs.get(job_id)
            if not job:
                raise KeyError(job_id)
            if job.get("status") in _TERMINAL_STATUSES:
                return self._public_job(job, include_result=True)
            job["cancel_event"].set()
            job["status"] = "cancelled"
            job["error"] = "Discovery job cancelled by user"
            job["updated_at"] = _now_iso()
            job["updated_at_epoch"] = _now_epoch()
            self._active_by_fingerprint.pop(job.get("fingerprint", ""), None)
            return self._public_job(job, include_result=True)


discovery_job_manager = DiscoveryJobManager()
