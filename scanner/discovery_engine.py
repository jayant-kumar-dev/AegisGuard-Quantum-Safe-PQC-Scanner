"""Discovery engine with parallel passive collection and bounded execution time."""

from __future__ import annotations

# When this module is executed directly (python scanner/discovery_engine.py)
# relative imports fail because there is no package context. Ensure the
# workspace root (one level above this package) is on sys.path so absolute
# imports like `import scanner.xxx` succeed when running as a script.
if __package__ is None:
    import sys
    from pathlib import Path

    pkg_root = str(Path(__file__).resolve().parent.parent)
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)

import asyncio
import concurrent.futures
import datetime
import json
import logging
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

try:
    import aiohttp
except Exception:  # pragma: no cover - optional dependency fallback
    aiohttp = None

try:
    from .enumeration_config import (
        ENABLE_ANUBIS_OSINT,
        ENABLE_CERTSPOTTER_OSINT,
        ENABLE_CRTSH_OSINT,
        ENABLE_HACKERTARGET_OSINT,
        ENABLE_OTX_OSINT,
        ENABLE_URLSCAN_OSINT,
        MAX_OSINT_RESULTS_PER_SOURCE,
        MAX_THREADS,
        OSINT_RETRIES,
        OSINT_TIMEOUT_SECONDS,
        RECURSION_DEPTH,
        SUBDOMAIN_LIMIT,
        SUBDOMAIN_WORDLIST,
        USE_DNS_BRUTEFORCING,
    )
    from .pqc_analyzer import analyze_pqc
    from .risk_scorer import calculate_risk_score
    from .tls_probe import scan_tls_raw
    from .validation import validate_tls_scan
except Exception:
    from scanner.enumeration_config import (
        ENABLE_ANUBIS_OSINT,
        ENABLE_CERTSPOTTER_OSINT,
        ENABLE_CRTSH_OSINT,
        ENABLE_HACKERTARGET_OSINT,
        ENABLE_OTX_OSINT,
        ENABLE_URLSCAN_OSINT,
        MAX_OSINT_RESULTS_PER_SOURCE,
        MAX_THREADS,
        OSINT_RETRIES,
        OSINT_TIMEOUT_SECONDS,
        RECURSION_DEPTH,
        SUBDOMAIN_LIMIT,
        SUBDOMAIN_WORDLIST,
        USE_DNS_BRUTEFORCING,
    )
    from scanner.pqc_analyzer import analyze_pqc
    from scanner.risk_scorer import calculate_risk_score
    from scanner.tls_probe import scan_tls_raw
    from scanner.validation import validate_tls_scan

logger = logging.getLogger("AegisGuard.DiscoveryEngine")


DISCOVERY_CACHE_TTL_SECONDS = 1800
CRTSH_CACHE_TTL_SECONDS = 3600
DISCOVERY_GLOBAL_TIMEOUT_SECONDS = 60.0
PASSIVE_SOURCE_TIMEOUT_SECONDS = 6.0
PASSIVE_SOURCE_MAX_RETRY = max(0, min(OSINT_RETRIES, 1))
PASSIVE_SOURCE_CONCURRENCY = 6
TLS_SCAN_TIMEOUT_SECONDS = 6.0
TLS_SCAN_WORKERS = 10
DNS_RESOLVE_TIMEOUT_SECONDS = 2.0
MAX_DNS_GUESSES_PER_DEPTH = 200


PASSIVE_SOURCE_CONFIDENCE = {
    "crtsh": 0.92,
    "certspotter": 0.90,
    "urlscan": 0.82,
    "otx": 0.78,
    "anubis": 0.74,
    "hackertarget": 0.68,
    "bruteforce": 0.65,
    "base": 1.0,
}


@dataclass(frozen=True)
class PassiveSource:
    name: str
    enabled: bool
    fetcher: Callable[[str], Awaitable[Set[str]]]


def _now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _log_event(event: str, **fields: Any) -> None:
    payload = {"event": event, **fields}
    logger.info("%s", json.dumps(payload, sort_keys=True, default=str))


def _normalize_host(value: str) -> str:
    v = (value or "").strip().lower().strip(".")
    if v.startswith("*."):
        v = v[2:]
    return v


def _is_valid_subdomain(hostname: str, domain: str) -> bool:
    host = _normalize_host(hostname)
    root = _normalize_host(domain)
    if not host or not root:
        return False
    if " " in host or "/" in host or "@" in host:
        return False
    return host == root or host.endswith(f".{root}")


def _retry_after_seconds(exc: HTTPError) -> Optional[float]:
    try:
        if not exc.headers:
            return None
        retry_after = exc.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return float(retry_after)
    except Exception:
        return None
    return None


class DiscoveryEngine:
    def __init__(self) -> None:
        self._cache: Dict[str, Dict[str, Any]] = {}
        # local cache for crt.sh with longer TTL
        self._crtsh_cache: Dict[str, Dict[str, Any]] = {}
        self._sources = [
            PassiveSource("crtsh", ENABLE_CRTSH_OSINT, self._fetch_crtsh_subdomains),
            PassiveSource("certspotter", ENABLE_CERTSPOTTER_OSINT, self._fetch_certspotter_subdomains),
            PassiveSource("urlscan", ENABLE_URLSCAN_OSINT, self._fetch_urlscan_subdomains),
            PassiveSource("otx", ENABLE_OTX_OSINT, self._fetch_otx_subdomains),
            PassiveSource("anubis", ENABLE_ANUBIS_OSINT, self._fetch_anubis_subdomains),
            PassiveSource("hackertarget", ENABLE_HACKERTARGET_OSINT, self._fetch_hackertarget_subdomains),
        ]

    def _cache_key(self, source: str, url: str) -> str:
        return f"{source}:{url}"

    def _cache_get(self, source: str, url: str) -> Optional[str]:
        entry = self._cache.get(self._cache_key(source, url))
        if not entry:
            return None
        if time.time() - float(entry.get("ts", 0.0)) > DISCOVERY_CACHE_TTL_SECONDS:
            self._cache.pop(self._cache_key(source, url), None)
            return None
        return str(entry.get("value", ""))

    def _cache_set(self, source: str, url: str, value: str) -> None:
        self._cache[self._cache_key(source, url)] = {"ts": time.time(), "value": value}

    def _http_get_text_blocking(self, url: str, source: str) -> str:
        cached = self._cache_get(source, url)
        if cached is not None:
            return cached

        req = Request(url, headers={"User-Agent": "AegisGuard/2.1"})
        attempt = 0
        max_attempts = 1 + PASSIVE_SOURCE_MAX_RETRY

        while attempt < max_attempts:
            attempt += 1
            try:
                with urlopen(req, timeout=PASSIVE_SOURCE_TIMEOUT_SECONDS) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    self._cache_set(source, url, body)
                    return body
            except HTTPError as exc:
                status = int(getattr(exc, "code", 0) or 0)
                if status == 404:
                    _log_event("passive.source.ignore_404", source=source, url=url)
                    return ""

                if status == 429 and attempt < max_attempts:
                    retry_after = _retry_after_seconds(exc)
                    backoff = retry_after if retry_after is not None else (2 ** (attempt - 1))
                    _log_event("passive.source.rate_limited", source=source, url=url, attempt=attempt, backoff_s=round(backoff, 2))
                    time.sleep(backoff)
                    continue

                if status == 502 and attempt < max_attempts:
                    _log_event("passive.source.retry_502", source=source, url=url, attempt=attempt)
                    continue

                _log_event("passive.source.http_error", source=source, url=url, status=status, attempt=attempt)
                return ""
            except TimeoutError:
                if attempt < max_attempts:
                    backoff = 2 ** (attempt - 1)
                    _log_event("passive.source.retry_timeout", source=source, url=url, attempt=attempt, backoff_s=round(backoff, 2))
                    time.sleep(backoff)
                    continue
                _log_event("passive.source.timeout", source=source, url=url, attempt=attempt)
                return ""
            except URLError as exc:
                if attempt < max_attempts:
                    backoff = 2 ** (attempt - 1)
                    _log_event(
                        "passive.source.retry_network_error",
                        source=source,
                        url=url,
                        error=str(exc),
                        attempt=attempt,
                        backoff_s=round(backoff, 2),
                    )
                    time.sleep(backoff)
                    continue
                _log_event("passive.source.network_error", source=source, url=url, error=str(exc), attempt=attempt)
                return ""
            except Exception as exc:
                _log_event("passive.source.unexpected_error", source=source, url=url, error=str(exc), attempt=attempt)
                return ""

        return ""

    async def _http_get_text(self, url: str, source: str) -> str:
        cached = self._cache_get(source, url)
        if cached is not None:
            return cached

        if aiohttp is None:
            return await asyncio.to_thread(self._http_get_text_blocking, url, source)

        headers = {"User-Agent": "AegisGuard/2.1"}
        timeout = aiohttp.ClientTimeout(total=PASSIVE_SOURCE_TIMEOUT_SECONDS)
        attempt = 0
        max_attempts = 1 + PASSIVE_SOURCE_MAX_RETRY

        while attempt < max_attempts:
            attempt += 1
            try:
                async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                    async with session.get(url, allow_redirects=True) as resp:
                        if resp.status == 404:
                            _log_event("passive.source.ignore_404", source=source, url=url)
                            return ""

                        if resp.status == 429 and attempt < max_attempts:
                            retry_after = resp.headers.get("Retry-After")
                            backoff = float(retry_after) if retry_after and retry_after.isdigit() else float(2 ** (attempt - 1))
                            _log_event("passive.source.rate_limited", source=source, url=url, attempt=attempt, backoff_s=round(backoff, 2))
                            await asyncio.sleep(backoff)
                            continue

                        if resp.status == 502 and attempt < max_attempts:
                            _log_event("passive.source.retry_502", source=source, url=url, attempt=attempt)
                            await asyncio.sleep(float(2 ** (attempt - 1)))
                            continue

                        if resp.status >= 400:
                            _log_event("passive.source.http_error", source=source, url=url, status=resp.status, attempt=attempt)
                            return ""

                        body = await resp.read()
                        text = body.decode("utf-8", errors="ignore")
                        self._cache_set(source, url, text)
                        return text
            except asyncio.TimeoutError:
                if attempt < max_attempts:
                    backoff = float(2 ** (attempt - 1))
                    _log_event("passive.source.retry_timeout", source=source, url=url, attempt=attempt, backoff_s=round(backoff, 2))
                    await asyncio.sleep(backoff)
                    continue
                _log_event("passive.source.timeout", source=source, url=url, attempt=attempt)
                return ""
            except aiohttp.ClientError as exc:
                if attempt < max_attempts:
                    backoff = float(2 ** (attempt - 1))
                    _log_event(
                        "passive.source.retry_network_error",
                        source=source,
                        url=url,
                        error=str(exc),
                        attempt=attempt,
                        backoff_s=round(backoff, 2),
                    )
                    await asyncio.sleep(backoff)
                    continue
                _log_event("passive.source.network_error", source=source, url=url, error=str(exc), attempt=attempt)
                return ""
            except Exception as exc:
                _log_event("passive.source.unexpected_error", source=source, url=url, error=str(exc), attempt=attempt)
                return ""

        return ""

    async def _http_get_json(self, url: str, source: str) -> Any:
        text = await self._http_get_text(url, source=source)
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            _log_event("passive.source.invalid_json", source=source, url=url)
            return None

    async def _fetch_crtsh_subdomains(self, domain: str) -> Set[str]:
        # Check per-domain crt.sh cache first
        entry = self._crtsh_cache.get(domain)
        if entry and (time.time() - float(entry.get('ts', 0))) < CRTSH_CACHE_TTL_SECONDS:
            return set(entry.get('value', []))

        urls = (
            f"https://crt.sh/?Identity=%25.{quote(domain)}&output=json",
            f"https://crt.sh/?q=%25.{quote(domain)}&output=json",
            f"https://crt.sh/?q={quote(domain)}&output=json",
        )

        records = None
        headers = {"User-Agent": "AegisGuard/2.1"}
        timeout = 6.0

        if aiohttp is None:
            # Best-effort fallback using existing helper with our own timeout
            for url in urls:
                try:
                    data = await asyncio.wait_for(self._http_get_json(url, source="crtsh"), timeout=timeout)
                except asyncio.TimeoutError:
                    _log_event("passive.source.crtsh_timeout", source="crtsh", url=url)
                    continue
                if isinstance(data, list):
                    records = data
                    break
        else:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout), headers=headers) as session:
                for url in urls:
                    try:
                        async with session.get(url, allow_redirects=True) as resp:
                            if resp.status == 502:
                                _log_event("passive.source.crtsh_502", source="crtsh", url=url)
                                # Per requirements: do not retry on 502s
                                records = None
                                break
                            if resp.status == 404:
                                continue
                            if resp.status >= 400:
                                continue
                            body = await resp.read()
                            try:
                                data = json.loads(body.decode("utf-8", errors="ignore"))
                            except Exception:
                                data = None
                            if isinstance(data, list):
                                records = data
                                break
                    except asyncio.TimeoutError:
                        _log_event("passive.source.crtsh_timeout", source="crtsh", url=url)
                        continue
                    except Exception:
                        continue

        if not isinstance(records, list):
            return set()

        found: Set[str] = set()
        for rec in records[:MAX_OSINT_RESULTS_PER_SOURCE]:
            if not isinstance(rec, dict):
                continue
            names_blob = str(rec.get("name_value", ""))
            for candidate in names_blob.splitlines():
                host = _normalize_host(candidate)
                if _is_valid_subdomain(host, domain):
                    found.add(host)

        # Cache successful crt.sh responses for one hour
        try:
            self._crtsh_cache[domain] = {"ts": time.time(), "value": list(found)}
        except Exception:
            pass

        return found

    async def _fetch_hackertarget_subdomains(self, domain: str) -> Set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(domain)}"
        body = await self._http_get_text(url, source="hackertarget")
        if not body:
            return set()
        low = body.lower()
        if low.startswith("error") or "api count exceeded" in low:
            return set()

        found: Set[str] = set()
        for line in body.splitlines():
            host = _normalize_host(line.split(",", 1)[0])
            if _is_valid_subdomain(host, domain):
                found.add(host)
        return found

    async def _fetch_otx_subdomains(self, domain: str) -> Set[str]:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/passive_dns"
        headers = {"User-Agent": "AegisGuard/2.1"}
        max_attempts = 3
        attempt = 0

        if aiohttp is None:
            # Best-effort fallback using helper (may not expose Retry-After); keep single attempt
            data = await self._http_get_json(url, source="otx")
            if not isinstance(data, dict):
                return set()
            found: Set[str] = set()
            for rec in data.get("passive_dns", [])[:MAX_OSINT_RESULTS_PER_SOURCE]:
                host = _normalize_host((rec or {}).get("hostname", ""))
                if _is_valid_subdomain(host, domain):
                    found.add(host)
            return found

        # Use aiohttp to honor Retry-After and implement exponential backoff
        while attempt < max_attempts:
            attempt += 1
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=OSINT_TIMEOUT_SECONDS), headers=headers) as session:
                    async with session.get(url, allow_redirects=True) as resp:
                        if resp.status == 429:
                            # Honor Retry-After if present
                            retry_after = resp.headers.get('Retry-After')
                            backoff = float(retry_after) if retry_after and retry_after.isdigit() else float(2 ** attempt)
                            _log_event("passive.source.rate_limited", source='otx', url=url, attempt=attempt, backoff_s=round(backoff, 2))
                            if attempt >= max_attempts:
                                logger.warning("[DISCOVERY] OTX rate-limited after %s attempts for domain=%s", attempt, domain)
                                # Signal to caller that OTX was skipped due to rate limiting
                                raise Exception("rate_limited")
                            await asyncio.sleep(backoff)
                            continue

                        if resp.status >= 400:
                            _log_event("passive.source.http_error", source='otx', url=url, status=resp.status, attempt=attempt)
                            return set()

                        data = await resp.json()
                        if not isinstance(data, dict):
                            return set()
                        found: Set[str] = set()
                        for rec in data.get("passive_dns", [])[:MAX_OSINT_RESULTS_PER_SOURCE]:
                            host = _normalize_host((rec or {}).get("hostname", ""))
                            if _is_valid_subdomain(host, domain):
                                found.add(host)
                        return found
            except asyncio.TimeoutError:
                _log_event("passive.source.retry_timeout", source='otx', url=url, attempt=attempt)
                if attempt >= max_attempts:
                    return set()
                await asyncio.sleep(2 ** attempt)
                continue
            except Exception as exc:
                # Bubble up rate_limited as a distinct error string for stats handling
                if str(exc) == 'rate_limited':
                    raise
                _log_event("passive.source.unexpected_error", source='otx', url=url, error=str(exc), attempt=attempt)
                if attempt >= max_attempts:
                    return set()
                await asyncio.sleep(2 ** attempt)
                continue

    async def _fetch_urlscan_subdomains(self, domain: str) -> Set[str]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}&size=100"
        data = await self._http_get_json(url, source="urlscan")
        if not isinstance(data, dict):
            return set()
        found: Set[str] = set()
        for rec in data.get("results", [])[:MAX_OSINT_RESULTS_PER_SOURCE]:
            page = (rec or {}).get("page", {})
            host = _normalize_host(page.get("domain", ""))
            if _is_valid_subdomain(host, domain):
                found.add(host)
        return found

    async def _fetch_anubis_subdomains(self, domain: str) -> Set[str]:
        url = f"https://jldc.me/anubis/subdomains/{quote(domain)}"
        data = await self._http_get_json(url, source="anubis")
        if not isinstance(data, list):
            return set()
        found: Set[str] = set()
        for item in data[:MAX_OSINT_RESULTS_PER_SOURCE]:
            host = _normalize_host(str(item))
            if host and _is_valid_subdomain(host, domain):
                found.add(host)
        return found

    async def _fetch_certspotter_subdomains(self, domain: str) -> Set[str]:
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={quote(domain)}&include_subdomains=true&expand=dns_names"
        )
        data = await self._http_get_json(url, source="certspotter")
        if not isinstance(data, list):
            return set()
        found: Set[str] = set()
        for rec in data[:MAX_OSINT_RESULTS_PER_SOURCE]:
            if not isinstance(rec, dict):
                continue
            for dns_name in rec.get("dns_names", []):
                host = _normalize_host(str(dns_name))
                if _is_valid_subdomain(host, domain):
                    found.add(host)
        return found

    async def fetch_from_source(self, source_name: str, domain: str) -> Set[str]:
        for source in self._sources:
            if source.name == source_name and source.enabled:
                return await source.fetcher(domain)
        return set()

    async def _collect_passive(self, domain: str, time_deadline: float) -> Tuple[Set[str], Dict[str, Any]]:
        hosts: Set[str] = set()
        stats: Dict[str, Any] = {}

        sources = [s for s in self._sources if s.enabled]
        sem = asyncio.Semaphore(PASSIVE_SOURCE_CONCURRENCY)

        async def run_source(source: PassiveSource) -> Tuple[str, Set[str], Optional[str], int]:
            async with sem:
                started = time.perf_counter()
                _log_event("passive.source.start", source=source.name, domain=domain)
                try:
                    remaining = max(0.1, time_deadline - time.time())
                    result = await asyncio.wait_for(source.fetcher(domain), timeout=min(remaining, PASSIVE_SOURCE_TIMEOUT_SECONDS + 2.0))
                    duration_ms = int((time.perf_counter() - started) * 1000)
                    _log_event("passive.source.done", source=source.name, domain=domain, count=len(result), duration_ms=duration_ms)
                    return source.name, result, None, duration_ms
                except asyncio.TimeoutError:
                    duration_ms = int((time.perf_counter() - started) * 1000)
                    _log_event("passive.source.timeout", source=source.name, domain=domain, duration_ms=duration_ms)
                    return source.name, set(), "timeout", duration_ms
                except Exception as exc:
                    duration_ms = int((time.perf_counter() - started) * 1000)
                    _log_event("passive.source.failed", source=source.name, domain=domain, error=str(exc), duration_ms=duration_ms)
                    return source.name, set(), str(exc), duration_ms

        tasks = [asyncio.create_task(run_source(source)) for source in sources]
        for task in asyncio.as_completed(tasks):
            if time.time() >= time_deadline:
                break
            source_name, result, error, duration_ms = await task
            valid = {h for h in result if _is_valid_subdomain(h, domain)}
            hosts.update(valid)
            if source_name == 'otx' and error == 'rate_limited':
                stats[source_name] = {
                    "count": 0,
                    "skipped": True,
                    "reason": "rate_limited",
                    "duration_ms": duration_ms,
                }
            else:
                stats[source_name] = {
                    "count": len(valid),
                    "error": error,
                    "duration_ms": duration_ms,
                }

        for task in tasks:
            if not task.done():
                task.cancel()

        return hosts, stats

    def _load_subdomain_words(self) -> List[str]:
        default_words = [
            "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
            "portal", "vpn", "owa", "webmail", "ns1", "ns2", "mx", "smtp",
            "imap", "cdn", "app", "secure", "login", "sso", "dashboard", "status",
            "blog", "shop", "store", "gateway", "backup", "git", "ci", "cloud",
        ]
        path = Path(SUBDOMAIN_WORDLIST)
        if not path.exists():
            return default_words
        words = []
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            w = line.strip().lower()
            if not w or w.startswith("#"):
                continue
            words.append(w)
        return words or default_words

    def _resolve_host(self, hostname: str) -> Dict[str, Any]:
        try:
            ip = socket.gethostbyname(hostname)
            return {"hostname": hostname, "ip": ip, "resolved": True}
        except socket.gaierror:
            return {"hostname": hostname, "ip": None, "resolved": False}

    async def _resolve_host_async(self, hostname: str) -> Dict[str, Any]:
        return await asyncio.to_thread(self._resolve_host, hostname)

    async def _run_dns_bruteforce(self, domain: str, seen_hosts: Set[str], time_deadline: float) -> Set[str]:
        if not USE_DNS_BRUTEFORCING:
            return set()

        words = self._load_subdomain_words()
        discovered: Set[str] = set()
        parent_hosts = [domain]

        for depth in range(1, RECURSION_DEPTH + 1):
            if time.time() >= time_deadline:
                break

            candidates: List[str] = []
            for parent in parent_hosts:
                for word in words:
                    host = f"{word}.{parent}"
                    if host in seen_hosts:
                        continue
                    seen_hosts.add(host)
                    candidates.append(host)
                    if len(candidates) >= MAX_DNS_GUESSES_PER_DEPTH:
                        break
                if len(candidates) >= MAX_DNS_GUESSES_PER_DEPTH:
                    break

            if not candidates:
                break

            next_parents: List[str] = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as exe:
                futures = {exe.submit(self._resolve_host, host): host for host in candidates}
                for future in concurrent.futures.as_completed(futures, timeout=max(1.0, time_deadline - time.time())):
                    if time.time() >= time_deadline:
                        break
                    try:
                        resolved = future.result(timeout=DNS_RESOLVE_TIMEOUT_SECONDS)
                    except Exception:
                        continue
                    if resolved.get("resolved"):
                        host = str(resolved.get("hostname") or "")
                        if _is_valid_subdomain(host, domain):
                            discovered.add(host)
                            next_parents.append(host)

            _log_event("dns.bruteforce.depth_done", domain=domain, depth=depth, discovered=len(next_parents))
            parent_hosts = next_parents
            if not parent_hosts:
                break

        return discovered

    def _source_trust(self, source: str) -> float:
        return PASSIVE_SOURCE_CONFIDENCE.get(source, 0.7)

    def _scan_subdomain_tls(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        raw = scan_tls_raw(hostname, port, timeout=TLS_SCAN_TIMEOUT_SECONDS)
        if raw.get("error") and not raw.get("reachable"):
            return {
                "hostname": hostname,
                "port": port,
                "ip": raw.get("ip"),
                "reachable": False,
                "error": raw.get("error"),
                "validation_confidence": 0,
                "validation_low_confidence": True,
            }

        validation = validate_tls_scan(raw)
        normalized = validation.get("normalized") or {}
        normalized["validation"] = validation
        pqc = analyze_pqc(normalized)
        risk = calculate_risk_score(normalized, pqc, validation=validation)

        return {
            "hostname": hostname,
            "port": port,
            "ip": normalized.get("ip"),
            "reachable": normalized.get("reachable", False),
            "tls_version": normalized.get("tls_version"),
            "cipher_suite": normalized.get("cipher_suite"),
            "cert_subject": normalized.get("cert_subject"),
            "cert_issuer": normalized.get("cert_issuer"),
            "cert_sig_alg": normalized.get("cert_sig_alg"),
            "cert_pubkey_alg": normalized.get("cert_pubkey_alg"),
            "cert_pubkey_bits": normalized.get("cert_pubkey_bits"),
            "cert_not_after": normalized.get("cert_not_after"),
            "cert_days_left": normalized.get("cert_days_left"),
            "cert_expired": normalized.get("cert_expired"),
            "cert_sha256": normalized.get("cert_sha256"),
            "hsts": normalized.get("hsts", False),
            "pqc_safe": pqc.get("pqc_safe", False),
            "pqc_status": pqc.get("status"),
            "risk_score": risk.get("score"),
            "risk_grade": risk.get("grade"),
            "validation_confidence": validation.get("confidence", 0),
            "validation_low_confidence": validation.get("low_confidence", False),
            "validation_checks": validation.get("checks", []),
            "error": normalized.get("error"),
        }

    async def discover(
        self,
        domain: str,
        scan_subdomains: bool = True,
        progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
        global_timeout_seconds: float = DISCOVERY_GLOBAL_TIMEOUT_SECONDS,
    ) -> Dict[str, Any]:
        started_at = time.time()
        deadline = started_at + global_timeout_seconds
        root_domain = _normalize_host(domain)

        if not root_domain:
            raise ValueError("Domain cannot be empty")

        _log_event("discover.start", domain=root_domain, timeout_s=global_timeout_seconds)

        found_map: Dict[str, Dict[str, Any]] = {}
        seen_hosts: Set[str] = set()

        async def add_found(hostname: str, source: str) -> None:
            host = _normalize_host(hostname)
            if not _is_valid_subdomain(host, root_domain):
                return
            trust = self._source_trust(source)

            if host in found_map:
                record = found_map[host]
                sources = record.setdefault("sources", [])
                if source not in sources:
                    sources.append(source)
                record["source"] = ",".join(sources)
                record["source_confidence"] = round(
                    min(1.0, max(float(record.get("source_confidence", 0.0)), trust) + (0.03 * (len(sources) - 1))),
                    2,
                )
                return

            resolved = await self._resolve_host_async(host)
            found_map[host] = {
                "detection_date": datetime.datetime.utcnow().strftime("%d %b %Y"),
                "hostname": host,
                "ip": resolved.get("ip"),
                "type": "A" if resolved.get("resolved") else "N/A",
                "status": "confirmed" if resolved.get("resolved") else "discovered",
                "is_base": host == root_domain,
                "source": source,
                "sources": [source],
                "source_confidence": round(trust, 2),
            }

        await add_found(root_domain, "base")
        seen_hosts.add(root_domain)

        passive_stats: Dict[str, Any] = {}
        if scan_subdomains and time.time() < deadline:
            passive_hosts, passive_stats = await self._collect_passive(root_domain, deadline)
            for host in sorted(passive_hosts):
                if len(found_map) >= SUBDOMAIN_LIMIT:
                    break
                seen_hosts.add(host)
                await add_found(host, "passive")

        elapsed_after_passive_ms = round((time.time() - started_at) * 1000)
        passive_summary = {
            "total_discovered": len(found_map),
            "total_reachable": 0,
            "total_pqc_safe": 0,
            "total_pqc_vulnerable": 0,
        }
        passive_payload = {
            "domain": root_domain,
            "scan_time_ms": elapsed_after_passive_ms,
            "summary": passive_summary,
            "discovered_subdomains": sorted(found_map.keys())[:SUBDOMAIN_LIMIT],
            "domains": [],
            "ssl": [],
            "ip_addresses": [],
            "software": [],
            "raw_scans": [],
            "passive_source_stats": passive_stats,
            "timed_out": time.time() >= deadline,
            "generated_at": _now_iso(),
            "is_partial": True,
            "stage": "passive_complete",
        }

        if progress_cb:
            progress_cb({
                "stage": "passive_complete",
                "counts": {
                    "discovered": len(found_map),
                },
                "passive_stats": passive_stats,
                "result": passive_payload,
            })

        if scan_subdomains and time.time() < deadline and len(found_map) < SUBDOMAIN_LIMIT:
            brute_hosts = await self._run_dns_bruteforce(root_domain, seen_hosts, deadline)
            for host in sorted(brute_hosts):
                if len(found_map) >= SUBDOMAIN_LIMIT:
                    break
                await add_found(host, "bruteforce")

        subdomains = sorted(found_map.values(), key=lambda r: (not bool(r.get("is_base")), r.get("hostname", "")))
        subdomains = subdomains[:SUBDOMAIN_LIMIT]

        elapsed_after_subdomains_ms = round((time.time() - started_at) * 1000)
        subdomains_payload = {
            "domain": root_domain,
            "scan_time_ms": elapsed_after_subdomains_ms,
            "summary": {
                "total_discovered": len(subdomains),
                "total_reachable": 0,
                "total_pqc_safe": 0,
                "total_pqc_vulnerable": 0,
            },
            "discovered_subdomains": [s.get("hostname") for s in subdomains],
            "domains": [
                {
                    "detection_date": s.get("detection_date", ""),
                    "domain_name": s.get("hostname", ""),
                    "ip": s.get("ip", ""),
                    "registrar": s.get("source", "DNS/OSINT"),
                    "company_name": root_domain,
                    "status": s.get("status", "discovered"),
                    "reachable": bool(s.get("ip")),
                    "source_confidence": s.get("source_confidence", 0),
                    "sources": s.get("sources", []),
                }
                for s in subdomains
            ],
            "ssl": [],
            "ip_addresses": [],
            "software": [],
            "raw_scans": [],
            "passive_source_stats": passive_stats,
            "timed_out": time.time() >= deadline,
            "generated_at": _now_iso(),
            "is_partial": True,
            "stage": "subdomains_ready",
        }

        if progress_cb:
            progress_cb({
                "stage": "subdomains_ready",
                "counts": {
                    "discovered": len(subdomains),
                },
                "result": subdomains_payload,
            })

        scanned: List[Dict[str, Any]] = []
        if time.time() < deadline:
            reachable_hosts = [s for s in subdomains if s.get("ip")]
            host_to_meta = {s.get("hostname"): s for s in subdomains}

            with concurrent.futures.ThreadPoolExecutor(max_workers=TLS_SCAN_WORKERS) as exe:
                futures = {exe.submit(self._scan_subdomain_tls, s.get("hostname", "")): s.get("hostname", "") for s in reachable_hosts}
                for future in concurrent.futures.as_completed(futures, timeout=max(1.0, deadline - time.time())):
                    if time.time() >= deadline:
                        break
                    host = futures.get(future, "")
                    meta = host_to_meta.get(host, {})
                    try:
                        row = future.result(timeout=max(0.2, deadline - time.time()))
                    except Exception as exc:
                        row = {
                            "hostname": host,
                            "ip": meta.get("ip"),
                            "reachable": False,
                            "error": str(exc),
                            "validation_confidence": 0,
                            "validation_low_confidence": True,
                        }
                    row["detection_date"] = meta.get("detection_date")
                    row["dns_status"] = meta.get("status")
                    scanned.append(row)

        domains_list: List[Dict[str, Any]] = []
        ssl_list: List[Dict[str, Any]] = []
        ip_list: List[Dict[str, Any]] = []
        software_list: List[Dict[str, Any]] = []

        scanned_map = {s.get("hostname"): s for s in scanned if s.get("hostname")}

        for sub in subdomains:
            hostname = sub.get("hostname", "")
            scan_data = scanned_map.get(hostname, {})
            domains_list.append(
                {
                    "detection_date": sub.get("detection_date", ""),
                    "domain_name": hostname,
                    "ip": sub.get("ip", ""),
                    "registrar": sub.get("source", "DNS/OSINT"),
                    "company_name": root_domain,
                    "status": sub.get("status", "discovered"),
                    "reachable": scan_data.get("reachable", bool(sub.get("ip"))),
                    "source_confidence": sub.get("source_confidence", 0),
                    "sources": sub.get("sources", []),
                }
            )

        for s in scanned:
            if not s.get("reachable"):
                continue

            if s.get("cert_sha256"):
                ssl_list.append(
                    {
                        "detection_date": s.get("detection_date", ""),
                        "ssl_sha_fingerprint": str(s.get("cert_sha256", ""))[:40],
                        "common_name": s.get("cert_subject", ""),
                        "certificate_authority": s.get("cert_issuer", ""),
                        "cert_expired": s.get("cert_expired", False),
                        "cert_days_left": s.get("cert_days_left"),
                        "hostname": s.get("hostname", ""),
                    }
                )

            ip_list.append(
                {
                    "ip_address": s.get("ip", ""),
                    "hostname": s.get("hostname", ""),
                    "tls_version": s.get("tls_version", ""),
                    "pqc_safe": s.get("pqc_safe", False),
                    "risk_grade": s.get("risk_grade", ""),
                }
            )

            if s.get("tls_version"):
                software_list.append(
                    {
                        "product": s.get("tls_version", ""),
                        "version": s.get("cipher_suite", ""),
                        "hostname": s.get("hostname", ""),
                        "pqc_safe": s.get("pqc_safe", False),
                    }
                )

        total_reachable = sum(1 for row in scanned if row.get("reachable"))
        total_pqc = sum(1 for row in scanned if row.get("pqc_safe"))
        elapsed_ms = round((time.time() - started_at) * 1000)

        payload = {
            "domain": root_domain,
            "scan_time_ms": elapsed_ms,
            "summary": {
                "total_discovered": len(subdomains),
                "total_reachable": total_reachable,
                "total_pqc_safe": total_pqc,
                "total_pqc_vulnerable": max(0, total_reachable - total_pqc),
            },
            "discovered_subdomains": [s.get("hostname") for s in subdomains],
            "domains": domains_list,
            "ssl": ssl_list,
            "ip_addresses": ip_list,
            "software": software_list,
            "raw_scans": scanned,
            "passive_source_stats": passive_stats,
            "timed_out": time.time() >= deadline,
            "generated_at": _now_iso(),
        }

        if progress_cb:
            progress_cb(
                {
                    "stage": "complete",
                    "counts": {
                        "discovered": len(subdomains),
                        "reachable": total_reachable,
                    },
                    "result": payload,
                }
            )

        _log_event(
            "discover.done",
            domain=root_domain,
            elapsed_ms=elapsed_ms,
            discovered=len(subdomains),
            reachable=total_reachable,
            pqc_safe=total_pqc,
            timed_out=payload["timed_out"],
        )

        return payload
