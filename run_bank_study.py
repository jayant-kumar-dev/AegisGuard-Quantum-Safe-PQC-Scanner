"""
AegisGuard — 100-Bank PQC Research Batch Runner
Run from the project root (same folder as app.py / config.py):

    python run_bank_study.py banks.csv results.csv

banks.csv input format (header required):
    domain,port,bank_name,country
    hdfcbank.com,443,HDFC Bank,IN
    icicibank.com,443,ICICI Bank,IN
    ...

port/bank_name/country are optional — port defaults to 443.

Output: a strict 32-column research CSV at the path you give as the second
argument, plus a per-target progress line on stdout so a 100-endpoint run
is easy to babysit. One failing endpoint never aborts the batch.
"""

import csv
import sys
import time

from scanner.exporters import build_audit_record, export_audit_csv
from scanner.tls_probe import scan_tls_raw


def load_targets(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def main():
    if len(sys.argv) != 3:
        print("Usage: python run_bank_study.py <targets.csv> <output.csv>")
        sys.exit(1)

    targets = load_targets(sys.argv[1])
    records = []

    for idx, t in enumerate(targets, start=1):
        domain = t["domain"].strip()
        port = int(t.get("port") or 443)
        bank_name = t.get("bank_name", "")
        country = t.get("country", "")

        print(f"[{idx}/{len(targets)}] Scanning {domain}:{port} ...", end=" ", flush=True)
        try:
            raw = scan_tls_raw(domain, port, timeout=10)
        except Exception as e:
            raw = {"host": domain, "port": port, "reachable": False, "error": str(e), "ip": None}

        error = str(raw.get("error") or "")
        fallback_errors = (
            "getaddrinfo failed", "connection timed out", "connection refused",
            "forcibly closed", "connection reset",
        )
        if raw.get("reachable") is False and any(message in error.lower() for message in fallback_errors):
            fallback_domain = f"www.{domain}"
            print(f"[www-fallback] {domain} -> {fallback_domain}")
            try:
                fallback_raw = scan_tls_raw(fallback_domain, port, timeout=10)
            except Exception:
                fallback_raw = None
            if fallback_raw and fallback_raw.get("reachable"):
                raw = fallback_raw

        rec = build_audit_record(domain, port, raw, record_id=idx, bank_name=bank_name, country=country)
        records.append(rec)

        status = "OK" if rec["reachable"] else "FAILED"
        print(f"{status}  tls={rec['tls_version']}  kex={rec['key_exchange_group']}  "
              f"pqc_status={rec['pqc_status']}  grade={rec['risk_grade']}")
        if idx < len(targets):
            time.sleep(1)

    export_audit_csv(records, sys.argv[2])
    print(f"\nDone. {len(records)} records written to {sys.argv[2]}")


if __name__ == "__main__":
    main()
