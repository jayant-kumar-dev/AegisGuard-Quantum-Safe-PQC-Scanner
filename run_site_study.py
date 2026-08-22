"""
AegisGuard - 300-Site PQC Research Batch Runner
Run from the project root (same folder as app.py / config.py):

    python run_site_study.py

Reads sites_300.csv and writes site_study_results.csv plus
site_study_category_summary.csv. One failing endpoint never aborts the batch.
"""

import csv
import time

from scanner.exporters import build_audit_record, export_audit_csv
from scanner.tls_probe import scan_tls_raw

SUMMARY_COLUMNS = [
    "category", "total", "reachable", "tls_1_2_count", "tls_1_3_count",
    "classical_count", "hybrid_pqc_count", "pqc_count", "not_verified_count",
    "hsts_missing_count", "expired_certificate_count", "average_risk_score",
    "average_risk_score_reachable_only",
]

FALLBACK_ERRORS = (
    "getaddrinfo failed",
    "connection timed out",
    "connection refused",
    "forcibly closed",
    "connection reset",
)


def load_targets(path="sites_300.csv"):
    with open(path, newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))


def scan_target(domain, port):
    try:
        raw = scan_tls_raw(domain, port, timeout=10)
    except Exception as error:
        raw = {
            "host": domain,
            "port": port,
            "reachable": False,
            "error": str(error),
            "ip": None,
        }

    error_text = str(raw.get("error") or "").lower()
    if raw.get("reachable") is False and any(
        message in error_text for message in FALLBACK_ERRORS
    ):
        fallback_domain = f"www.{domain}"
        print(f"[www-fallback] {domain} -> {fallback_domain}", flush=True)
        try:
            fallback_raw = scan_tls_raw(fallback_domain, port, timeout=10)
        except Exception:
            fallback_raw = None
        if fallback_raw and fallback_raw.get("reachable"):
            raw = fallback_raw

    return raw


def build_category_summary(records):
    grouped = {}
    for record in records:
        category = record.get("category", "")
        grouped.setdefault(category, []).append(record)

    summary = []
    for category in sorted(grouped):
        category_records = grouped[category]
        scores = [float(record.get("risk_score") or 0) for record in category_records]
        reachable_scores = [
            float(record.get("risk_score") or 0)
            for record in category_records
            if record.get("reachable")
        ]
        statuses = [record.get("pqc_status", "NOT_VERIFIED") for record in category_records]
        tls_versions = [record.get("tls_version", "Unknown") for record in category_records]
        summary.append({
            "category": category,
            "total": len(category_records),
            "reachable": sum(bool(record.get("reachable")) for record in category_records),
            "tls_1_2_count": tls_versions.count("TLSv1.2"),
            "tls_1_3_count": tls_versions.count("TLSv1.3"),
            "classical_count": statuses.count("CLASSICAL"),
            "hybrid_pqc_count": statuses.count("HYBRID_PQC"),
            "pqc_count": statuses.count("PQC"),
            "not_verified_count": statuses.count("NOT_VERIFIED"),
            "hsts_missing_count": sum(not bool(record.get("hsts")) for record in category_records),
            "expired_certificate_count": sum(
                bool(record.get("certificate_expired")) for record in category_records
            ),
            "average_risk_score": round(sum(scores) / len(scores), 2) if scores else 0,
            "average_risk_score_reachable_only": (
                round(sum(reachable_scores) / len(reachable_scores), 2)
                if reachable_scores else 0
            ),
        })
    return summary


def export_category_summary(summary, path="site_study_category_summary.csv"):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=SUMMARY_COLUMNS)
        writer.writeheader()
        writer.writerows(summary)


def main():
    targets = load_targets()
    records = []

    for index, target in enumerate(targets, start=1):
        domain = target["domain"].strip()
        port = int(target.get("port") or 443)
        organization = target.get("organization", "")
        country = target.get("country", "")
        record_id = int(target.get("id") or index)

        print(f"[{index}/{len(targets)}] Scanning {domain}:{port} ...", end=" ", flush=True)
        raw = scan_target(domain, port)
        record = build_audit_record(
            domain,
            port,
            raw,
            record_id=record_id,
            bank_name=organization,
            country=country,
        )
        record["category"] = target.get("category", "")
        record["confidence_note"] = target.get("confidence_note", "")
        records.append(record)

        status = "OK" if record["reachable"] else "FAILED"
        print(
            f"{status}  tls={record['tls_version']}  "
            f"kex={record['key_exchange_group']}  "
            f"pqc_status={record['pqc_status']}  grade={record['risk_grade']}"
        )
        if index < len(targets):
            time.sleep(1)

    summary = build_category_summary(records)
    export_audit_csv(records, "site_study_results.csv")
    export_category_summary(summary)

    print(f"\nDone. {len(records)} records written to site_study_results.csv")
    print(f"Reachable: {sum(bool(record.get('reachable')) for record in records)}/{len(records)}")
    print("Per-category counts:")
    for row in summary:
        print(f"{row['category']}: total={row['total']} reachable={row['reachable']}")
    print("Category summary written to site_study_category_summary.csv")


if __name__ == "__main__":
    main()
