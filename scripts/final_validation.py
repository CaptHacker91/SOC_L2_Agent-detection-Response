"""Release validation script: datasets, search behavior, correlation and PDF path.
Run from the project root with Python 3.13 after installing requirements.
"""
from pathlib import Path
from collections import Counter
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pandas as pd

from core.analysis import analyze_events
from core.file_loader import FileLoader
from services.incident_context import find_related_events
from core.security import safe_json
from services.report_service import build_report_data, generate_pdf


def check(condition, label):
    if not condition:
        raise AssertionError(label)
    print(f"PASS: {label}")

def main():
    checks = [
        ("wazuh_events.jsonl", 1000),
        ("splunk_export.jsonl", 500),
        ("BLUE_TEAM_DEFENSE_DATASET.jsonl", 350),
    ]
    for filename, expected_count in checks:
        events = FileLoader(ROOT / "data" / filename).load()
        df = analyze_events(events, source_mode="MOCK")
        check(len(events) == expected_count, f"{filename}: {expected_count} records loaded")
        check(len(df) == expected_count, f"{filename}: {expected_count} records analysed")
        check(not df.attrs.get("parser_errors"), f"{filename}: no parser errors")
        check(not df.attrs.get("normalizer_errors"), f"{filename}: no normalizer errors")
        print(f"  Severity: {dict(Counter(df['severity']))}")

    wazuh = analyze_events(FileLoader(ROOT / "data" / "wazuh_events.jsonl").load(), source_mode="MOCK")
    by_id = wazuh[wazuh["id"].astype(str) == "1790411382.000997"]
    check(len(by_id) == 1, "Alert search test ID resolves to one incident")
    by_rule = wazuh[wazuh["rule_id"].astype(str) == "80700"]
    check(len(by_rule) == 125, "Rule 80700 resolves to 125 incidents")
    check((by_rule["severity"] == "High").all(), "Rule 80700 incidents are High")

    check(by_id.iloc[0].get("filename") == "/opt/app/config.yml", "Wazuh data.path maps to filename")
    web_alerts = wazuh[wazuh["url"].notna()]
    if not web_alerts.empty:
        check(web_alerts.iloc[0].get("uri_path") is not None, "Wazuh URL path is extracted")

    safe_string = safe_json('{"password":"secret-string","client_secret":"client-string","token":"token-string"}')
    check("secret-string" not in safe_string and "client-string" not in safe_string and "token-string" not in safe_string, "Stringified JSON secrets are redacted")
    safe_session = safe_json("GET /login?JSESSIONID=session-secret&token=query-secret HTTP/1.1")
    check("session-secret" not in safe_session and "query-secret" not in safe_session, "Session/query secrets are redacted")

    alert = by_id.iloc[0].to_dict()
    related = find_related_events(wazuh, alert)
    check(len(related) <= 10, "Related events stay within display limit")
    ts = pd.to_datetime(alert["timestamp"], utc=True)
    check(all(abs((ts - pd.to_datetime(e["timestamp"], utc=True)).total_seconds()) <= 7*24*3600 for e in related), "Related events respect 7-day window")
    check(all(e.get("correlation") for e in related), "Related events expose correlation reasons")

    pdf = generate_pdf(build_report_data(alert, "AI analysis not generated."))
    check(pdf.startswith(b"%PDF"), "Incident PDF generation succeeds")
    print("ALL RELEASE VALIDATION CHECKS PASSED")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"RELEASE VALIDATION FAILED: {exc}")
        sys.exit(1)
