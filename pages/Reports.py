"""Centralized report and incident-package center for completed investigations."""
from __future__ import annotations

import html
import re
import pandas as pd

import streamlit as st

from core.config import load_settings
from core.pipeline import load_pipeline
from core.security import safe_json
from core.ui import apply_theme, footer, metric_card, nav_brand, navigation_links, operational_strip, page_header, section_title, status_badge
from services.case_store import audit_events, case_history, list_cases
from services.report_service import build_incident_package, build_report_data, generate_pdf


def main() -> None:
    st.set_page_config(page_title="Reports // SOC L2", page_icon="📄", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "case reports + evidence packages", "REPORT CENTER", "info")
        navigation_links(st)
    settings = load_settings()
    df = load_pipeline()
    cases = list_cases(250)
    page_header(st, "Reports Center", "rebuild a case report from persisted analyst state and export a portable evidence package")
    operational_strip(st, [("CASES", len(cases), "info"), ("SOURCE", settings.data_source, "success" if settings.data_source == "MOCK" else "info"), ("REPORT ENGINE", "READY", "success"), ("EVIDENCE", "REDACTION ENABLED", "success")])
    if not cases:
        st.info("No cases have been created yet. Open Investigation and save a case decision or assignment.")
        footer(st)
        return
    labels = {c["case_id"]: f"{c['case_id']} | {c['status']} | {c.get('severity') or 'N/A'} | {c['incident_id']}" for c in cases}
    selected_case_id = st.selectbox("Select case", list(labels), format_func=lambda key: labels[key], key="reports_case_selector")
    case = next(c for c in cases if c["case_id"] == selected_case_id)
    match = df[df.get("id", []).astype(str) == str(case["incident_id"])] if "id" in df.columns else df.iloc[0:0]
    if match.empty:
        st.warning("The selected incident is not present in the currently loaded telemetry. The case record remains intact; load the matching source dataset to rebuild its report.")
        footer(st)
        return
    alert = match.iloc[0].to_dict()
    report_data = build_report_data(alert, "AI analysis not generated.", related=[], case=case, analyst_decision=str(case.get("decision") or "Not recorded"), analyst_note=str(case.get("note") or "Not recorded"), assigned_analyst=str(case.get("assigned_analyst") or "Unassigned"))
    report_data["case_history"] = case_history(case["case_id"], 100)
    report_data["audit_history"] = audit_events(100, incident_id=case["incident_id"])
    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card(st, "CASE STATUS", case["status"], "success" if case["status"] == "CLOSED" else "warning", "persisted")
    with c2: metric_card(st, "PRIORITY", case["priority"], "high" if case["priority"] in {"P1", "P2"} else "info", "case priority")
    with c3: metric_card(st, "DECISION", case.get("decision") or "Not recorded", "info", "human analyst")
    with c4: metric_card(st, "EVIDENCE", report_data.get("evidence_completeness", "N/A"), "success", "telemetry completeness")
    with st.container(border=True):
        section_title(st, "Case Metadata")
        st.json({k: case.get(k) for k in ["case_id", "incident_id", "status", "priority", "assigned_analyst", "decision", "note", "note_type", "ai_recommendation", "ai_latency_ms", "source", "severity", "created_at", "updated_at"]}, expanded=True)
        st.caption(f"Case history events: {len(report_data['case_history'])} // Audit events: {len(report_data['audit_history'])} // Evidence fingerprint: {report_data.get('event_fingerprint', 'N/A')}")
    try:
        pdf = generate_pdf(report_data)
        safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", str(case["case_id"])) or "case"
        c1, c2 = st.columns(2)
        with c1: st.download_button("Download PDF Report", data=pdf, file_name=f"SOC_{safe_id}.pdf", mime="application/pdf", use_container_width=True, key="reports_download_pdf")
        with c2: st.download_button("Download Incident Package", data=build_incident_package(report_data), file_name=f"SOC_{safe_id}_PACKAGE.zip", mime="application/zip", use_container_width=True, key="reports_download_package")
    except Exception as exc:
        st.error(f"Report generation failed safely: {type(exc).__name__}.")
    with st.expander("Report payload preview"):
        st.code(safe_json(report_data, max_chars=16000), language="json", wrap_lines=True)
    footer(st, "SOC_L2 // REPORT CENTER // HUMAN DECISION // INTEGRITY METADATA")

if __name__ == "__main__":
    main()
