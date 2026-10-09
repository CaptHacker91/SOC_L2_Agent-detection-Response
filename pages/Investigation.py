"""Evidence-first Level-2 incident investigation and analyst case-management workspace."""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
import time

import pandas as pd
import streamlit as st

from core.config import load_settings
from core.pipeline import load_pipeline, refresh_data
from core.security import redact_text, safe_json
from core.telemetry_quality import is_present
from core.ui import apply_theme, footer, ioc_chip, metric_card, nav_brand, navigation_links, operational_strip, page_header, progress_bar, render_kv_cards, section_title, status_badge, terminal_box, timeline_html
from services.case_store import allowed_next_statuses, audit_events, case_history, get_or_create_case, record_audit, update_case
from services.chatbot_service import ChatbotService
from services.incident_context import find_related_events
from services.llm_service import LLMService
from services.report_service import build_incident_package, build_report_data, generate_pdf, get_recommendations

NA_TEXT = "Not available in supplied telemetry"
DECISIONS = ["True Positive", "False Positive", "Needs Investigation", "Benign"]
STATUSES = ["NEW", "INVESTIGATING", "REVIEWED", "CLOSED"]
PRIORITIES = ["P1", "P2", "P3", "P4"]


def _get_chatbot() -> ChatbotService:
    settings = load_settings()
    return ChatbotService(settings.groq_api_key, settings.groq_model)


def _get_investigator() -> LLMService:
    settings = load_settings()
    return LLMService(settings.groq_api_key, settings.groq_model)


def _display_timestamp(raw_value, zone_name: str = "UTC") -> str:
    ts = pd.to_datetime(raw_value, utc=True, errors="coerce")
    if pd.isna(ts):
        return NA_TEXT
    try:
        zone = ZoneInfo("Asia/Kolkata") if zone_name == "IST" else ZoneInfo("UTC")
        return ts.to_pydatetime().astimezone(zone).strftime("%Y-%m-%d %H:%M:%S %Z")
    except Exception:
        return str(raw_value)


def value(alert: dict, key: str):
    current = alert.get(key)
    if not is_present(current):
        return NA_TEXT
    if isinstance(current, (dict, list)):
        return safe_json(current, max_chars=3000)
    return redact_text(current)


def _severity_tone(severity: str) -> str:
    return {"Critical": "error", "High": "warning", "Medium": "warning", "Low": "success"}.get(severity, "info")


def _default_priority(severity: str) -> str:
    return {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}.get(severity, "P3")


def _select_alert(df: pd.DataFrame) -> str | None:
    candidates = df.copy()
    if "final_detection" in candidates.columns:
        candidates = candidates[candidates["final_detection"].astype(str).str.lower() != "normal"]
    if candidates.empty or "id" not in candidates.columns:
        return None
    candidates = candidates.sort_values("timestamp", ascending=False, kind="stable") if "timestamp" in candidates.columns else candidates
    search = st.text_input("Find incident", placeholder="ID / IP / host / rule / threat / command", key="investigation_search")
    if search.strip():
        needle = search.strip().lower()
        mask = candidates.astype(str).apply(lambda col: col.str.lower().str.contains(needle, regex=False, na=False)).any(axis=1)
        candidates = candidates[mask]
    if candidates.empty:
        st.info("No incidents match the investigation search.")
        return None
    # Keep selector bounded; actual data is still searchable above.
    candidates = candidates.head(100)
    ids = [str(x) for x in candidates["id"].tolist()]
    current = str(st.session_state.get("selected_alert_id", ""))
    index = ids.index(current) if current in ids else 0
    selected = st.selectbox("SELECT INCIDENT", ids, index=index, format_func=lambda ident: _incident_label(candidates, ident), key="investigation_selector")
    st.session_state["selected_alert_id"] = str(selected)
    return str(selected)


def _incident_label(df: pd.DataFrame, ident: str) -> str:
    row = df[df["id"].astype(str) == str(ident)]
    if row.empty:
        return ident
    data = row.iloc[0]
    return f"{ident} | {data.get('severity', 'Normal')} | {str(data.get('threat', 'Unclassified Event'))[:60]}"


def _get_case(alert: dict, inc_id: str) -> dict:
    return get_or_create_case(inc_id, source=str(alert.get("source") or ""), severity=str(alert.get("severity") or ""), default_priority=_default_priority(str(alert.get("severity") or "")))


def _record_case_audit(action: str, case: dict, inc_id: str, detail: str = "") -> None:
    record_audit(action, incident_id=inc_id, case_id=case.get("case_id", ""), detail=detail)


def _render_case_control(alert: dict, inc_id: str, case: dict) -> dict:
    with st.container(border=True):
        section_title(st, "Case Control", "Persistent analyst workflow. Detection severity and case decision are separate concepts.")
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            allowed_statuses = allowed_next_statuses(str(case.get("status", "NEW")))
            current_status = str(case.get("status", "NEW"))
            status = st.selectbox("Case Status", allowed_statuses, index=allowed_statuses.index(current_status) if current_status in allowed_statuses else 0, key=f"case_status_{inc_id}")
        with c2:
            priority = st.selectbox("Priority", PRIORITIES, index=PRIORITIES.index(case.get("priority", _default_priority(str(alert.get("severity") or "")))) if case.get("priority") in PRIORITIES else 2, key=f"case_priority_{inc_id}")
        with c3:
            analyst = st.text_input("Assigned Analyst", value=case.get("assigned_analyst") or "Unassigned", key=f"case_owner_{inc_id}")
        with c4:
            metric_card(st, "CASE ID", case.get("case_id", "N/A"), "info", "persistent local case store")
        b1, b2, b3 = st.columns(3)
        with b1:
            if st.button("Save Case Control", type="primary", use_container_width=True, key=f"case_save_{inc_id}"):
                case = update_case(case["case_id"], status=status, priority=priority, assigned_analyst=analyst)
                _record_case_audit("CASE_CONTROL_UPDATED", case, inc_id, f"status={status}; priority={priority}; analyst={analyst}")
                st.success("Case control saved.")
                st.rerun()
        with b2:
            if st.button("Mark Reviewed", use_container_width=True, key=f"case_review_{inc_id}"):
                case = update_case(case["case_id"], status="REVIEWED")
                _record_case_audit("CASE_REVIEWED", case, inc_id, "Explicit analyst review state recorded.")
                st.success("Case marked REVIEWED.")
                st.rerun()
        with b3:
            if st.button("Close Case", use_container_width=True, key=f"case_close_{inc_id}"):
                case = update_case(case["case_id"], status="CLOSED")
                _record_case_audit("CASE_CLOSED", case, inc_id, "Analyst closed the case.")
                st.success("Case marked CLOSED.")
                st.rerun()
    return case


def _case_age_seconds(case: dict) -> int:
    try:
        created = pd.to_datetime(case.get("created_at"), utc=True, errors="coerce")
        if pd.isna(created):
            return 0
        return max(0, int((pd.Timestamp.now(tz="UTC") - created).total_seconds()))
    except Exception:
        return 0


def _render_case_sla(case: dict, severity: str) -> None:
    # Demo-safe timer: operational age only; no claim that an external SLA exists.
    age = _case_age_seconds(case)
    target = {"Critical": 30*60, "High": 60*60, "Medium": 4*60*60, "Low": 8*60*60}.get(severity, 4*60*60)
    remaining = target - age
    state = "WITHIN DEMO TARGET" if remaining >= 0 else "DEMO TARGET EXCEEDED"
    mins, secs = divmod(age, 60)
    hours, mins = divmod(mins, 60)
    with st.container(border=True):
        section_title(st, "Case Age / Demo SLA", "Illustrative local timer only; not an organizational SLA commitment.")
        a, b, c = st.columns(3)
        with a: metric_card(st, "CASE AGE", f"{hours:02d}:{mins:02d}:{secs:02d}", "info", "local persisted case age")
        with b: metric_card(st, "TARGET", f"{target//60} min", "normal", f"{severity} demo target")
        with c: metric_card(st, "STATUS", state, "success" if remaining >= 0 else "warning", "simulation")


def _render_case_decision(alert: dict, case: dict, inc_id: str) -> dict:
    with st.container(border=True):
        section_title(st, "Human Decision Boundary", "AI and rule outputs remain advisory. The final classification is explicitly analyst-controlled.")
        current_decision = case.get("decision") or "Needs Investigation"
        decision = st.radio("Case classification", DECISIONS, index=DECISIONS.index(current_decision) if current_decision in DECISIONS else 2, horizontal=True, key=f"decision_{inc_id}")
        note_type = st.selectbox("Note Type", ["Analyst Note", "Evidence Note"], index=0 if case.get("note_type", "Analyst Note") == "Analyst Note" else 1, key=f"note_type_{inc_id}")
        note = st.text_area("Analyst note", value=case.get("note") or "", placeholder="Document the evidence you verified, uncertainty, or next step…", key=f"note_area_{inc_id}")
        ai_recommendation = case.get("ai_recommendation") or "Not generated"
        with st.container(border=True):
            section_title(st, "AI vs Analyst", "The system records the advisory recommendation separately from the human classification.")
            st.write(f"AI recommendation: **{ai_recommendation}**")
            st.caption("Analyst decision is authoritative and may disagree with AI.")
        if st.button("Save Analyst Decision", type="primary", use_container_width=True, key=f"save_decision_{inc_id}"):
            case = update_case(case["case_id"], decision=decision, note=note, note_type=note_type)
            override = bool(case.get("ai_recommendation") and case.get("ai_recommendation") not in {"Not generated", decision})
            _record_case_audit("ANALYST_DECISION", case, inc_id, f"decision={decision}; note_type={note_type}; ai_override={override}")
            st.success("Analyst decision persisted.")
            st.rerun()
    return case


def _evidence_score(alert: dict) -> int:
    raw = alert.get("evidence_completeness")
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return 0


def _render_incident_header(alert: dict, inc_id: str, related: list, case: dict) -> None:
    severity = str(alert.get("severity") or "Normal")
    risk = alert.get("risk_score")
    conf = alert.get("confidence_score")
    with st.container(border=True):
        left, right = st.columns([3.5, 1])
        with left:
            st.caption("// SELECTED INCIDENT //")
            st.markdown(f"### {html.escape(str(alert.get('threat') or 'Unclassified Event'))}")
            st.caption(f"INCIDENT `{html.escape(str(inc_id))}` // CASE `{html.escape(str(case.get('case_id')) )}` // SOURCE `{html.escape(str(value(alert, 'source')) )}`")
        with right:
            status_badge(st, severity.upper(), _severity_tone(severity))
        cards = [
            ("SEVERITY", severity, severity.lower() if severity in {"Critical", "High", "Medium", "Low"} else "normal", "Triage dimension"),
            ("RISK", f"{risk}/10" if risk is not None else NA_TEXT, "high" if isinstance(risk, (int, float)) and risk >= 7 else "normal", "Engine assessment"),
            ("CONFIDENCE", value(alert, "confidence_level"), "normal", "Detection match confidence"),
            ("CASE STATUS", case.get("status", "NEW"), "success" if case.get("status") in {"REVIEWED", "CLOSED"} else "warning", "Persistent workflow"),
            ("DECISION", case.get("decision") or "Not recorded", "info", "Human decision"),
        ]
        cols = st.columns(5)
        for col, item in zip(cols, cards):
            with col: metric_card(st, item[0], item[1], item[2], item[3])
        risk_num = float(risk) if isinstance(risk, (int, float)) else 0.0
        conf_num = float(conf * 100) if isinstance(conf, (int, float)) and conf <= 1 else (float(conf) if isinstance(conf, (int, float)) else 0.0)
        a, b, c = st.columns(3)
        with a: progress_bar(st, risk_num * 10, "RISK SIGNAL", f"{risk_num:.1f}/10")
        with b: progress_bar(st, conf_num, "CONFIDENCE SIGNAL", f"{conf_num:.0f}%")
        with c: progress_bar(st, _evidence_score(alert), "EVIDENCE COMPLETENESS", f"{_evidence_score(alert)}%")
        st.caption(html.escape(str(alert.get("detection_reason") or "Detection reason not supplied.")))


def _metadata(alert: dict, display_tz: str = "UTC") -> None:
    fields = [
        ("Timestamp (display)", _display_timestamp(alert.get("timestamp"), display_tz)), ("Source Timestamp", value(alert, "timestamp")), ("Data Source", value(alert, "source")), ("Host", value(alert, "hostname")),
        ("Agent ID", value(alert, "agent_id")), ("Agent IP", value(alert, "agent_ip")), ("Source IP", value(alert, "source_ip")),
        ("Destination IP", value(alert, "destination_ip")), ("Username", value(alert, "username")), ("Event Type", value(alert, "event_type")),
        ("Rule ID", value(alert, "rule_id")), ("Rule Version", value(alert, "rule_version")), ("Rule Level", value(alert, "rule_level")),
        ("Rule Enabled", value(alert, "rule_enabled")), ("Schema", value(alert, "schema_version")), ("Fingerprint", value(alert, "event_fingerprint")),
    ]
    render_kv_cards(st, [(k, html.escape(str(v))) for k, v in fields], columns=4)


def _ioc_items(alert: dict) -> list[tuple[str, str]]:
    fields = [("IP", alert.get("source_ip")), ("DEST", alert.get("destination_ip")), ("DOMAIN", alert.get("domain")), ("URL", alert.get("url")), ("HASH", alert.get("file_hash")), ("FILE", alert.get("filename")), ("USER", alert.get("username"))]
    return [(kind, redact_text(val)) for kind, val in fields if is_present(val)]


def _flatten_paths(value, prefix=""):
    rows = []
    if isinstance(value, dict):
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(_flatten_paths(item, path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            rows.extend(_flatten_paths(item, f"{prefix}[{index}]"))
    else:
        rows.append((prefix, redact_text(value)))
    return rows


def _render_rule_explanation(alert: dict) -> None:
    with st.container(border=True):
        section_title(st, "WHY THIS ALERT FIRED", "Trace the configured detection signature and the observed fields that were available to the engine.")
        render_kv_cards(st, [
            ("Threat Signature", value(alert, "threat")), ("Rule ID", value(alert, "rule_id")), ("Rule Version", value(alert, "rule_version")),
            ("Rule Description", value(alert, "rule_description")), ("Rule Source", value(alert, "rule_source")), ("Detection Reason", value(alert, "detection_reason")),
            ("Observed Result", value(alert, "final_detection")), ("Confidence Reason", value(alert, "confidence_reason")),
        ], columns=4)
        st.caption(html.escape(str(alert.get("why_alert_fired") or "No explainability trace was produced.")))
        with st.expander("Evidence checklist"):
            st.write(str(alert.get("evidence_checklist") or "Not available"))
    risk = float(alert.get("risk_score")) if isinstance(alert.get("risk_score"), (int, float)) else None
    with st.container(border=True):
        section_title(st, "Why This May Be Benign / Unconfirmed", "A mature triage console shows uncertainty as well as suspicion.")
        if str(alert.get("confirmation_status", "Unconfirmed")) == "Unconfirmed":
            st.info("This alert is not analyst-confirmed. A single rule match, risk score or severity does not independently establish compromise.")
        elif risk is not None and risk < 7:
            st.info("The configured risk signal is below the high-priority threshold used by this console; corroborating evidence is still required.")
        else:
            st.info("No benign conclusion is asserted from the available telemetry. Analyst validation remains required.")


def _render_timeline(alert: dict, related: list, case: dict) -> None:
    ts = pd.to_datetime(alert.get("timestamp"), utc=True, errors="coerce")
    start = ts.strftime("%Y-%m-%d %H:%M:%S UTC") if not pd.isna(ts) else "timestamp unavailable"
    case_steps = [(h.get("at", ""), f"{h.get('action', 'CASE')} — {h.get('detail', '')}") for h in reversed(case_history(case["case_id"], 8))]
    steps = [(start, "Telemetry event observed"), ("STEP 02", f"Detection: {alert.get('final_detection', NA_TEXT)}"), ("STEP 03", f"Risk: {alert.get('risk_score', NA_TEXT)} / 10"), ("STEP 04", f"MITRE: {alert.get('mapped_technique', NA_TEXT)}"), ("STEP 05", f"Related context: {len(related)} records"), ("STEP 06", f"Case state: {case.get('status', 'NEW')}")] + case_steps
    timeline_html(st, steps[:16])


def _parse_ai(text: str) -> dict[str, str]:
    sections = {"SUMMARY": "", "EVIDENCE": "", "RISK": "", "MITRE": "", "LIMITATIONS": "", "RECOMMENDATIONS": ""}
    current = None
    for line in str(text or "").splitlines():
        clean = line.strip()
        heading = clean.strip("#*: ").upper()
        if heading in sections:
            current = heading
            continue
        if current:
            sections[current] += ("\n" if sections[current] else "") + clean
    if not any(sections.values()):
        sections["SUMMARY"] = str(text or "No AI output generated.")
    return sections


def _render_ai(alert: dict, related: list, case: dict, inc_id: str) -> None:
    investigator = _get_investigator()
    chatbot = _get_chatbot()
    report_key = f"ai_report_{inc_id}"
    chat_key = f"chat_history_{inc_id}"
    st.session_state.setdefault(report_key, None)
    st.session_state.setdefault(chat_key, [])
    with st.container(border=True):
        section_title(st, "AI Investigation Assistant", "Grounded assistance over the selected incident. With no API key, the console uses deterministic evidence-grounded analysis; with Groq configured, the LLM is optional.")
        status_badge(st, "LLM ENABLED // GROUNDED" if investigator.available else "LOCAL GROUNDED MODE // NO API REQUIRED", "success" if investigator.available else "info")
        quick = st.selectbox(
            "Quick question",
            ["Choose…", "What is the highest-risk activity?", "Why was this alert flagged?", "Which MITRE technique is mapped?", "Summarize this incident", "What should the analyst investigate next?"],
            key=f"incident_ai_quick_{inc_id}",
        )
        if quick != "Choose…":
            st.caption(f"Suggested prompt: {html.escape(quick)}")
        if st.button("Generate AI Investigation", type="primary", use_container_width=True, key=f"generate_ai_{inc_id}"):
            ai_started = time.perf_counter()
            with st.spinner("$ ai_assist --grounded incident context ..."):
                st.session_state[report_key] = investigator.investigate(alert, related)
            st.session_state[f"ai_latency_{inc_id}"] = round((time.perf_counter() - ai_started) * 1000, 2)
            record_audit("AI_ANALYSIS_GENERATED", incident_id=inc_id, case_id=case.get("case_id", ""), detail="Grounded AI/local investigation requested.")
        if st.session_state[report_key]:
            sections = _parse_ai(st.session_state[report_key])
            ai_recommendation = sections.get("RISK") or sections.get("SUMMARY") or "Not generated"
            try:
                ai_conf = alert.get("confidence_score")
                update_case(case["case_id"], ai_recommendation=ai_recommendation[:1200], ai_confidence=float(ai_conf) if isinstance(ai_conf, (int, float)) else None, ai_latency_ms=st.session_state.get(f"ai_latency_{inc_id}"))
                case = get_or_create_case(inc_id, source=str(alert.get("source") or ""), severity=str(alert.get("severity") or ""), default_priority=_default_priority(str(alert.get("severity") or "")))
            except Exception:
                pass
            latency = st.session_state.get(f"ai_latency_{inc_id}")
            if latency is not None:
                st.caption(f"Generation latency: {latency} ms // source: {'Groq LLM' if investigator.available else 'local grounded engine'}")
            cols = st.columns(2)
            order = [("SUMMARY", "Threat Summary"), ("EVIDENCE", "Key Evidence"), ("RISK", "Risk Assessment"), ("MITRE", "MITRE Context"), ("LIMITATIONS", "Limitations / Missing Evidence"), ("RECOMMENDATIONS", "Recommended Actions")]
            for idx, (key, title) in enumerate(order):
                with cols[idx % 2]:
                    with st.container(border=True):
                        section_title(st, title)
                        st.markdown(sections.get(key) or "Not supplied.")
            if st.button("Regenerate Investigation", use_container_width=True, key=f"regen_ai_{inc_id}"):
                st.session_state[report_key] = None
                st.rerun()
    with st.container(border=True):
        section_title(st, "Incident Report & Evidence Package", "Exports use persisted analyst state and redaction-safe report generation.")
        report_data = build_report_data(alert, st.session_state.get(report_key) or "AI analysis not generated.", related=related, case=case, analyst_decision=str(case.get("decision") or "Not recorded"), analyst_note=str(case.get("note") or "Not recorded"), assigned_analyst=str(case.get("assigned_analyst") or "Unassigned"))
        report_data["case_history"] = case_history(case["case_id"], 100)
        report_data["audit_history"] = audit_events(100, incident_id=inc_id)
        try:
            pdf_bytes = generate_pdf(report_data)
            package_bytes = build_incident_package(report_data)
            safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", str(case.get("case_id", inc_id))).strip("._-") or "incident"
            c1, c2 = st.columns(2)
            with c1:
                st.download_button("Download Incident PDF", data=pdf_bytes, file_name=f"SOC_Report_{safe_id}.pdf", mime="application/pdf", use_container_width=True, key=f"pdf_download_{inc_id}")
            with c2:
                st.download_button("Generate Incident Package", data=package_bytes, file_name=f"SOC_Package_{safe_id}.zip", mime="application/zip", use_container_width=True, key=f"pkg_download_{inc_id}")
        except Exception as exc:
            st.error(f"Report generation failed safely: {type(exc).__name__}.")
    with st.container(border=True):
        section_title(st, "Incident Chat", "Ask grounded questions about this incident. Local fallback works without an API key.")
        for msg in st.session_state[chat_key]:
            with st.chat_message(msg["role"]): st.markdown(msg["content"])
        question = st.chat_input("Ask about this incident", key=f"chat_input_{inc_id}")
        if question:
            st.session_state[chat_key].append({"role": "user", "content": question})
            # Reuse the local grounded dataset answer as a safe fallback when Groq is unavailable.
            answer = chatbot.ask(question, alert, st.session_state[chat_key], related) if chatbot.available else __import__("services.chatbot_service", fromlist=["answer_dataset_question"]).answer_dataset_question(question, pd.DataFrame([alert]), [case])
            st.session_state[chat_key].append({"role": "assistant", "content": answer})
            record_audit("AI_CHAT_MESSAGE", incident_id=inc_id, case_id=case.get("case_id", ""), detail="Incident chat message recorded.")
            st.rerun()
    with st.container(border=True):
        section_title(st, "Incident Report & Evidence Package", "Exports use persisted analyst case state and redaction-safe report generation.")
        report_data = build_report_data(alert, st.session_state.get(report_key) or "AI analysis not generated.", related=related, case=case, analyst_decision=str(case.get("decision") or "Not recorded"), analyst_note=str(case.get("note") or "Not recorded"), assigned_analyst=str(case.get("assigned_analyst") or "Unassigned"))
        report_data["case_history"] = case_history(case["case_id"], 100)
        report_data["audit_history"] = audit_events(100, incident_id=inc_id)
        try:
            pdf_bytes = generate_pdf(report_data)
            package_bytes = build_incident_package(report_data)
            safe_id = re.sub(r"[^A-Za-z0-9._-]+", "_", str(case.get("case_id", inc_id))).strip("._-") or "incident"
            c1, c2 = st.columns(2)
            with c1:
                st.download_button("Download Incident PDF", data=pdf_bytes, file_name=f"SOC_Report_{safe_id}.pdf", mime="application/pdf", use_container_width=True, key=f"pdf_download_{inc_id}")
            with c2:
                st.download_button("Generate Incident Package", data=package_bytes, file_name=f"SOC_Package_{safe_id}.zip", mime="application/zip", use_container_width=True, key=f"pkg_download_{inc_id}")
        except Exception as exc:
            st.error(f"Report generation failed safely: {type(exc).__name__}.")
    with st.container(border=True):
        section_title(st, "Incident Chat", "Ask grounded questions about this incident. Responses are advisory and bounded by supplied context.")
        if not chatbot.available:
            st.info(chatbot.status_message)
        else:
            for msg in st.session_state[chat_key]:
                with st.chat_message(msg["role"]): st.markdown(msg["content"])
            question = st.chat_input("Ask about this incident", key=f"chat_input_{inc_id}")
            if question:
                st.session_state[chat_key].append({"role": "user", "content": question})
                answer = chatbot.ask(question, alert, st.session_state[chat_key], related)
                st.session_state[chat_key].append({"role": "assistant", "content": answer})
                record_audit("AI_CHAT_MESSAGE", incident_id=inc_id, case_id=case.get("case_id", ""), detail="Incident chat message recorded.")
                st.rerun()


def main() -> None:
    st.set_page_config(page_title="Investigation // SOC L2", page_icon="🔎", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "evidence-first case management console", "ANALYST MODE", "info")
        navigation_links(st, include_system=True)
        if st.button("Reload Dataset", use_container_width=True, key="investigation_reload"):
            with st.spinner("$ reload verified telemetry ..."):
                refresh_data()
            st.rerun()
        st.caption("Telemetry is authoritative. AI is advisory. Human decision controls case state.")
    df = load_pipeline()
    page_header(st, "Incident Investigation", "inspect evidence, explain the detection, correlate context, manage the case, request AI assistance and export evidence")
    st.session_state.setdefault("display_tz", "IST")
    display_tz = st.selectbox("Display timezone", ["IST", "UTC"], key="investigation_display_tz")
    if df is None or df.empty:
        st.warning("NO TELEMETRY LOADED // open Ingestion Center and run the configured source.")
        footer(st)
        return
    query_incident = str(st.query_params.get("incident", "")) if hasattr(st, "query_params") else ""
    if query_incident and "id" in df.columns and query_incident in set(df["id"].astype(str)):
        st.session_state["selected_alert_id"] = query_incident
    inc_id = _select_alert(df)
    if inc_id is None:
        footer(st)
        return
    match = df[df["id"].astype(str) == str(inc_id)]
    if match.empty:
        st.error(f"Incident {inc_id} is not present in the current dataset.")
        footer(st)
        return
    alert = match.iloc[0].to_dict()
    case = _get_case(alert, inc_id)
    related_mode = st.selectbox("Correlation Mode", ["auto", "source_ip", "host", "username", "rule", "host_rule"], key=f"corr_mode_{inc_id}")
    related = find_related_events(df, alert, mode=related_mode)
    _render_incident_header(alert, inc_id, related, case)
    operational_strip(st, [("EVIDENCE", "AVAILABLE" if is_present(alert.get("raw_event")) else "LIMITED", "success" if is_present(alert.get("raw_event")) else "warning"), ("MITRE", "MAPPED" if not str(alert.get("mapped_technique", "")).lower().startswith("not mapped") else "NOT MAPPED", "success" if not str(alert.get("mapped_technique", "")).lower().startswith("not mapped") else "warning"), ("RELATED", len(related), "info"), ("CASE", case.get("status", "NEW"), "success" if case.get("status") in {"REVIEWED", "CLOSED"} else "warning"), ("AI", "ADVISORY", "info")])
    tabs = st.tabs(["OVERVIEW", "EVIDENCE", "CORRELATION", "CASE", "AI & REPORT", "HISTORY"])
    with tabs[0]:
        _render_rule_explanation(alert)
        with st.container(border=True):
            section_title(st, "Normalized Event Metadata")
            _metadata(alert, display_tz)
        with st.container(border=True):
            section_title(st, "Incident Timeline", "Telemetry first, then processing/analyst state; no attack step is invented.")
            _render_timeline(alert, related, case)
        with st.container(border=True):
            section_title(st, "MITRE ATT&CK", "Configuration and telemetry mappings only.")
            render_kv_cards(st, [("Technique ID", html.escape(str(value(alert, "mapped_technique")))), ("Technique Name", html.escape(str(value(alert, "mitre_technique_name")))), ("Tactic", html.escape(str(value(alert, "mitre_tactic")))), ("Mapping Source", html.escape(str(value(alert, "mitre_mapping_source"))))], columns=4)
        with st.container(border=True):
            section_title(st, "IOC Snapshot", "Only indicators present in selected telemetry.")
            iocs = _ioc_items(alert)
            if iocs:
                for kind, item in iocs: ioc_chip(st, kind, item)
            else: st.info("No IOC-like fields are present.")
    with tabs[1]:
        with st.container(border=True):
            section_title(st, "Observed Evidence")
            evidence = {"Process": value(alert, "process"), "Command": value(alert, "command"), "Filename": value(alert, "filename"), "File Hash": value(alert, "file_hash"), "Domain": value(alert, "domain"), "URL": value(alert, "url"), "URI Path": value(alert, "uri_path"), "URI Query": value(alert, "uri_query"), "HTTP Method": value(alert, "http_method"), "HTTP Status": value(alert, "http_status"), "User Agent": value(alert, "user_agent"), "Referer": value(alert, "referer")}
            render_kv_cards(st, [(k, html.escape(str(v))) for k, v in evidence.items()], columns=2)
        with st.container(border=True):
            section_title(st, "Raw / Normalized / Provenance")
            raw_view = st.radio("View", ["Redacted RAW", "Normalized JSON", "Field Provenance", "JSON Paths"], horizontal=True, key=f"raw_view_{inc_id}")
            if raw_view == "Redacted RAW":
                st.code(safe_json(alert.get("raw_event") or alert.get("original_log"), max_chars=15000), language="json", wrap_lines=True)
            elif raw_view == "Normalized JSON":
                normalized = {k: alert.get(k) for k in ["id", "timestamp", "source", "hostname", "source_ip", "destination_ip", "username", "event_type", "rule_id", "rule_version", "threat", "severity", "risk_score", "confidence_level", "mapped_technique", "confirmation_status", "event_fingerprint", "evidence_completeness_label"] if k in alert}
                st.code(safe_json(normalized, max_chars=10000), language="json", wrap_lines=True)
            elif raw_view == "Field Provenance":
                provenance = {"source_system": alert.get("source"), "source_type": alert.get("source_type"), "normalized_contract": {"source_ip": "source_ip", "hostname": "hostname", "rule_id": "rule_id", "timestamp": "timestamp"}, "event_fingerprint": alert.get("event_fingerprint"), "schema_version": alert.get("schema_version")}
                st.json(provenance, expanded=True)
            else:
                raw = alert.get("raw_event")
                if isinstance(raw, dict):
                    path_rows = _flatten_paths(raw)
                    query = st.text_input("JSON path filter", placeholder="data.win / commandLine / srcip", key=f"json_path_filter_{inc_id}")
                    if query.strip(): path_rows = [r for r in path_rows if query.lower() in r[0].lower() or query.lower() in str(r[1]).lower()]
                    st.dataframe(pd.DataFrame(path_rows, columns=["JSON Path", "Observed Value"]), use_container_width=True, hide_index=True, height=450)
                else:
                    st.info("Raw event is not a structured JSON object; JSON path inspection is not available.")
    with tabs[2]:
        with st.container(border=True):
            section_title(st, f"Incident Correlation // {len(related)} related", "Correlation mode is explicit and time-bounded. Related events provide context only.")
            if related:
                related_df = pd.DataFrame(related)
                cols = [c for c in ["id", "timestamp", "severity", "threat", "correlation", "correlation_confidence", "correlation_window_hours", "detection_reason", "source_ip", "hostname"] if c in related_df.columns]
                st.dataframe(related_df[cols], use_container_width=True, hide_index=True, height=450)
            else: st.info("No related events were found using the selected correlation mode.")
        with st.container(border=True):
            section_title(st, "Relationship Graph")
            st.markdown(f"`{alert.get('source_ip') or alert.get('hostname') or 'source unavailable'}` → `{alert.get('hostname') or 'host unavailable'}` → `RULE {alert.get('rule_id') or 'N/A'}` → `{alert.get('mapped_technique') or 'MITRE not mapped'}` → `CASE {case.get('case_id')}`")
    with tabs[3]:
        case = _render_case_control(alert, inc_id, case)
        _render_case_sla(case, str(alert.get("severity") or "Medium"))
        case = _render_case_decision(alert, case, inc_id)
        with st.container(border=True):
            section_title(st, "Analyst Playbook", "Checklist for Level-2 triage; checking an item does not itself change case state.")
            for label in ["Validate source and timestamp", "Review host/user context", "Inspect command/process evidence", "Review related telemetry", "Verify MITRE mapping", "Record analyst decision"]:
                st.checkbox(label, key=f"playbook_{inc_id}_{re.sub(r'[^a-z0-9]+','_',label.lower())}")
        rec = get_recommendations(alert.get("mitre_tactic"), alert.get("severity"))
        with st.container(border=True):
            section_title(st, "Recommendations + Rationale", "Conservative guidance derived from the observed tactic/severity configuration.")
            for title, key in [("Investigation", "investigation"), ("Containment", "containment"), ("Remediation", "remediation")]:
                st.markdown(f"**{title}**")
                for item in rec.get(key, []): st.markdown(f"- {html.escape(str(item))}")
                st.caption("Rationale: recommendation is tied to configured context; action still requires analyst validation.")
    with tabs[4]:
        _render_ai(alert, related, case, inc_id)
    with tabs[5]:
        with st.container(border=True):
            section_title(st, "Case History", "Persistent status/assignment/decision changes for this case.")
            history = case_history(case["case_id"], 100)
            st.dataframe(history, use_container_width=True, hide_index=True, height=420) if history else st.info("No case-history events yet.")
        with st.container(border=True):
            section_title(st, "Audit History")
            events = audit_events(100, incident_id=inc_id)
            st.dataframe(events, use_container_width=True, hide_index=True, height=300) if events else st.info("No persistent audit events yet.")
        with st.container(border=True):
            section_title(st, "Decision Boundary")
            terminal_box(st, ["detection != confirmation", "severity != proof_of_compromise", "AI output != telemetry", "analyst_decision = human_controlled", "case_status = persistent_workflow"])
    footer(st, "SOC_L2 // INVESTIGATION // EVIDENCE FIRST // AI ADVISORY // HUMAN DECISION // CASE PERSISTENCE")


if __name__ == "__main__":
    main()
