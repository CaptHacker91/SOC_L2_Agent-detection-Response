"""SOC L2 Agent command console: telemetry, triage, analytics and analyst hand-off."""
from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from core.config import load_settings
from core.pipeline import DEFAULT_LIMIT, DEFAULT_LOOKBACK, LOOKBACK_OPTIONS, get_data_source_status, get_wazuh_controls, load_pipeline, refresh_data, run_connection_test
from core.security import safe_json
from core.telemetry_quality import data_quality_summary
from core.ui import alert_feed_html, apply_theme, command_matrix, command_palette, data_quality_cards, footer, metric_card, mini_field, nav_brand, navigation_links, operational_strip, page_header, progress_bar, render_kv_cards, section_title, show_pipeline, sort_alerts_newest_first, status_badge, terminal_box
from core.visualization import alert_trend, confidence_breakdown, detection_bar, event_category_bar, mitre_tactic_bar, risk_confidence_scatter, risk_distribution, safe_chart, severity_donut, source_distribution, top_techniques
from services.case_store import audit_events, case_metrics, list_cases
from services.chatbot_service import ChatbotService, answer_dataset_question


def _status_tone(status: dict) -> str:
    if status.get("error"):
        return "error"
    if status.get("connected"):
        return "success"
    if status.get("message") not in {None, "Not checked"}:
        return "warning"
    return "info"


def _severity_tone(severity: str) -> str:
    return {"Critical": "error", "High": "warning", "Medium": "warning", "Low": "success"}.get(severity, "info")


def _clean(value, fallback: str = "Not available") -> str:
    if value is None or str(value).strip().lower() in {"", "none", "nan", "null"}:
        return fallback
    return html.escape(str(value))


def _detections(df: pd.DataFrame) -> pd.DataFrame:
    if "final_detection" not in df.columns:
        return df.iloc[0:0].copy()
    return df[df["final_detection"].astype(str).str.lower() != "normal"].copy()


def _health_score(df: pd.DataFrame, status: dict) -> int:
    """Transparent console-readiness score from pipeline health and data quality, not threat severity."""
    if df is None or df.empty:
        return 0
    q = data_quality_summary(df)
    score = 100
    if status.get("error"):
        score -= 30
    if q["parser_errors"]:
        score -= min(20, q["parser_errors"])
    if q["normalizer_errors"]:
        score -= min(20, q["normalizer_errors"])
    if q["valid_timestamps"] < q["records"]:
        score -= 10
    if q["missing_core_fields"]:
        score -= min(10, q["missing_core_fields"])
    if q["duplicate_events"]:
        score -= 5
    return max(0, min(100, int(score)))


def _paginate(df: pd.DataFrame, key_prefix: str, page_size: int = 25) -> pd.DataFrame:
    if df.empty:
        return df
    page_key = f"{key_prefix}_page"
    max_page = max(1, (len(df) - 1) // page_size + 1)
    current = int(st.session_state.get(page_key, 1))
    current = max(1, min(current, max_page))
    a, b, c = st.columns([1, 1, 4])
    with a:
        if st.button("← Previous", disabled=current <= 1, key=f"{key_prefix}_prev", use_container_width=True):
            st.session_state[page_key] = current - 1
            st.rerun()
    with b:
        if st.button("Next →", disabled=current >= max_page, key=f"{key_prefix}_next", use_container_width=True):
            st.session_state[page_key] = current + 1
            st.rerun()
    with c:
        st.caption(f"PAGE {current} / {max_page}  //  {len(df):,} MATCHING RECORDS  //  {page_size} PER PAGE")
    start = (current - 1) * page_size
    return df.iloc[start:start + page_size]


def render_sidebar(settings, status) -> bool:
    with st.sidebar:
        nav_brand(st, "enterprise hacker-terminal analyst console", "SYSTEM ONLINE" if not status.get("error") else "CHECK SOURCE", _status_tone(status))
        navigation_links(st, include_system=True)
        st.divider()
        st.markdown("**SOURCE //**")
        mini_field(st, "Configured", html.escape(str(settings.data_source)))
        if settings.data_source == "WAZUH":
            limit, lookback = get_wazuh_controls()
            st.number_input("Alerts to fetch", min_value=10, max_value=1000, value=limit, step=10, key="wazuh_limit")
            st.selectbox("Lookback", LOOKBACK_OPTIONS, index=LOOKBACK_OPTIONS.index(lookback), key="wazuh_lookback")
            st.session_state["wazuh_limit"] = int(st.session_state["wazuh_limit"])
            st.session_state["wazuh_lookback"] = str(st.session_state["wazuh_lookback"])
        elif settings.data_source == "MOCK":
            status_badge(st, "MOCK / DEMO MODE", "success")
        else:
            status_badge(st, "SPLUNK / LIVE MODE", "info")
        st.divider()
        presentation_mode = st.toggle("Presentation Mode", value=False, key="dashboard_presentation_mode", help="Condense the dashboard to strongest demo views.")
        if st.button("Run Ingestion", use_container_width=True, type="primary", key="dashboard_run_ingestion"):
            with st.spinner("$ ingest -> parse -> normalize -> detect -> enrich ..."):
                refresh_data()
            st.rerun()
        if st.button("Test Source", use_container_width=True, key="dashboard_test_source"):
            with st.spinner("$ probe configured source ..."):
                run_connection_test()
            st.rerun()
        st.caption("AI = advisory. Telemetry = authoritative. Final status = analyst-controlled.")
        st.caption("L2 // ANALYST NODE // ENCRYPTED")
        return presentation_mode



def render_global_search(df: pd.DataFrame) -> None:
    """Global incident/event search surface for fast analyst navigation."""
    with st.container(border=True):
        section_title(st, "Global Search", "Search the loaded telemetry by incident ID, host, source IP, rule, threat or MITRE technique.")
        query = st.text_input("SEARCH // TELEMETRY", placeholder="incident ID / host / IP / rule / threat / MITRE...", key="dashboard_global_search_bar")
        if not query.strip():
            st.caption("Search is bounded to the currently loaded dataset; no external index is queried.")
            return
        needle = query.strip().lower()
        view = df.copy()
        mask = view.astype(str).apply(lambda col: col.str.lower().str.contains(needle, regex=False, na=False)).any(axis=1)
        view = view[mask]
        st.caption(f"$ global search returned {len(view):,} matching record(s)")
        if view.empty:
            st.info("No matching telemetry found in the current dataset.")
            return
        cols = [c for c in ["id", "timestamp", "severity", "risk_score", "threat", "hostname", "source_ip", "rule_id", "mapped_technique"] if c in view.columns]
        st.dataframe(view[cols].head(12), use_container_width=True, hide_index=True, height=300)
        ids = [str(x) for x in view["id"].head(50).tolist()] if "id" in view.columns else []
        if ids:
            chosen = st.selectbox("OPEN MATCH", ids, key="dashboard_global_search_match")
            if st.button("Open in Investigation", type="primary", use_container_width=True, key="dashboard_global_search_open"):
                st.session_state["selected_alert_id"] = chosen
                st.switch_page("pages/Investigation.py")


def render_soc_snapshot(df: pd.DataFrame, status: dict) -> None:
    """Render executive SOC snapshot using only currently observable telemetry and persisted cases."""
    detections = _detections(df)
    severity = detections["severity"].value_counts() if "severity" in detections.columns else pd.Series(dtype="int64")
    metrics = case_metrics()
    with st.container(border=True):
        section_title(st, "Live SOC Snapshot", "A compact executive view of the current telemetry, case lifecycle and console readiness.")
        cols = st.columns(8)
        values = [
            ("CRITICAL", int(severity.get("Critical", 0)), "critical"), ("HIGH", int(severity.get("High", 0)), "high"),
            ("MEDIUM", int(severity.get("Medium", 0)), "medium"), ("LOW", int(severity.get("Low", 0)), "low"),
            ("TOTAL EVENTS", len(df), "normal"), ("CASES", metrics.get("total", 0), "info"),
            ("OPEN", max(0, metrics.get("total", 0) - metrics.get("reviewed", 0) - metrics.get("closed", 0)), "warning"),
            ("HEALTH", f"{_health_score(df, status)}%", "success"),
        ]
        for col, (label, value, tone) in zip(cols, values):
            with col: metric_card(st, label, value, tone, "current state")

    lower = st.columns([1.15, 1, 1])
    with lower[0]:
        with st.container(border=True):
            section_title(st, "Top Active Threats", "Highest-risk observed detections; sorted by telemetry risk signal.")
            if detections.empty:
                st.info("No active detections.")
            else:
                tmp = detections.copy()
                tmp["_risk"] = pd.to_numeric(tmp.get("risk_score", 0), errors="coerce").fillna(-1)
                top = tmp.sort_values("_risk", ascending=False, kind="stable").head(5)
                rows = [{"Event": str(r.get("id", "N/A")), "Severity": str(r.get("severity", "Normal")), "Risk": f"{r.get('risk_score', 'N/A')}/10", "Threat": str(r.get("threat", "Unclassified"))[:58]} for _, r in top.iterrows()]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=250)
    with lower[1]:
        with st.container(border=True):
            section_title(st, "SOC Health", "Readiness and evidence quality—not threat severity.")
            quality = data_quality_summary(df)
            progress_bar(st, _health_score(df, status), "CONSOLE READINESS")
            progress_bar(st, (quality["valid_timestamps"] / quality["records"] * 100) if quality["records"] else 0, "TIMESTAMP COMPLETENESS")
            mitre_mapped = 0
            if "mapped_technique" in df.columns:
                mitre_mapped = int((~df["mapped_technique"].astype(str).str.lower().str.startswith("not mapped")).sum())
            progress_bar(st, (mitre_mapped / len(df) * 100) if len(df) else 0, "MITRE MAPPING")
            status_badge(st, "AI ASSISTANT READY" if True else "AI OFF", "success")
    with lower[2]:
        with st.container(border=True):
            section_title(st, "Recent Activity", "Most recent persisted analyst/case actions and telemetry state changes.")
            events = audit_events(6)
            if events:
                for event in events[:6]:
                    st.caption(f"{event.get('at','--')}  //  {event.get('action','EVENT')}  //  {str(event.get('detail',''))[:80]}")
            else:
                st.caption(f"{status.get('message', 'Telemetry state not checked')}  //  {len(df):,} records loaded")


def render_ai_soc_assistant(df: pd.DataFrame, settings) -> None:
    """Global grounded assistant: deterministic locally, optional Groq enhancement when configured."""
    service = ChatbotService(settings.groq_api_key, settings.groq_model)
    cases = list_cases(250)
    prompts = [
        "Which are the suspicious events?",
        "Which alert has the highest risk?",
        "Why was the highest-risk alert flagged?",
        "Which MITRE techniques are mapped?",
        "Give me the current incident summary.",
        "What should the analyst investigate next?",
    ]
    with st.container(border=True):
        section_title(st, "AI SOC Assistant", "Ask questions about the current telemetry. Answers stay bounded by observed data; final status remains analyst-controlled.")
        status_badge(st, "GROQ LLM + GROUNDED SNAPSHOT" if service.available else "LOCAL GROUNDED MODE // WORKS WITHOUT API KEY", "success" if service.available else "info")
        left, right = st.columns([1.05, 1.95])
        with left:
            prompt_choice = st.selectbox("Quick questions", ["Custom question"] + prompts, key="dashboard_ai_prompt_choice")
        with right:
            custom = st.text_input("Ask SOC", placeholder="e.g. Mere system mein kaun-kaun se suspicious events hain?", key="dashboard_ai_question")
        question = custom.strip() if custom.strip() else ("" if prompt_choice == "Custom question" else prompt_choice)
        if st.button("Analyze Current Telemetry", type="primary", use_container_width=True, key="dashboard_ai_analyze"):
            if not question:
                st.warning("Choose a quick question or enter a custom question.")
            else:
                with st.spinner("$ soc_ai --grounded-current-telemetry ..."):
                    ask_dataset = getattr(service, "ask_dataset", None)
                    if callable(ask_dataset):
                        answer = ask_dataset(question, df, cases)
                    else:
                        st.warning("ChatbotService code is stale in this running process; using local grounded mode. Stop and restart Streamlit to load the updated service.")
                        answer = answer_dataset_question(question, df, cases)
                st.session_state["dashboard_ai_last_answer"] = answer
                st.session_state["dashboard_ai_last_question"] = question
        if st.session_state.get("dashboard_ai_last_answer"):
            st.markdown(f"**QUERY //** {html.escape(str(st.session_state.get('dashboard_ai_last_question','')))}")
            with st.container(border=True):
                section_title(st, "Grounded Answer", "Evidence-derived from the current loaded dataset.")
                st.markdown(st.session_state["dashboard_ai_last_answer"])
            handoff_col1, handoff_col2 = st.columns(2)
            with handoff_col1:
                if st.button("Open Investigation Workspace", use_container_width=True, key="dashboard_ai_open_investigation"):
                    detections = _detections(df)
                    if not detections.empty and "id" in detections.columns:
                        st.session_state["selected_alert_id"] = str(detections.iloc[0]["id"])
                    st.switch_page("pages/Investigation.py")
            with handoff_col2:
                st.caption("AI is advisory. Telemetry is authoritative. Final status remains analyst-controlled.")

def render_status_strip(settings, df, status) -> None:
    pipeline = "READY" if not df.empty else "WAITING"
    limit = status.get("limit", "—")
    lookback = status.get("lookback", "—")
    operational_strip(st, [
        ("DATA SOURCE", settings.data_source, "success" if settings.data_source == "MOCK" else "info"),
        ("ACTIVE EVENTS", f"{len(df):,}", "info"),
        ("PIPELINE", pipeline, "success" if not df.empty else "warning"),
        ("WAZUH PROFILE", f"{limit} / {lookback}" if settings.data_source == "WAZUH" else "N/A", "info"),
        ("SYSTEM", str(status.get("message", "Not checked")), _status_tone(status)),
    ])


def render_command_metrics(df: pd.DataFrame, status: dict) -> None:
    detections = _detections(df)
    severity = detections["severity"].value_counts() if "severity" in detections.columns else pd.Series(dtype="int64")
    section_title(st, "Threat Monitor", "Telemetry triage indicators. A detection or severity value is not proof of compromise.")
    metrics = [
        ("TOTAL EVENTS", len(df), "normal", "Normalized telemetry"),
        ("DETECTIONS", len(detections), "normal", "Non-normal records"),
        ("CRITICAL", int(severity.get("Critical", 0)), "critical", "Immediate review"),
        ("HIGH", int(severity.get("High", 0)), "high", "Priority queue"),
        ("MEDIUM", int(severity.get("Medium", 0)), "medium", "Review required"),
        ("LOW", int(severity.get("Low", 0)), "low", "Lower priority"),
    ]
    cols = st.columns(6)
    for col, item in zip(cols, metrics):
        with col:
            metric_card(st, item[0], f"{int(item[1]):,}", item[2], item[3])
    d = detections
    c1, c2, c3 = st.columns(3)
    with c1:
        risk = pd.to_numeric(d.get("risk_score", pd.Series(dtype=float)), errors="coerce").dropna()
        risk_value = float(risk.mean()) if not risk.empty else 0.0
        progress_bar(st, risk_value * 10, "AVERAGE DETECTION RISK", f"{risk_value:.1f}/10")
    with c2:
        conf = pd.to_numeric(d.get("confidence_score", pd.Series(dtype=float)), errors="coerce").dropna()
        conf_value = float(conf.mean() * 100) if not conf.empty else 0.0
        progress_bar(st, conf_value, "AVERAGE DETECTION CONFIDENCE", f"{conf_value:.0f}%")
    with c3:
        health = _health_score(df, status)
        progress_bar(st, health, "CONSOLE READINESS", f"{health}%")
    with st.expander("How the console-readiness score is calculated"):
        st.caption("Starts at 100. Observable deductions: source error −30; parser errors up to −20; normalizer errors up to −20; incomplete timestamps −10; missing core fields up to −10; duplicate events −5.")


def render_overview_charts(df: pd.DataFrame) -> None:
    row1 = st.columns(2)
    with row1[0]:
        with st.container(border=True): safe_chart(severity_donut(df), st, height=300, key="overview_severity")
    with row1[1]:
        with st.container(border=True): safe_chart(detection_bar(df), st, height=300, key="overview_detection")
    row2 = st.columns(2)
    with row2[0]:
        with st.container(border=True): safe_chart(alert_trend(df), st, height=300, key="overview_trend")
    with row2[1]:
        with st.container(border=True): safe_chart(risk_distribution(df), st, height=300, key="overview_risk")
    row3 = st.columns(2)
    with row3[0]:
        with st.container(border=True): safe_chart(risk_confidence_scatter(_detections(df)), st, height=330, key="overview_risk_conf")
    with row3[1]:
        with st.container(border=True): safe_chart(mitre_tactic_bar(df), st, height=330, key="overview_tactics")
    row4 = st.columns(2)
    with row4[0]:
        with st.container(border=True): safe_chart(top_techniques(df), st, height=300, key="overview_mitre")
    with row4[1]:
        with st.container(border=True): safe_chart(event_category_bar(df), st, height=300, key="overview_event_types")
    row5 = st.columns(2)
    with row5[0]:
        with st.container(border=True): safe_chart(confidence_breakdown(df), st, height=300, key="overview_confidence")
    with row5[1]:
        with st.container(border=True): safe_chart(source_distribution(df), st, height=300, key="overview_sources")


def render_latest_alert_feed(df: pd.DataFrame) -> None:
    section_title(st, "Live Event Stream", "DEMO STREAM // newest loaded detections first; no response action is executed automatically.")
    alerts = sort_alerts_newest_first(_detections(df)).head(10)
    if alerts.empty:
        st.info("No security detections are present in the current telemetry.")
        return
    rows = []
    for _, row in alerts.iterrows():
        ts = pd.to_datetime(row.get("timestamp"), utc=True, errors="coerce")
        rows.append({
            "time": ts.strftime("%H:%M:%S") if not pd.isna(ts) else "--:--:--",
            "severity": str(row.get("severity") or "Normal"),
            "threat": str(row.get("threat") or "Unclassified Event"),
            "meta": " // ".join([str(row.get("source") or "UNKNOWN"), str(row.get("hostname") or "HOST-NA"), f"RULE {row.get('rule_id') or 'NA'}"]),
        })
    st.markdown(alert_feed_html(rows), unsafe_allow_html=True)


def filter_alerts(df: pd.DataFrame, search: str = "", severity: str = "All", source: str = "All", mapped: str = "All", confirmation: str = "All") -> pd.DataFrame:
    view = df.copy()
    if search.strip():
        needle = search.strip().lower()
        view = view[view.astype(str).apply(lambda col: col.str.lower().str.contains(needle, regex=False, na=False)).any(axis=1)]
    if severity != "All" and "severity" in view.columns:
        view = view[view["severity"] == severity]
    if source != "All" and "source" in view.columns:
        view = view[view["source"] == source]
    if mapped != "All" and "mapped_technique" in view.columns:
        is_mapped = ~view["mapped_technique"].astype(str).str.lower().str.startswith("not mapped")
        view = view[is_mapped if mapped == "Mapped" else ~is_mapped]
    if confirmation != "All" and "confirmation_status" in view.columns:
        view = view[view["confirmation_status"] == confirmation]
    return sort_alerts_newest_first(view)


def _alert_label(row) -> str:
    return f"{row.get('id', 'unknown')}  |  {row.get('severity', 'Normal')}  |  {str(row.get('threat', 'Unclassified Event'))[:58]}"


def _launch_high_risk_demo(df: pd.DataFrame) -> None:
    detections = _detections(df).copy()
    if detections.empty:
        st.warning("No detections available for the demo scenario.")
        return
    risk = pd.to_numeric(detections.get("risk_score"), errors="coerce").fillna(0)
    severity_rank = detections.get("severity", pd.Series(index=detections.index, dtype=str)).map({"Critical": 4, "High": 3, "Medium": 2, "Low": 1}).fillna(0)
    pick = detections.assign(_rank=risk + severity_rank).sort_values("_rank", ascending=False).iloc[0]
    st.session_state["selected_alert_id"] = str(pick["id"])
    st.session_state["demo_launch"] = True
    st.switch_page("pages/Investigation.py")


def render_alert_queue(df: pd.DataFrame) -> None:
    section_title(st, "Alert Center", "Search → filter → paginate → select → open the evidence-first investigation workspace.")
    alerts = _detections(df)
    if alerts.empty:
        st.success("No security detections are present in the loaded telemetry.")
        return
    current_quick = st.session_state.get("dashboard_quick_filter", "All")
    qcols = st.columns(5)
    for col, sev in zip(qcols, ["All", "Critical", "High", "Medium", "Low"]):
        with col:
            if st.button(sev.upper(), use_container_width=True, key=f"quick_filter_{sev.lower()}"):
                st.session_state["dashboard_quick_filter"] = sev
                st.session_state["alert_center_page"] = 1
                st.rerun()
    f1, f2, f3, f4, f5 = st.columns([2.3, .85, .9, .9, .95])
    with f1: search = st.text_input("Search", placeholder="IP / host / rule / threat / command / filename...", key="alert_center_search")
    with f2: severity = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], index=["All", "Critical", "High", "Medium", "Low"].index(current_quick) if current_quick in ["All", "Critical", "High", "Medium", "Low"] else 0, key="alert_center_severity")
    with f3:
        sources = ["All"] + sorted([str(x) for x in alerts.get("source", pd.Series(dtype=str)).dropna().unique()])
        source = st.selectbox("Source", sources, key="alert_center_source")
    with f4: mapped = st.selectbox("MITRE", ["All", "Mapped", "Unmapped"], key="alert_center_mitre")
    with f5:
        statuses = ["All"] + sorted([str(x) for x in alerts.get("confirmation_status", pd.Series(dtype=str)).dropna().unique()])
        confirmation = st.selectbox("Status", statuses, key="alert_center_status")
    view = filter_alerts(alerts, search, severity, source, mapped, confirmation)
    st.caption(f"$ query returned {len(view):,} matching detections // newest first")
    if view.empty:
        st.info("No incidents match the active filters.")
        return
    page_view = _paginate(view, "alert_center", 25)
    choice_map = {str(row["id"]): row for _, row in page_view.iterrows()}
    ids = list(choice_map)
    previous = str(st.session_state.get("selected_alert_id", ""))
    selected = st.selectbox("SELECTED INCIDENT", ids, index=(ids.index(previous) if previous in ids else 0), format_func=lambda ident: _alert_label(choice_map[ident]), key="alert_center_selector")
    row = choice_map[selected]
    st.session_state["selected_alert_id"] = str(selected)
    with st.container(border=True):
        left, right = st.columns([3.3, 1])
        with left:
            st.markdown(f"### {html.escape(str(row.get('threat') or 'Unclassified Event'))}")
            st.caption(f"INCIDENT `{html.escape(str(selected))}` // CASE `{html.escape(str(row.get('case_id') or 'auto-created on investigation'))}` // SOURCE `{html.escape(str(row.get('source') or 'UNKNOWN'))}`")
        with right: status_badge(st, str(row.get("severity") or "NORMAL").upper(), _severity_tone(str(row.get("severity") or "Normal")))
        render_kv_cards(st, [
            ("RISK", _clean(f"{row.get('risk_score', 'NA')}/10")), ("CONFIDENCE", _clean(row.get("confidence_level"))),
            ("HOST", _clean(row.get("hostname"))), ("SOURCE IP", _clean(row.get("source_ip"))),
            ("MITRE", _clean(row.get("mapped_technique"))), ("RULE", _clean(f"{row.get('rule_id', 'NA')} / v{row.get('rule_version', '1.0')}")),
        ], columns=3)
        st.caption(html.escape(str(row.get("why_alert_fired") or row.get("detection_reason") or "Detection explanation unavailable.")))
        b1, b2 = st.columns(2)
        with b1:
            if st.button("Open Investigation Workspace", type="primary", use_container_width=True, key="alert_center_open"):
                st.switch_page("pages/Investigation.py")
        with b2:
            if st.button("Mark Ready for Review", use_container_width=True, key="alert_center_review"):
                st.session_state[f"review_requested_{selected}"] = True
                st.success("Review state queued for the investigation workspace.")
    table_cols = [c for c in ["id", "timestamp", "source", "hostname", "source_ip", "destination_ip", "rule_id", "rule_version", "severity", "risk_score", "confidence_level", "mapped_technique", "confirmation_status", "duplicate_status", "evidence_completeness_label"] if c in view.columns]
    display = view[table_cols].copy()
    if "mapped_technique" in display.columns:
        display["mapped_technique"] = display["mapped_technique"].astype(str).str[:22]
    st.dataframe(display, use_container_width=True, hide_index=True, height=430)


def render_telemetry_explorer(df: pd.DataFrame) -> None:
    section_title(st, "Telemetry Explorer", "Normalized contract first; raw evidence remains available without fabricating missing fields.")
    query = st.text_input("Telemetry search", placeholder="event id / host / IP / rule / threat / command...", key="telemetry_console_search")
    view = df.copy()
    if query.strip():
        needle = query.strip().lower()
        view = view[view.astype(str).apply(lambda col: col.str.lower().str.contains(needle, regex=False, na=False)).any(axis=1)]
    st.caption(f"$ normalized query -> {len(view):,} hits")
    page_view = _paginate(view, "telemetry_console", 50) if not view.empty else view
    cols = [c for c in ["id", "timestamp", "source", "hostname", "source_ip", "destination_ip", "username", "event_type", "rule_id", "threat", "final_detection", "severity", "risk_score", "confidence_level", "mapped_technique", "duplicate_status", "evidence_completeness_label"] if c in page_view.columns]
    st.dataframe(page_view[cols], use_container_width=True, hide_index=True, height=460)
    if page_view.empty or "id" not in page_view.columns:
        return
    record_ids = [str(x) for x in page_view["id"].tolist()]
    inspect_id = st.selectbox("Inspect Event", record_ids, key="telemetry_inspect_id")
    match = view[view["id"].astype(str) == inspect_id]
    if match.empty:
        return
    record = match.iloc[0].to_dict()
    c1, c2 = st.columns(2)
    with c1:
        with st.container(border=True):
            section_title(st, "Normalized Event")
            safe = {k: record.get(k) for k in ["id", "timestamp", "source", "hostname", "source_ip", "destination_ip", "username", "event_type", "rule_id", "rule_version", "threat", "severity", "risk_score", "confidence_level", "mapped_technique", "evidence_completeness_label", "event_fingerprint"] if k in record}
            st.code(safe_json(safe, max_chars=9000), language="json", wrap_lines=True)
    with c2:
        with st.container(border=True):
            section_title(st, "Raw Event (redacted)")
            st.code(safe_json(record.get("raw_event") or record.get("original_log"), max_chars=12000), language="json", wrap_lines=True)


def main() -> None:
    st.set_page_config(page_title="SOC L2 // Command Console", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    apply_theme(st)
    settings = load_settings()
    df = load_pipeline()
    status = get_data_source_status() or {}
    presentation_mode = render_sidebar(settings, status)
    page_header(st, "Security Operations Center", "monitor detections, inspect evidence, triage risk, map MITRE and hand decisions to the analyst")
    render_status_strip(settings, df, status)
    if df is None or df.empty:
        st.warning("NO TELEMETRY LOADED // open Ingestion Center and run MOCK ingestion or a configured live source.")
        terminal_box(st, ["status=WAITING_FOR_DATA", "next=OPEN_INGESTION_CENTER", "fallback=MOCK_DEMO_SOURCE"])
        footer(st)
        return
    detections = _detections(df)
    posture = "CRITICAL REVIEW" if "severity" in detections.columns and int((detections["severity"] == "Critical").sum()) else ("HIGH PRIORITY" if "severity" in detections.columns and int((detections["severity"] == "High").sum()) else ("MONITOR / TRIAGE" if not detections.empty else "NORMALIZED"))
    posture_tone = _severity_tone("Critical" if posture == "CRITICAL REVIEW" else "High" if posture == "HIGH PRIORITY" else "Medium" if posture == "MONITOR / TRIAGE" else "Low")
    command_matrix(st, posture, posture_tone, len(df), len(detections), settings.data_source, "READY")
    quality = data_quality_summary(df)
    with st.container(border=True):
        section_title(st, "SOC Command Matrix", "Operational state, evidence quality and analyst-control boundaries.")
        cols = st.columns(4)
        with cols[0]: metric_card(st, "SOURCE STATE", "ONLINE" if not status.get("error") else "DEGRADED", "success" if not status.get("error") else "warning", settings.data_source)
        with cols[1]: metric_card(st, "EVIDENCE QUALITY", f"{round(quality['valid_timestamps'] / quality['records'] * 100) if quality['records'] else 0}%", "success", "timestamp completeness")
        with cols[2]: metric_card(st, "CASE CONTROL", "HUMAN", "normal", "analyst decision required")
        with cols[3]: metric_card(st, "AUTO RESPONSE", "DISABLED", "success", "no autonomous actions")
    render_global_search(df)
    render_soc_snapshot(df, status)
    render_ai_soc_assistant(df, settings)
    render_command_metrics(df, status)
    with st.container(border=True):
        data_quality_cards(st, quality)
    demo_col1, demo_col2, demo_col3 = st.columns([1.5, 1.1, 3])
    with demo_col1:
        if st.button("⚡ LAUNCH HIGH-RISK DEMO", type="primary", use_container_width=True, key="dashboard_high_risk_demo"):
            _launch_high_risk_demo(df)
    with demo_col2:
        if st.button("OPEN INVESTIGATION", use_container_width=True, key="dashboard_open_investigation"):
            if not detections.empty:
                st.session_state["selected_alert_id"] = str(detections.iloc[0]["id"])
            st.switch_page("pages/Investigation.py")
    with demo_col3:
        st.caption("Presentation flow: Dashboard → Alert → Evidence → Risk → MITRE → AI → Analyst Decision → Report.")
    tabs = st.tabs(["OVERVIEW", "ALERT CENTER", "TELEMETRY"])
    with tabs[0]:
        render_overview_charts(df)
        render_latest_alert_feed(df)
        if not presentation_mode:
            with st.container(border=True):
                section_title(st, "Operator Console", "The project keeps source evidence, rule detection and human confirmation separate.")
                terminal_box(st, ["01  OPEN ALERT CENTER", "02  SELECT INCIDENT", "03  OPEN INVESTIGATION", "04  INSPECT EVIDENCE + CORRELATION", "05  REQUEST OPTIONAL AI ASSISTANCE", "06  RECORD HUMAN DECISION", "07  EXPORT REPORT / INCIDENT PACKAGE"])
    with tabs[1]: render_alert_queue(df)
    with tabs[2]: render_telemetry_explorer(df)
    footer(st)


if __name__ == "__main__":
    main()
