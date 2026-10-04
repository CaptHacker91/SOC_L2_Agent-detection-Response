"""SOC L2 Agent - main Streamlit dashboard.

Dashboard responsibilities:
1. Show the configured data source and ingestion status.
2. Present explainable detection, severity, risk and confidence metrics.
3. Provide stable incident selection and Investigation navigation.
4. Keep the dashboard presentation layer separate from detection logic.

See ``CODE_MAP.md`` for professor-friendly navigation to every major module.
"""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Main Streamlit dashboard ko run/render karta hai aur user-facing SOC workflow ko assemble karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import pandas as pd
import streamlit as st

from core.config import load_settings
from core.pipeline import (
    DEFAULT_LIMIT,
    DEFAULT_LOOKBACK,
    LOOKBACK_OPTIONS,
    get_data_source_status,
    load_pipeline,
    refresh_data,
    run_connection_test,
)
from core.ui import apply_theme, page_header, section_title, show_pipeline
from core.visualization import alert_trend, detection_bar, safe_chart, severity_donut, top_techniques



# FUNCTION: _load_status
# Purpose: Ye internal helper load status operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _load_status() -> dict:
    """Return the last pipeline status or an empty status object."""
    return get_data_source_status() or {}


# FUNCTION: render_sidebar
# Purpose: Ye function render sidebar operation handle karta hai.
# Input: settings, status.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def render_sidebar(settings, status) -> None:
    """Render stable navigation and source actions shared by the main dashboard."""
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.sidebar:
        st.markdown("## SOC L2 Agent")
        st.caption("College demo control panel")
        st.write(f"**Configured source:** `{settings.data_source}`")

        # Wazuh-specific controls sidebar me rakhe gaye hain taaki main workspace clean aur focused rahe.
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if settings.data_source == "WAZUH":
            st.number_input(
                "Alerts to fetch", min_value=10, max_value=1000, value=DEFAULT_LIMIT,
                step=10, key="wazuh_limit",
            )
            st.selectbox(
                "Lookback window", LOOKBACK_OPTIONS,
                index=LOOKBACK_OPTIONS.index(DEFAULT_LOOKBACK), key="wazuh_lookback",
            )
        # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
        elif settings.data_source == "MOCK":
            st.success("MOCK / DEMO DATA", icon="✅")
        else:
            st.info("SPLUNK / LIVE SOURCE", icon="🔌")

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if status.get("connected"):
            st.success(status.get("message", "Ready"), icon="✅")
        # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
        elif status.get("message") not in {None, "Not checked"}:
            st.warning(status.get("message", "Unavailable"), icon="⚠️")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if status.get("error"):
            st.caption(f"Reason: {status['error']}")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if status.get("kept_previous"):
            st.caption("Previous verified dataset remains visible.")

        st.divider()
        st.markdown("### Actions")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if st.button("Refresh & Ingest", use_container_width=True, type="primary", key="sidebar_refresh"):
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with st.spinner("Running the SOC ingestion pipeline..."):
                refresh_data()
            st.rerun()

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if st.button("Test Connection", use_container_width=True, key="sidebar_test_connection"):
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with st.spinner("Testing the configured source..."):
                run_connection_test()
            st.rerun()

        st.divider()
        st.markdown("### Navigation")
        st.page_link("app.py", label="Dashboard", icon="📊")
        st.page_link("pages/Ingestion.py", label="Ingestion Center", icon="📥")
        st.page_link("pages/Investigation.py", label="Investigation", icon="🔎")


# FUNCTION: render_status_strip
# Purpose: Ye function render status strip operation handle karta hai.
# Input: settings, df, status.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def render_status_strip(settings, df, status) -> None:
    """Show the source, event count and latest state in one compact status row."""
    cols = st.columns(3)
    cols[0].metric("Data Source", settings.data_source)
    cols[1].metric("Loaded Events", len(df))
    cols[2].metric("Pipeline Status", status.get("message", "Ready"))


# FUNCTION: render_kpis
# Purpose: Ye function render kpis operation handle karta hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def render_kpis(df) -> None:
    """Render detection counts with a compact two-row layout that is easier on phones."""
    total = len(df)
    detections = df[df["final_detection"] != "Normal"] if "final_detection" in df.columns else df.iloc[0:0]
    severity = detections["severity"].value_counts() if "severity" in detections.columns else pd.Series(dtype="int64")
    values = [
        ("Total Events", total),
        ("Detections", len(detections)),
        ("Critical", int(severity.get("Critical", 0))),
        ("High", int(severity.get("High", 0))),
        ("Medium", int(severity.get("Medium", 0))),
        ("Low", int(severity.get("Low", 0))),
    ]
    st.markdown("### Detection Summary")
    first = st.columns(3)
    second = st.columns(3)
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for col, (label, val) in zip(first, values[:3]):
        col.metric(label, val)
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for col, (label, val) in zip(second, values[3:]):
        col.metric(label, val)


# FUNCTION: render_overview_charts
# Purpose: Ye function render overview charts operation handle karta hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def render_overview_charts(df) -> None:
    """Render the four explainable charts with stable sizes and readable labels."""
    section_title(st, "Security Overview", "Visual summary of the currently loaded telemetry.")
    c1, c2 = st.columns(2)
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with c1:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            safe_chart(severity_donut(df), st, height=300, key="severity_donut_chart")
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with c2:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            safe_chart(detection_bar(df), st, height=300, key="detection_bar_chart")
    c3, c4 = st.columns(2)
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with c3:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            safe_chart(top_techniques(df), st, height=300, key="mitre_chart")
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with c4:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            safe_chart(alert_trend(df), st, height=300, key="trend_chart")


# FUNCTION: _alert_label
# Purpose: Ye internal helper ka main kaam alert label se related processing ko centrally handle karna hai.
# Input: row.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _alert_label(row) -> str:
    """Build a compact incident selector label without creating many dynamic buttons."""
    ident = str(row.get("id") or "unknown")
    threat = str(row.get("threat") or "Unclassified Event")[:64]
    sev = str(row.get("severity") or "Normal")
    return f"{ident}  •  {sev}  •  {threat}"


# FUNCTION: render_alert_queue
# Purpose: Ye function render alert queue operation handle karta hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def render_alert_queue(df) -> None:
    """Render searchable incidents and a single stable Investigation action."""
    section_title(st, "Alert Queue", "Select one incident to inspect the full evidence and investigation workflow.")
    alerts = df[df["final_detection"] != "Normal"].copy() if "final_detection" in df.columns else df.iloc[0:0].copy()
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if alerts.empty:
        st.success("No security detections are present in the loaded telemetry.")
        return

    f1, f2 = st.columns([2, 1])
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with f1:
        search = st.text_input(
            "Search incidents", placeholder="Threat, IP, host, rule ID, command...", key="alert_search",
        )
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with f2:
        sev = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"], key="alert_severity_filter")

    view = alerts
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if search.strip():
        needle = search.strip().lower()
        mask = view.astype(str).apply(lambda col: col.str.lower().str.contains(needle, regex=False, na=False)).any(axis=1)
        view = view[mask]
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if sev != "All":
        view = view[view["severity"] == sev]

    st.caption(f"Showing {len(view)} of {len(alerts)} detections.")
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if view.empty:
        st.info("No incidents match the current filters.")
        return

    # Stable selectbox + action button use kiye gaye hain taaki filtering ke baad per-row buttons fragile na ho.
    choice_map = {str(row["id"]): row for _, row in view.head(100).iterrows()}
    ids = list(choice_map)
    previous = str(st.session_state.get("selected_alert_id", ""))
    default_index = ids.index(previous) if previous in ids else 0
    selected_id = st.selectbox(
        "Selected incident", ids, index=default_index,
        format_func=lambda item: _alert_label(choice_map[item]), key="alert_selector",
    )
    row = choice_map[selected_id]
    st.session_state["selected_alert_id"] = str(selected_id)

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.container(border=True):
        detail = pd.DataFrame(
            [
                ["Threat", row.get("threat")],
                ["Severity", row.get("severity")],
                ["Risk", f"{row.get('risk_score', 'NA')}/10"],
                ["Confidence", row.get("confidence_level")],
                ["Confirmation", row.get("confirmation_status")],
                ["Host", row.get("hostname")],
                ["Source IP", row.get("source_ip")],
                ["MITRE", row.get("mapped_technique")],
            ],
            columns=["Field", "Value"],
        )
        st.dataframe(detail, use_container_width=True, hide_index=True, height=315)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if st.button(
            "Open Investigation",
            type="primary",
            use_container_width=True,
            key="open_investigation",
        ):
            st.switch_page("pages/Investigation.py")

    table_cols = [
        c for c in [
            "id", "timestamp", "source", "hostname", "source_ip", "destination_ip", "rule_id",
            "severity", "risk_score", "confidence_level", "confirmation_status", "mapped_technique",
        ] if c in view.columns
    ]
    st.dataframe(view[table_cols].head(60), use_container_width=True, hide_index=True, height=420)


# FUNCTION: render_all_telemetry
# Purpose: Ye function render all telemetry operation handle karta hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def render_all_telemetry(df) -> None:
    """Render normalized telemetry with only the columns useful during a demo."""
    section_title(st, "Telemetry Explorer", "This is the normalized event contract used by downstream SOC stages.")
    cols = [
        c for c in [
            "id", "timestamp", "source", "hostname", "agent_ip", "source_ip", "destination_ip",
            "username", "event_type", "rule_id", "rule_level", "rule_groups", "threat", "final_detection",
            "severity", "risk_score", "confidence_level", "confirmation_status", "mapped_technique",
        ] if c in df.columns
    ]
    st.dataframe(df[cols], use_container_width=True, hide_index=True, height=560)


# FUNCTION: main
# Purpose: Ye function ka main kaam main se related processing ko centrally handle karna hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def main() -> None:
    """Assemble the dashboard from source status, KPIs, charts and the alert workflow."""
    st.set_page_config(page_title="SOC L2 Agent", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
    apply_theme(st)

    settings = load_settings()
    df = load_pipeline()
    status = _load_status()
    page_header(st, "SOC L2 Agent", "Detection • Triage • MITRE Enrichment • Investigation")
    render_sidebar(settings, status)
    render_status_strip(settings, df, status)
    show_pipeline(st)

    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if df.empty:
        st.warning("No telemetry is loaded. Open Ingestion Center and run the configured source, or use MOCK mode for the demo.")
        return

    render_kpis(df)
    tabs = st.tabs(["Overview", "Alerts", "Telemetry"])
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[0]:
        render_overview_charts(df)
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            st.markdown("**Demo path:** Overview → Alerts → select an incident → Open Investigation → Evidence → PDF / optional AI")
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[1]:
        render_alert_queue(df)
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[2]:
        render_all_telemetry(df)


if __name__ == "__main__":
    main()
