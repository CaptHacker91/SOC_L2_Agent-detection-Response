"""
SOC L2 Agent — Dashboard.

Pipeline: Wazuh (Indexer alerts) -> WazuhService (normalized events) ->
Parser -> Normalizer -> DetectionEngine -> MitreMapper -> SeverityEngine ->
AlertTriangle.

Alerts are fetched from Wazuh on first load and whenever "Fetch Latest
Alerts" is clicked in the sidebar; the analysed result is kept in
st.session_state (see core/pipeline.py). If Wazuh is unreachable the
dashboard still renders, with a clear "Wazuh Connection Failed" message.
"""

import html

import streamlit as st
from dotenv import load_dotenv

from core.pipeline import (
    DEFAULT_LIMIT, DEFAULT_LOOKBACK, LOOKBACK_OPTIONS,
    get_wazuh_status, load_pipeline, refresh_alerts, run_connection_test,
)

load_dotenv(override=True)

st.set_page_config(page_title="SOC L2 Agent", page_icon="🛡️", layout="wide")

CSS = """
<style>
:root{ --olive:olivedrab; --olive-dark:#4f6428; --brown:saddlebrown;
       --bg:#eee8dc; --paper:#fffdf8; --dark:#2f3e2f; }
.stApp{ background:var(--bg); }
.header-box{ background:linear-gradient(135deg,#4f6428 0%,olivedrab 48%,saddlebrown 100%);
       color:white; padding:26px; border-radius:16px; text-align:center; margin-bottom:20px; }
.kpi-card{ background:var(--paper); padding:18px; border-radius:14px; text-align:center;
       box-shadow:0 4px 12px rgba(65,50,35,.12); border-top:5px solid var(--olive); }
.kpi-card h2{ margin:4px 0 0; font-size:30px; font-weight:800; color:var(--olive-dark); }
.kpi-card p{ margin:0; font-size:12px; font-weight:700; color:var(--brown); letter-spacing:.03em; }
.alert-card{ background:var(--paper); padding:16px 18px; border-radius:12px; margin-bottom:10px;
       border-left:6px solid var(--olive); box-shadow:0 2px 8px rgba(65,50,35,.08); }
.badge{ padding:3px 10px; border-radius:20px; font-size:11px; font-weight:700; }
.sev-Critical{ background:#fde2e2; color:#a12a2a; }
.sev-High{ background:#fde9d0; color:#a15c1c; }
.sev-Medium{ background:#f5efce; color:#8a7a1c; }
.sev-Low{ background:#e4efd4; color:#4f6428; }
.sev-Normal{ background:#e9e9e9; color:#555; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


def render_header():
    st.markdown(
        '<div class="header-box"><h1>🛡️ SOC L2 Agent</h1>'
        '<p>Blue Team Defence Intelligence Dashboard · SOC L2 AI Investigation Platform</p></div>',
        unsafe_allow_html=True,
    )


def esc(value):
    """HTML-escape telemetry before it goes into unsafe_allow_html markup (log data is attacker-controlled)."""
    return "" if value is None else html.escape(str(value))


def render_wazuh_sidebar():
    status = get_wazuh_status() or {}
    with st.sidebar:
        st.markdown("### 🔌 Wazuh SIEM")

        if status.get("connected"):
            st.success("✅ Wazuh Connected")
            note = f"Server API {status['api_version']} · " if status.get("api_version") else ""
            if status.get("count") is not None:
                note += f"{status['count']} alerts fetched (last {status.get('lookback')}) · "
            st.caption(note + f"checked {status.get('checked_at', '')}")
        elif status:
            st.error("❌ Wazuh Connection Failed")

        if status.get("error"):
            st.caption(f"⚠️ {status['error']}")
        if status.get("kept_previous"):
            st.caption("Showing the last successfully fetched alerts.")

        st.number_input("Alerts to fetch", min_value=10, max_value=1000, value=DEFAULT_LIMIT,
                        step=10, key="wazuh_limit")
        st.selectbox("Lookback window", LOOKBACK_OPTIONS,
                     index=LOOKBACK_OPTIONS.index(DEFAULT_LOOKBACK), key="wazuh_lookback")
        st.button("🔄 Fetch Latest Alerts", on_click=refresh_alerts, use_container_width=True)
        st.button("Test Connection", on_click=run_connection_test, use_container_width=True)


def render_kpis(df):
    total = len(df)
    alerts_df = df[df["final_detection"] != "Normal"]
    security_alerts = len(alerts_df)
    counts = alerts_df["severity"].value_counts()

    cols = st.columns(6)
    kpis = [
        ("Total Events", total),
        ("Security Alerts", security_alerts),
        ("Critical", int(counts.get("Critical", 0))),
        ("High", int(counts.get("High", 0))),
        ("Medium", int(counts.get("Medium", 0))),
        ("Low", int(counts.get("Low", 0))),
    ]
    for col, (label, value) in zip(cols, kpis):
        with col:
            st.markdown(f'<div class="kpi-card"><h2>{value}</h2><p>{label}</p></div>', unsafe_allow_html=True)


def render_alert_card(row, position):
    """
    position: the row's position within THIS render pass (from
    enumerate() in the caller). Used as part of the widget key so it
    is guaranteed unique even if two rows somehow share the same
    'id' value — never rely on data content alone for a Streamlit key.
    """
    sev = row.get("severity", "Low")
    with st.container():
        st.markdown(
            f"""<div class="alert-card">
                <span class="badge sev-{esc(sev)}">{esc(sev)}</span>
                &nbsp;<b>{esc(row.get('threat'))}</b>
                &nbsp;<span style="color:#888;font-size:12px">{esc(row.get('event_time'))}</span>
                <div style="font-size:13px;color:#555;margin-top:6px">{esc(row.get('detection_reason'))}</div>
                </div>""",
            unsafe_allow_html=True,
        )
        c1, c2 = st.columns([1, 5])
        with c1:
            if st.button("Investigate", key=f"inv_{position}_{row.get('id')}"):
                st.session_state["selected_alert_id"] = str(row.get("id"))
                st.switch_page("pages/Investigation.py")


def main():
    render_header()
    df = load_pipeline()
    render_wazuh_sidebar()

    if df.empty:
        status = get_wazuh_status() or {}
        if status.get("connected") and not status.get("error"):
            st.info(f"Wazuh is connected but returned no alerts for the last {status.get('lookback')}. "
                    "Try a longer lookback window in the sidebar, then click Fetch Latest Alerts.")
        else:
            st.error("No alerts loaded — Wazuh connection failed. See the sidebar for details and "
                     "check the WAZUH_* settings in your .env file.")
        return

    render_kpis(df)

    tab_alerts, tab_all = st.tabs(["🚨 Alert Queue", "📋 All Telemetry"])

    with tab_alerts:
        alerts_df = df[df["final_detection"] != "Normal"].reset_index(drop=True)

        c1, c2 = st.columns([3, 1])
        with c1:
            search = st.text_input("🔍 Search threat, IP, host, rule ID, URI…", "")
        with c2:
            sev_filter = st.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])

        view = alerts_df
        if search:
            s = search.lower()
            mask = view.apply(
                lambda r: s in str(r.get("threat", "")).lower()
                or s in str(r.get("source_ip", "")).lower()
                or s in str(r.get("hostname", "")).lower()
                or s in str(r.get("url", "")).lower()
                or s in str(r.get("rule_id", "")).lower(),
                axis=1,
            )
            view = view[mask]
        if sev_filter != "All":
            view = view[view["severity"] == sev_filter]

        st.caption(f"Showing {len(view)} of {len(alerts_df)} security alerts ({total_events_note(df)}).")
        for position, (_, row) in enumerate(view.iterrows()):
            render_alert_card(row, position)

    with tab_all:
        st.caption(f"Full source dataset — {len(df)} total events, including Normal telemetry.")
        display_cols = [c for c in [
            "id", "event_time", "hostname", "source_ip", "username", "rule_id", "rule_level",
            "http_method", "http_status", "uri_path", "url", "threat", "mapped_technique",
            "severity", "risk_score", "final_detection",
        ] if c in df.columns]
        st.dataframe(df[display_cols], use_container_width=True, height=500)


def total_events_note(df):
    return f"{len(df)} total events in source dataset"


if __name__ == "__main__":
    main()
