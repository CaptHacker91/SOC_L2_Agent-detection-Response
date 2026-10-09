"""Persistent audit console for analyst actions and case lifecycle history."""
from __future__ import annotations

import streamlit as st

from core.ui import apply_theme, footer, metric_card, nav_brand, navigation_links, operational_strip, page_header, section_title
from services.case_store import audit_events, case_metrics


def main() -> None:
    st.set_page_config(page_title="Audit Log // SOC L2", page_icon="📜", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "append-only analyst activity trail", "AUDIT CONSOLE", "info")
        navigation_links(st)
    page_header(st, "Audit Console", "review persisted analyst actions, case updates and decision history")
    metrics = case_metrics()
    operational_strip(st, [("CASES", metrics["total"], "info"), ("ASSIGNED", metrics["assigned"], "info"), ("REVIEWED", metrics["reviewed"], "success"), ("CLOSED", metrics["closed"], "success")])
    outcome_cols = st.columns(4)
    with outcome_cols[0]: metric_card(st, "TRUE POSITIVE", metrics.get("true_positive", 0), "high", "persisted decisions")
    with outcome_cols[1]: metric_card(st, "FALSE POSITIVE", metrics.get("false_positive", 0), "warning", "persisted decisions")
    with outcome_cols[2]: metric_card(st, "NEEDS INVESTIGATION", metrics.get("needs_investigation", 0), "info", "persisted decisions")
    with outcome_cols[3]: metric_card(st, "BENIGN", metrics.get("benign", 0), "success", "persisted decisions")
    events = audit_events(500)
    action_filter = st.selectbox("Filter action", ["ALL"] + sorted({str(e.get("action")) for e in events if e.get("action")}), key="audit_action_filter")
    case_filter = st.text_input("Filter incident/case", placeholder="Incident ID or CASE-SOC-", key="audit_case_filter")
    if action_filter != "ALL":
        events = [e for e in events if str(e.get("action")) == action_filter]
    if case_filter.strip():
        q = case_filter.strip().lower()
        events = [e for e in events if q in str(e.get("incident_id", "")).lower() or q in str(e.get("case_id", "")).lower()]
    c1, c2 = st.columns(2)
    with c1: metric_card(st, "AUDIT EVENTS", f"{len(events):,}", "info", "persistent local store")
    with c2: metric_card(st, "AUDIT MODE", "APPEND-ONLY", "success", "records are not overwritten by UI refresh")
    with st.container(border=True):
        section_title(st, "Activity Stream")
        if events:
            st.dataframe(events, use_container_width=True, hide_index=True, height=600)
        else:
            st.info("No persistent analyst actions have been recorded yet.")
    with st.expander("Audit boundary"):
        st.caption("This is a local application audit store for the prototype. It is not a replacement for an enterprise SIEM/SOAR audit pipeline.")
    footer(st, "SOC_L2 // AUDIT CONSOLE // LOCAL PERSISTENCE")

if __name__ == "__main__":
    main()
