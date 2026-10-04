"""Ingestion Center - source testing, loading and pipeline preview."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Data source testing, loading aur pipeline preview ka Streamlit page provide karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

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
from core.ui import apply_theme, page_header, section_title


# FUNCTION: _render_sidebar
# Purpose: Ye internal helper render sidebar operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _render_sidebar() -> None:
    """Render navigation links for the ingestion page."""
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.sidebar:
        st.markdown("## Navigation")
        st.page_link("app.py", label="Dashboard", icon="📊")
        st.page_link("pages/Ingestion.py", label="Ingestion Center", icon="📥")
        st.page_link("pages/Investigation.py", label="Investigation", icon="🔎")


# FUNCTION: main
# Purpose: Ye function ka main kaam main se related processing ko centrally handle karna hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def main() -> None:
    """Show source configuration, test/load actions and a safe pipeline preview."""
    st.set_page_config(page_title="Ingestion | SOC L2 Agent", page_icon="📥", layout="wide")
    apply_theme(st)
    settings = load_settings()
    status = get_data_source_status() or {}
    df = load_pipeline()

    page_header(st, "Ingestion Center", "Source readiness • connection testing • parsing • normalization • detection")
    _render_sidebar()

    summary = st.columns(3)
    summary[0].metric("Configured Source", settings.data_source)
    summary[1].metric("Loaded Events", len(df))
    summary[2].metric("Current Status", status.get("message", "Not checked"))

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.container(border=True):
        section_title(st, "1. Source Controls", "Use MOCK for the college demo; Wazuh and Splunk use values from .env.")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if settings.data_source == "MOCK":
            st.info(f"MOCK reads local telemetry from `{settings.mock_data_path}`.")
        # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
        elif settings.data_source == "WAZUH":
            c1, c2 = st.columns(2)
            c1.number_input("Alerts to fetch", min_value=10, max_value=1000, value=DEFAULT_LIMIT, step=10, key="wazuh_limit")
            c2.selectbox("Lookback window", LOOKBACK_OPTIONS, index=LOOKBACK_OPTIONS.index(DEFAULT_LOOKBACK), key="wazuh_lookback")
            st.caption("Wazuh Server API + Indexer credentials and TLS verification are read from .env.")
        else:
            st.info("Splunk credentials, token and search query are read from .env.")

        c_load, c_test = st.columns(2)
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with c_load:
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if st.button("Run Ingestion", type="primary", use_container_width=True, key="ingestion_run"):
                # Resource/context ko safely open karke operation complete kiya ja raha hai.
                with st.spinner("Loading → parsing → normalizing → detecting → enriching..."):
                    refresh_data()
                st.rerun()
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with c_test:
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if st.button("Test Source Connection", use_container_width=True, key="ingestion_test"):
                # Resource/context ko safely open karke operation complete kiya ja raha hai.
                with st.spinner("Testing the configured source..."):
                    run_connection_test()
                st.rerun()

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.container(border=True):
        section_title(st, "2. Latest Ingestion Status")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if status.get("connected"):
            st.success(status.get("message", "Connected"))
        # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
        elif status.get("message") and status.get("message") != "Not checked":
            st.warning(status.get("message", "Unavailable"))
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if status.get("error"):
            st.error(status.get("error"))
        details = status.get("details", [])
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if details:
            st.write("**Checks:**")
            # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
            for detail in details:
                st.write(f"- {detail}")
        warnings = status.get("processing_warnings", [])
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if warnings:
            st.warning(f"{len(warnings)} processing warning(s) were recorded. The remaining valid events are still usable.")
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with st.expander("View processing warnings"):
                # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
                for warning in warnings:
                    st.code(warning)

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.container(border=True):
        section_title(st, "3. Pipeline Preview", "The same normalized pipeline is used for MOCK, Wazuh and Splunk.")
        st.caption("Data Source → Parser → Normalizer → Detection → Severity / Risk → MITRE → Investigation")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if df.empty:
            st.info("No telemetry loaded yet.")
        else:
            cols = [
                c for c in ["id", "timestamp", "source", "hostname", "rule_id", "threat", "final_detection", "severity", "risk_score", "mapped_technique"]
                if c in df.columns
            ]
            st.dataframe(df[cols].head(20), use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
