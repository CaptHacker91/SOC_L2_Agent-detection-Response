"""SOC ingestion control room for deterministic MOCK and optional Wazuh/Splunk sources."""
from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from core.config import load_settings
from core.pipeline import DEFAULT_LIMIT, DEFAULT_LOOKBACK, LOOKBACK_OPTIONS, get_data_source_status, get_wazuh_controls, load_pipeline, refresh_data, run_connection_test
from core.telemetry_quality import data_quality_summary
from core.ui import apply_theme, data_quality_cards, footer, metric_card, mini_field, nav_brand, navigation_links, operational_strip, page_header, progress_bar, section_title, show_pipeline, status_badge, terminal_box


def _status_tone(status: dict) -> str:
    if status.get("error"):
        return "error"
    if status.get("connected"):
        return "success"
    if status.get("message") not in {None, "Not checked"}:
        return "warning"
    return "info"


def main() -> None:
    st.set_page_config(page_title="Ingestion // SOC L2", page_icon="📥", layout="wide")
    apply_theme(st)
    settings = load_settings()
    df = load_pipeline()
    status = get_data_source_status() or {}
    with st.sidebar:
        nav_brand(st, "source health + ingestion control", "INGESTION CENTER", "info")
        navigation_links(st)
        if settings.data_source == "WAZUH":
            limit, lookback = get_wazuh_controls()
            st.number_input("Alerts to fetch", min_value=10, max_value=1000, value=limit, step=10, key="wazuh_limit")
            st.selectbox("Lookback", LOOKBACK_OPTIONS, index=LOOKBACK_OPTIONS.index(lookback), key="wazuh_lookback")
        st.caption("MOCK is deterministic. Live-provider states are shown only when actually verified.")
    page_header(st, "Ingestion Control Room", "probe source health, configure fetch profile, run the common pipeline and inspect reconciliation")
    operational_strip(st, [("CONFIGURED", settings.data_source, "success" if settings.data_source == "MOCK" else "info"), ("EVENTS", f"{len(df):,}", "info"), ("BATCH", status.get("batch_id", "N/A"), "info"), ("PIPELINE", "READY" if not df.empty else "WAITING", "success" if not df.empty else "warning")])
    with st.container(border=True):
        section_title(st, "Source Configuration", "Only non-secret configuration is surfaced here.")
        left, right = st.columns([1.5, 1])
        with left:
            mini_field(st, "Configured source", html.escape(str(settings.data_source)))
            if settings.data_source == "MOCK":
                mini_field(st, "Dataset", html.escape(str(settings.mock_data_path)))
                status_badge(st, "MOCK / DETERMINISTIC DEMO", "success")
            elif settings.data_source == "WAZUH":
                limit, lookback = get_wazuh_controls()
                mini_field(st, "Alerts to fetch", limit)
                mini_field(st, "Lookback", lookback)
                mini_field(st, "TLS verification", settings.wazuh_verify_ssl)
            else:
                mini_field(st, "Splunk host", settings.splunk_host or "Not configured")
                mini_field(st, "Search query", settings.splunk_search_query or "Not configured")
        with right:
            metric_card(st, "CURRENT RECORDS", f"{len(df):,}", "normal", "analyzed telemetry")
            if st.button("Run Ingestion", type="primary", use_container_width=True, key="ingestion_run_final"):
                with st.spinner("$ ingest -> parse -> normalize -> detect -> triage ..."):
                    refresh_data()
                st.rerun()
            if st.button("Test Source", use_container_width=True, key="ingestion_test_final"):
                with st.spinner("$ probe source connection ..."):
                    run_connection_test()
                st.rerun()
    with st.container(border=True):
        section_title(st, "Source Health", "Connection outcomes are displayed honestly; failed providers never become fake success.")
        a, b, c, d = st.columns(4)
        with a: status_badge(st, "CONNECTED" if status.get("connected") else "NOT VERIFIED", _status_tone(status))
        with b: mini_field(st, "Last message", html.escape(str(status.get("message", "Not checked"))))
        with c: mini_field(st, "Duration", f"{status.get('duration_ms', 'N/A')} ms")
        with d: mini_field(st, "Last checked", html.escape(str(status.get("checked_at", "Not checked"))))
        if status.get("error"): st.warning(f"Source issue: {status['error']}" if status.get("kept_previous") else f"Source issue: {status['error']}")
        if status.get("processing_stages"):
            stage_df = pd.DataFrame([{"Stage": k.upper(), "State": v} for k, v in status["processing_stages"].items()])
            st.dataframe(stage_df, use_container_width=True, hide_index=True, height=230)
    with st.container(border=True):
        section_title(st, "Event Reconciliation", "A simple end-to-end count contract makes ingestion failures visible.")
        def _stage_count(key: str, fallback: int | str = "N/A"):
            value = status.get(key)
            return fallback if value is None else value

        counts = [
            ("FETCHED", _stage_count("fetched_count", len(df) if settings.data_source == "MOCK" else "N/A")),
            ("PARSED", _stage_count("parsed_count", len(df) if settings.data_source == "MOCK" else "N/A")),
            ("NORMALIZED", _stage_count("normalized_count", len(df))),
            ("ANALYZED", _stage_count("analyzed_count", len(df))),
            ("DISPLAYED", len(df)),
        ]
        cols = st.columns(5)
        for col, (label, value) in zip(cols, counts):
            with col: metric_card(st, label, value, "success" if value not in {"N/A", None} else "info", "stage count")
        if settings.data_source == "WAZUH":
            limit, lookback = get_wazuh_controls()
            terminal_box(st, [f"wazuh.limit={limit}", f"wazuh.lookback={lookback}", f"batch={status.get('batch_id', 'N/A')}"])
    with st.container(border=True):
        section_title(st, "Data Quality", "Parser and normalizer warnings remain inspectable without blocking valid telemetry.")
        data_quality_cards(st, data_quality_summary(df))
    with st.container(border=True):
        section_title(st, "Ingestion Pipeline")
        show_pipeline(st)
        if not df.empty: progress_bar(st, 100, "PIPELINE COMPLETENESS", "READY")
    with st.container(border=True):
        section_title(st, "Normalized Preview", "Common fields after parsing, normalization, detection and triage.")
        if df.empty:
            st.info("No telemetry loaded yet.")
            terminal_box(st, ["status=WAITING", "action=RUN_INGESTION", "recommended=MOCK_FOR_DEMO"])
        else:
            cols = [c for c in ["id", "timestamp", "source", "hostname", "rule_id", "rule_version", "threat", "final_detection", "severity", "risk_score", "confidence_level", "mapped_technique", "event_fingerprint", "evidence_completeness_label"] if c in df.columns]
            st.dataframe(df[cols].head(30), use_container_width=True, hide_index=True, height=430)
    footer(st, "SOC_L2 // INGESTION CONTROL ROOM // SOURCE HONESTY // EVIDENCE FIRST")

if __name__ == "__main__":
    main()
