"""SOC analytics wall: trends, risk, confidence, quality and rule coverage."""
from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from core.pipeline import get_data_source_status, load_pipeline
from core.telemetry_quality import data_quality_summary
from core.ui import apply_theme, command_palette, data_quality_cards, footer, metric_card, nav_brand, navigation_links, operational_strip, page_header, progress_bar, section_title, status_badge
from core.visualization import alert_trend, detection_bar, mitre_heatmap, mitre_tactic_bar, risk_confidence_scatter, risk_distribution, safe_chart, severity_donut, source_distribution, top_techniques
from services.case_store import list_cases


def _detections(df: pd.DataFrame) -> pd.DataFrame:
    return df[df.get("final_detection", pd.Series(index=df.index, dtype=str)).astype(str).str.lower() != "normal"].copy()


def main() -> None:
    st.set_page_config(page_title="Analytics // SOC L2", page_icon="📊", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "threat analytics + quality console", "ANALYTICS", "info")
        navigation_links(st)
    df = load_pipeline()
    status = get_data_source_status() or {}
    page_header(st, "SOC Analytics Center", "quantify telemetry, detection behavior, risk-confidence distribution and MITRE coverage")
    operational_strip(st, [("EVENTS", f"{len(df):,}", "info"), ("DETECTIONS", f"{len(_detections(df)):,}", "info"), ("SOURCE", status.get("source", "UNKNOWN"), "success" if not status.get("error") else "warning"), ("BATCH", status.get("batch_id", "N/A"), "info")])
    if df.empty:
        st.warning("No telemetry loaded. Open Ingestion Center first.")
        footer(st)
        return
    quality = data_quality_summary(df)
    with st.container(border=True):
        section_title(st, "Data Quality", "Only observable pipeline counts are displayed; no quality values are invented.")
        data_quality_cards(st, quality)
    detections = _detections(df)
    risk = pd.to_numeric(detections.get("risk_score", pd.Series(dtype=float)), errors="coerce").dropna()
    conf = pd.to_numeric(detections.get("confidence_score", pd.Series(dtype=float)), errors="coerce").dropna()
    c1, c2, c3, c4 = st.columns(4)
    with c1: metric_card(st, "MEAN DETECTION RISK", f"{risk.mean():.1f}/10" if not risk.empty else "N/A", "high" if not risk.empty and risk.mean() >= 7 else "normal", "detection records only")
    with c2: metric_card(st, "MEAN DETECTION CONFIDENCE", f"{conf.mean()*100:.0f}%" if not conf.empty else "N/A", "success", "detection records only")
    with c3: metric_card(st, "MITRE MAPPED", f"{int((~df['mapped_technique'].astype(str).str.lower().str.startswith('not mapped')).sum()) if 'mapped_technique' in df.columns else 0:,}", "success", "mapped telemetry records")
    with c4: metric_card(st, "UNIQUE FINGERPRINTS", f"{df['event_fingerprint'].nunique():,}" if 'event_fingerprint' in df.columns else "N/A", "success", "deterministic event identity")
    search_options = [f"RULE::{x}" for x in df.get("rule_id", pd.Series(dtype=str)).dropna().astype(str).unique()]
    search_options += [f"HOST::{x}" for x in df.get("hostname", pd.Series(dtype=str)).dropna().astype(str).unique()]
    chosen = command_palette(st, sorted(search_options)[:150], key="analytics_command")
    working = df
    if chosen.startswith("RULE::"):
        working = df[df["rule_id"].astype(str) == chosen.split("::", 1)[1]]
    elif chosen.startswith("HOST::"):
        working = df[df["hostname"].astype(str) == chosen.split("::", 1)[1]]
    if chosen:
        st.info(f"Cross-filter active: {html.escape(chosen)} → {len(working):,} records")
    rows = st.columns(2)
    with rows[0]:
        with st.container(border=True): safe_chart(severity_donut(working), st, height=310, key="analytics_severity")
        with st.container(border=True): safe_chart(alert_trend(working), st, height=310, key="analytics_trend")
        with st.container(border=True): safe_chart(mitre_tactic_bar(working), st, height=310, key="analytics_tactics")
        with st.container(border=True): safe_chart(mitre_heatmap(working), st, height=340, key="analytics_mitre_heatmap")
    with rows[1]:
        with st.container(border=True): safe_chart(risk_distribution(working), st, height=310, key="analytics_risk")
        with st.container(border=True): safe_chart(risk_confidence_scatter(_detections(working)), st, height=330, key="analytics_risk_conf")
        with st.container(border=True): safe_chart(top_techniques(working), st, height=310, key="analytics_techniques")
    with st.container(border=True):
        section_title(st, "Rule Coverage", "Detection rules mapped to observed telemetry; configuration metadata is authoritative for configured rules.")
        rule_cols = [c for c in ["rule_id", "rule_version", "rule_description", "rule_enabled", "severity", "mapped_technique", "mitre_tactic"] if c in df.columns]
        if rule_cols:
            rules = df[rule_cols].drop_duplicates().sort_values([c for c in ["rule_id", "rule_version"] if c in rule_cols])
            st.dataframe(rules, use_container_width=True, hide_index=True, height=320)
    with st.container(border=True):
        section_title(st, "Analyst Outcome Statistics", "False-positive / true-positive counts are computed only from persisted analyst decisions.")
        cases = list_cases(500)
        if cases and "rule_id" in df.columns:
            case_map = {str(c.get("incident_id")): c for c in cases}
            rows = []
            for rule_id, group in df.groupby(df["rule_id"].astype(str), dropna=False):
                linked = [case_map.get(str(i)) for i in group["id"].astype(str)]
                linked = [c for c in linked if c]
                rows.append({"Rule ID": rule_id, "Detections": len(group), "Reviewed Cases": sum(c.get("status") in {"REVIEWED", "CLOSED"} for c in linked), "True Positive": sum(c.get("decision") == "True Positive" for c in linked), "False Positive": sum(c.get("decision") == "False Positive" for c in linked), "Needs Investigation": sum(c.get("decision") == "Needs Investigation" for c in linked), "Benign": sum(c.get("decision") == "Benign" for c in linked)})
            st.dataframe(pd.DataFrame(rows).sort_values("Detections", ascending=False), use_container_width=True, hide_index=True, height=300)
        else:
            st.info("No persisted analyst decisions exist yet.")
    footer(st, "SOC_L2 // ANALYTICS CENTER // OBSERVABLE METRICS // HUMAN DECISION")


if __name__ == "__main__":
    main()
