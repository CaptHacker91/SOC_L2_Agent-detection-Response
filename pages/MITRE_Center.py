"""MITRE ATT&CK mapping center driven only by supplied/configured mappings."""
from __future__ import annotations

import html

import pandas as pd
import streamlit as st

from core.pipeline import load_pipeline
from core.ui import apply_theme, footer, metric_card, nav_brand, navigation_links, page_header, section_title, status_badge
from core.visualization import mitre_tactic_bar, safe_chart, top_techniques


def main() -> None:
    st.set_page_config(page_title="MITRE ATT&CK // SOC L2", page_icon="🎯", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "attack mapping + coverage console", "MITRE CENTER", "info")
        navigation_links(st)
    df = load_pipeline()
    page_header(st, "MITRE ATT&CK Center", "review configured technique mappings, tactics, coverage and unmapped detections")
    if df.empty:
        st.warning("No telemetry loaded.")
        footer(st)
        return
    mapped_mask = ~df.get("mapped_technique", pd.Series(index=df.index, dtype=str)).astype(str).str.lower().str.startswith("not mapped")
    mapped = df[mapped_mask].copy()
    unmapped = df[~mapped_mask].copy()
    c1, c2, c3 = st.columns(3)
    with c1: metric_card(st, "MAPPED RECORDS", f"{len(mapped):,}", "success", f"of {len(df):,}")
    with c2: metric_card(st, "UNMAPPED RECORDS", f"{len(unmapped):,}", "warning" if len(unmapped) else "success", "mapping not established")
    with c3: metric_card(st, "TECHNIQUES", f"{mapped.get('mapped_technique', pd.Series(dtype=str)).nunique():,}", "info", "unique mapped IDs")
    charts = st.columns(2)
    with charts[0]:
        with st.container(border=True): safe_chart(top_techniques(mapped), st, height=330, key="mitre_top")
    with charts[1]:
        with st.container(border=True): safe_chart(mitre_tactic_bar(mapped), st, height=330, key="mitre_tactics")
    with st.container(border=True):
        section_title(st, "Technique → Tactic → Evidence", "Each row is traceable back to telemetry fields; no external threat intelligence is added.")
        cols = [c for c in ["mapped_technique", "mitre_technique_name", "mitre_tactic", "mitre_mapping_source", "rule_id", "threat", "severity", "risk_score", "evidence_completeness_label", "evidence_summary", "why_alert_fired"] if c in mapped.columns]
        st.dataframe(mapped[cols].sort_values([c for c in ["mitre_tactic", "mapped_technique"] if c in cols]), use_container_width=True, hide_index=True, height=520)
    with st.expander("Unmapped queue"):
        cols = [c for c in ["id", "timestamp", "rule_id", "threat", "severity", "risk_score", "detection_reason"] if c in unmapped.columns]
        st.dataframe(unmapped[cols], use_container_width=True, hide_index=True, height=300)
    with st.expander("MITRE boundary"):
        status_badge(st, "CONFIGURATION / TELEMETRY MAPPINGS ONLY", "info")
        st.caption("An unmapped event remains unmapped. A configured technique is a mapping aid and does not independently establish attacker intent or compromise.")
    footer(st, "SOC_L2 // MITRE ATT&CK CENTER // MAPPING TRACEABLE // NO FABRICATED INTEL")

if __name__ == "__main__":
    main()
