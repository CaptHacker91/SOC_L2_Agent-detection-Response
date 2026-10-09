"""Detection engineering console: rule coverage, replay and regression-friendly inspection."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from core.analysis import analyze_events
from core.pipeline import load_pipeline
from core.ui import apply_theme, footer, metric_card, nav_brand, navigation_links, page_header, section_title, terminal_box

ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules" / "detection_rules.json"


def main() -> None:
    st.set_page_config(page_title="Detection Engineering // SOC L2", page_icon="🧪", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "rules + replay + coverage console", "DETECTION ENGINEERING", "info")
        navigation_links(st)
    df = load_pipeline()
    page_header(st, "Detection Engineering", "inspect configured rules, execute controlled replay on a supplied event and view coverage")
    rules = json.loads(RULES_PATH.read_text(encoding="utf-8")) if RULES_PATH.exists() else []
    active = [r for r in rules if r.get("enabled", True)]
    c1, c2, c3 = st.columns(3)
    with c1: metric_card(st, "ACTIVE RULES", len(active), "success", "configuration")
    with c2: metric_card(st, "TOTAL RULES", len(rules), "info", "rule pack")
    with c3: metric_card(st, "EVENTS", f"{len(df):,}", "info", "current telemetry")
    with st.container(border=True):
        section_title(st, "Rule Coverage Matrix", "Configuration-driven metadata; coverage is measured against the current telemetry.")
        rows = []
        for rule in rules:
            mask = df.get("threat", pd.Series(index=df.index, dtype=str)).astype(str) == str(rule.get("threat"))
            subset = df[mask]
            rows.append({"Rule": rule.get("threat"), "Version": rule.get("version", "1.0"), "Enabled": rule.get("enabled", True), "Observed Matches": len(subset), "Severity": rule.get("severity"), "Risk": rule.get("risk_score"), "MITRE": rule.get("mitre"), "Tactic": rule.get("mitre_tactic")})
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True, height=330)
    if not df.empty and "id" in df.columns:
        with st.container(border=True):
            section_title(st, "Safe Event Replay", "Replays one already-supplied event through the pure analysis pipeline; no external action is executed.")
            event_id = st.selectbox("Event", df["id"].astype(str).head(150).tolist(), key="rule_replay_event")
            row = df[df["id"].astype(str) == event_id]
            if not row.empty and st.button("Replay Selected Event", type="primary", use_container_width=True, key="rule_replay_button"):
                original = row.iloc[0].to_dict().get("raw_event") or row.iloc[0].to_dict().get("original_log") or row.iloc[0].to_dict()
                if isinstance(original, dict):
                    replay = analyze_events([original], source_mode=str(row.iloc[0].get("source") or "MOCK"))
                    if not replay.empty:
                        result = replay.iloc[0].to_dict()
                        terminal_box(st, [f"event={event_id}", f"detection={result.get('final_detection')}", f"severity={result.get('severity')}", f"risk={result.get('risk_score')}", f"mitre={result.get('mapped_technique')}", f"fingerprint={result.get('event_fingerprint')}"]) 
                else:
                    st.info("The selected event's raw evidence is not structured JSON, so automatic replay is intentionally skipped.")
    with st.container(border=True):
        section_title(st, "Event Schema Inspector", "Shows the observed normalized contract, value types and field presence for the selected telemetry view.")
        schema_source = df.head(1)
        if not schema_source.empty:
            row = schema_source.iloc[0].to_dict()
            required = {"id", "timestamp", "source", "hostname", "source_ip", "destination_ip", "rule_id", "severity", "risk_score", "confidence_score", "mapped_technique"}
            schema_rows = []
            for name, val in row.items():
                schema_rows.append({"Field": name, "Type": type(val).__name__, "Present": bool(val is not None and str(val).strip().lower() not in {"", "none", "nan", "null"}), "Required": name in required})
            st.dataframe(pd.DataFrame(schema_rows).sort_values(["Required", "Field"], ascending=[False, True]), use_container_width=True, hide_index=True, height=360)
    with st.expander("Regression strategy"):
        st.caption("Use positive and negative test events per rule, keep the supplied datasets as regression fixtures, and run the test suite after rule changes.")
    footer(st, "SOC_L2 // DETECTION ENGINEERING // CONTROLLED REPLAY // NO AUTONOMOUS RESPONSE")

if __name__ == "__main__":
    main()
