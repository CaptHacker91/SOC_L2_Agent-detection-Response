"""
Shared pipeline entry point. Both app.py and pages/Investigation.py
import load_pipeline() from here so there is exactly one definition
of "how raw data becomes normalized alerts" in the codebase.

No caching here on purpose — see app.py's module docstring.
"""

import os
import streamlit as st

from core.file_loader import FileLoader
from core.data_source import get_data_source
from core.parser import DetectionParser
from core.normalizer import DataNormalizer
from engine.detection_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper
from engine.severity_engine import SeverityEngine
from engine.alert_triangle import AlertTriangle


def load_pipeline():
    data_source_mode = os.getenv("DATA_SOURCE", "mock").lower()
    try:
        raw = get_data_source().load()
        if data_source_mode == "splunk":
            st.success("Loaded live alerts from Splunk.")
    except Exception as e:
        if data_source_mode == "splunk":
            st.warning(f"Splunk unavailable ({e}) — showing local static export instead.")
        raw = FileLoader(os.getenv("MOCK_DATA_PATH", "data/splunk_export.json")).load()

    parsed = DetectionParser().parse(raw)
    df = DataNormalizer().normalize(parsed)
    if df.empty:
        return df

    df = DetectionEngine("rules/detection_rules.json").analyze(df)
    df = MitreMapper().map(df)
    df = SeverityEngine().calculate(df)
    df = AlertTriangle().generate(df)

    if "id" not in df.columns:
        # IMPORTANT: do NOT use reset_index().rename(columns={"index": "id"})
        # here. Real Splunk exports include a field literally called
        # "index" (Splunk's default index is named "main"), so that
        # rename would silently overwrite the wrong column and give
        # almost every row the same id ("main") -> duplicate widget
        # keys and a StreamlitDuplicateElementKey crash on the
        # dashboard. Building "id" directly from a clean positional
        # index avoids the collision entirely.
        df = df.reset_index(drop=True)
        df["id"] = df.index.astype(str)
    else:
        df["id"] = df["id"].astype(str)
        if df["id"].duplicated().any():
            # Source "id" field exists but isn't actually unique —
            # make it unique rather than let the UI crash on it.
            df["id"] = df.reset_index(drop=True).index.astype(str)

    return df
