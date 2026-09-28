"""
SOC analysis pipeline (pure Python / pandas - no Streamlit).

    normalized events (from services/wazuh_service.py)
      -> DetectionParser -> DataNormalizer -> DetectionEngine
      -> MitreMapper -> SeverityEngine -> AlertTriangle

Kept separate from core/pipeline.py (which owns the Streamlit session state)
so this logic can be imported and tested without a running dashboard.
"""

import pandas as pd

from core.parser import DetectionParser
from core.normalizer import DataNormalizer
from engine.detection_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper
from engine.severity_engine import SeverityEngine
from engine.alert_triangle import AlertTriangle


def analyze_events(events, rules_path="rules/detection_rules.json"):
    """Run a list of normalized event dicts through the full SOC engine."""
    parsed = DetectionParser().parse(events)
    df = DataNormalizer().normalize(parsed)
    if df.empty:
        return pd.DataFrame()

    df = DetectionEngine(rules_path).analyze(df)
    df = MitreMapper().map(df)
    df = SeverityEngine().calculate(df)
    df = AlertTriangle().generate(df)

    if "id" not in df.columns:
        # IMPORTANT: build "id" from a clean positional index. Do NOT use
        # reset_index().rename(columns={"index": "id"}) - a source field
        # literally named "index" would be silently overwritten and give
        # almost every row the same id (duplicate widget keys -> a
        # StreamlitDuplicateElementKey crash on the dashboard).
        df = df.reset_index(drop=True)
        df["id"] = df.index.astype(str)
    else:
        df["id"] = df["id"].astype(str)
        if df["id"].isin(["None", "nan", ""]).any() or df["id"].duplicated().any():
            # Source "id" missing or not actually unique - make it unique
            # rather than let the UI crash on it.
            df["id"] = df.reset_index(drop=True).index.astype(str)

    return df
