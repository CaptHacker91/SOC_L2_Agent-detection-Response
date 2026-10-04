"""Pure SOC processing pipeline - no Streamlit dependency."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Normalized events ko DataFrame me laakar detection, severity, risk aur alert analysis ke liye pipeline chalata hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from core.normalizer import DataNormalizer
from core.parser import DetectionParser
from engine.alert_triangle import AlertTriangle
from engine.detection_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper
from engine.severity_engine import SeverityEngine

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RULES_PATH = PROJECT_ROOT / "rules" / "detection_rules.json"


# FUNCTION: analyze_events
# Purpose: Ye function analyze events operation handle karta hai.
# Input: events, rules_path, source_mode.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def analyze_events(
    events: list[dict[str, Any]] | None,
    rules_path: str | Path = DEFAULT_RULES_PATH,
    source_mode: str = "MOCK",
) -> pd.DataFrame:
    """Run Source -> Parser -> Normalizer -> Detection -> Risk -> MITRE -> Triage."""
    parser = DetectionParser()
    parsed = parser.parse(events or [])
    normalizer = DataNormalizer()
    df = normalizer.normalize(parsed, source_mode=source_mode)
    df.attrs["parser_errors"] = list(parser.errors)
    df.attrs["normalizer_errors"] = list(normalizer.errors)
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if df.empty:
        return df

    df = DetectionEngine(rules_path).analyze(df)
    df = MitreMapper(rules_path=rules_path).map(df)
    df = SeverityEngine(rules_path=rules_path).calculate(df)
    df = AlertTriangle().generate(df)
    return df
