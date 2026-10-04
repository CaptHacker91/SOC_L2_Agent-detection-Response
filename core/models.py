"""Shared normalized event contract used by all pipeline stages."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Project ke common normalized event fields aur data-contract ko define karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from typing import Any

import pandas as pd


NOT_AVAILABLE = "Not available in supplied telemetry"

# Ye stable fields UI, detection aur reporting layers ke liye common contract provide karte hain.
NORMALIZED_FIELDS = (
    "id",
    "timestamp",
    "source",
    "source_type",
    "event_type",
    "hostname",
    "agent_id",
    "agent_name",
    "agent_ip",
    "source_ip",
    "destination_ip",
    "dst_ip",
    "username",
    "description",
    "rule_id",
    "rule_level",
    "rule_groups",
    "mitre_technique",
    "mitre_technique_name",
    "mitre_tactic",
    "mitre_mapping_source",
    "process",
    "command",
    "command_line",
    "url",
    "domain",
    "filename",
    "file_hash",
    "http_method",
    "http_status",
    "uri_path",
    "uri_query",
    "referer",
    "user_agent",
    "raw_event",
    "original_log",
)


# FUNCTION: clean_value
# Purpose: Ye function clean value operation handle karta hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def clean_value(value: Any) -> Any:
    """Convert common placeholder/null values to None without changing real data."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if value is None:
        return None
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, float) and pd.isna(value):
        return None
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, str):
        text = value.strip()
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if text.lower() in {"", "none", "null", "nan", "n/a", "na", "-"}:
            return None
        return text
    return value


# FUNCTION: ensure_contract_columns
# Purpose: Ye function ensure contract columns operation handle karta hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def ensure_contract_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Ensure all normalized columns exist so UI/dataframe operations never KeyError."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if df is None:
        return pd.DataFrame(columns=NORMALIZED_FIELDS)
    result = df.copy()
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for column in NORMALIZED_FIELDS:
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if column not in result.columns:
            result[column] = None
    return result
