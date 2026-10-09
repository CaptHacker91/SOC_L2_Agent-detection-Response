"""Single Streamlit-facing orchestration layer for MOCK, WAZUH and SPLUNK."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: UI aur data-processing layers ke beech central orchestration layer ke roop me kaam karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from datetime import datetime, timezone
import time
from typing import Any

import pandas as pd
import streamlit as st

from core.analysis import analyze_events
from core.config import load_settings
from core.data_source import get_data_source
from core.file_loader import FileLoadError, FileLoader
from core.splunk_loader import SplunkError
from services.wazuh_service import WazuhError, WazuhService

STATE_DF = "soc_df"
STATE_STATUS = "data_source_status"
DEFAULT_LIMIT = 100
DEFAULT_LOOKBACK = "24h"
LOOKBACK_OPTIONS = ["1h", "24h", "7d", "30d"]
WAZUH_LIMIT_KEY = "wazuh_limit"
WAZUH_LOOKBACK_KEY = "wazuh_lookback"


# FUNCTION: _now
# Purpose: Ye internal helper ka main kaam now se related processing ko centrally handle karna hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# FUNCTION: _empty_df
# Purpose: Ye internal helper ka main kaam empty df se related processing ko centrally handle karna hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _empty_df() -> pd.DataFrame:
    return pd.DataFrame()


# FUNCTION: _set_status
# Purpose: Ye internal helper set status operation handle karta hai.
# Input: status.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _set_status(status: dict[str, Any]) -> None:
    st.session_state[STATE_STATUS] = status


def _finalize_status(status: dict[str, Any], started_perf: float) -> None:
    """Stamp completion telemetry consistently, including early-return source failures."""
    status["completed_at"] = _now()
    status["duration_ms"] = round(max(0.0, (time.perf_counter() - started_perf) * 1000.0), 2)
    _set_status(status)


# FUNCTION: _base_status
# Purpose: Ye internal helper ka main kaam base status se related processing ko centrally handle karna hai.
# Input: source.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _base_status(source: str) -> dict[str, Any]:
    now = _now()
    return {
        "source": source,
        "connected": False,
        "message": "Not checked",
        "checked_at": now,
        "error": None,
        "details": [],
        "count": None,
        "kept_previous": False,
        "last_error": None,
        "processing_stages": {},
        "batch_id": f"BATCH-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
        "started_at": now,
        "completed_at": None,
        "duration_ms": None,
        "fetched_count": None,
        "parsed_count": None,
        "normalized_count": None,
        "analyzed_count": None,
        "parser_errors": 0,
        "normalizer_errors": 0,
    }



def get_wazuh_controls() -> tuple[int, str]:
    """Return the canonical Wazuh fetch limit and lookback used by the pipeline."""
    limit = int(st.session_state.get(WAZUH_LIMIT_KEY, st.session_state.get("dashboard_wazuh_limit", st.session_state.get("ingestion_wazuh_limit", DEFAULT_LIMIT))))
    lookback = str(st.session_state.get(WAZUH_LOOKBACK_KEY, st.session_state.get("dashboard_wazuh_lookback", st.session_state.get("ingestion_wazuh_lookback", DEFAULT_LOOKBACK))))
    if limit < 10 or limit > 1000:
        limit = DEFAULT_LIMIT
    if lookback not in LOOKBACK_OPTIONS:
        lookback = DEFAULT_LOOKBACK
    st.session_state[WAZUH_LIMIT_KEY] = limit
    st.session_state[WAZUH_LOOKBACK_KEY] = lookback
    return limit, lookback



# FUNCTION: _append_analysis_warnings
# Purpose: Ye internal helper ka main kaam append analysis warnings se related processing ko centrally handle karna hai.
# Input: status, df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _append_analysis_warnings(status: dict[str, Any], df: pd.DataFrame) -> None:
    """Expose bounded parsing/normalization diagnostics without failing the dashboard."""
    parser_errors = list(df.attrs.get("parser_errors", []))
    normalizer_errors = list(df.attrs.get("normalizer_errors", []))
    status["parser_errors"] = len(parser_errors)
    status["normalizer_errors"] = len(normalizer_errors)
    warnings = parser_errors + normalizer_errors
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if warnings:
        status.setdefault("details", []).append(f"Processing warnings: {len(warnings)} record(s) needed attention.")
        status["processing_warnings"] = warnings[:20]


# FUNCTION: refresh_data
# Purpose: Ye function refresh data operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def refresh_data() -> None:
    """Load the configured source, run the common pipeline and preserve old data on failure."""
    cfg = load_settings()
    source = cfg.data_source
    status = _base_status(source)
    previous = st.session_state.get(STATE_DF)
    started_perf = time.perf_counter()

    # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
    try:
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if source == "MOCK":
            loader = get_data_source(cfg)
            if not isinstance(loader, FileLoader):
                raise FileLoadError("MOCK source did not resolve to the configured file loader.")
            events = loader.load()
            status["processing_stages"] = {"ingestion": "PASS", "parser": "RUN", "normalizer": "RUN", "detection": "RUN", "triage": "RUN"}
            df = analyze_events(events, source_mode="MOCK")
            status["processing_stages"] = {"ingestion": "PASS", "parser": "PASS", "normalizer": "PASS", "detection": "PASS", "triage": "PASS"}
            status.update({"fetched_count": len(events), "parsed_count": len(events), "normalized_count": len(df), "analyzed_count": len(df)})
            _append_analysis_warnings(status, df)
            status.update({
                "connected": True,
                "message": "MOCK DATA Loaded",
                "count": len(events),
                "details": [f"Local demo source: {cfg.mock_data_path}"],
            })
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if loader.errors:
                status["details"].append(f"Skipped {len(loader.errors)} malformed record(s).")
            st.session_state[STATE_DF] = df

        # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
        elif source == "WAZUH":
            limit, lookback = get_wazuh_controls()
            service = get_data_source(cfg)
            if not isinstance(service, WazuhService):
                raise WazuhError("WAZUH source did not resolve to the configured Wazuh service.")
            connection = service.test_connection()
            status.update(connection)
            status.update({"source": "WAZUH", "checked_at": _now(), "lookback": lookback, "limit": limit, "count": None, "kept_previous": False})
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if not connection.get("connected"):
                status["error"] = "; ".join(connection.get("details", [])) or "Wazuh is unavailable."
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if previous is not None and not previous.empty:
                    status["kept_previous"] = True
                _finalize_status(status, started_perf)
                return
            status["processing_stages"] = {"connection": "PASS", "fetch": "PASS"}
            events = service.fetch_alerts(limit=limit, lookback=lookback)
            df = analyze_events(events, source_mode="WAZUH")
            status["processing_stages"].update({"parser": "PASS", "normalizer": "PASS", "detection": "PASS", "triage": "PASS"})
            status.update({"fetched_count": len(events), "parsed_count": len(events), "normalized_count": len(df), "analyzed_count": len(df)})
            _append_analysis_warnings(status, df)
            status["count"] = len(events)
            status["message"] = "Wazuh Connected"
            st.session_state[STATE_DF] = df

        else:  # SPLUNK
            service = get_data_source(cfg)
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                connection = service.test_connection()
            except SplunkError as exc:
                connection = {"connected": False, "message": "Splunk Connection Failed", "details": [str(exc)]}
            status.update(connection)
            status.update({"source": "SPLUNK", "checked_at": _now(), "count": None, "kept_previous": False})
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if not connection.get("connected"):
                status["error"] = connection.get("message") or "; ".join(connection.get("details", []))
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if previous is not None and not previous.empty:
                    status["kept_previous"] = True
                _finalize_status(status, started_perf)
                return
            status["processing_stages"] = {"connection": "PASS", "fetch": "PASS"}
            events = service.load()
            df = analyze_events(events, source_mode="SPLUNK")
            status["processing_stages"].update({"parser": "PASS", "normalizer": "PASS", "detection": "PASS", "triage": "PASS"})
            status.update({"fetched_count": len(events), "parsed_count": len(events), "normalized_count": len(df), "analyzed_count": len(df)})
            _append_analysis_warnings(status, df)
            status["count"] = len(events)
            status["message"] = "Splunk Connected"
            st.session_state[STATE_DF] = df

    except (WazuhError, SplunkError, FileLoadError, OSError, ValueError) as exc:
        status["message"] = f"{source} Load Failed"
        status["error"] = str(exc)
        status["last_error"] = str(exc)
        status["kept_previous"] = bool(previous is not None and not previous.empty)
        # Kabhi bhi fake/replacement events manufacture mat karo; available ho to previous verified data preserve karo.
    except Exception as exc:  # pragma: no cover - final safety net for the UI.
        status["message"] = f"{source} Processing Error"
        status["error"] = f"Unexpected processing error: {type(exc).__name__}."
        status["last_error"] = status["error"]
        status["kept_previous"] = bool(previous is not None and not previous.empty)

    _finalize_status(status, started_perf)


# FUNCTION: refresh_alerts
# Purpose: Ye function refresh alerts operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def refresh_alerts() -> None:
    """Backward-compatible callback name used by the dashboard."""
    refresh_data()


# FUNCTION: run_connection_test
# Purpose: Ye function run connection test operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def run_connection_test() -> None:
    """Test the active real source; MOCK mode is always locally available."""
    cfg = load_settings()
    status = _base_status(cfg.data_source)
    # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
    try:
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if cfg.data_source == "MOCK":
            loader = get_data_source(cfg)
            if not isinstance(loader, FileLoader):
                raise FileLoadError("MOCK source did not resolve to the configured file loader.")
            events = loader.load()
            count = len(events)
            malformed = len(loader.errors)
            ready = count > 0
            details = [f"{cfg.mock_data_path}", f"Readable records: {count}"]
            if malformed:
                details.append(f"Skipped malformed records: {malformed}")
            status.update({
                "connected": ready,
                "message": "MOCK DATA Ready" if ready else "MOCK DATA Empty",
                "details": details,
                "count": count,
                "error": None if ready else "Configured mock data file is empty or contains no valid records.",
            })
        # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
        elif cfg.data_source == "WAZUH":
            result = get_data_source(cfg).test_connection()
            status.update(result)
        else:
            result = get_data_source(cfg).test_connection()
            status.update(result)
    except (FileLoadError, WazuhError, SplunkError, OSError, ValueError) as exc:
        status.update({"connected": False, "message": "Connection Test Failed", "error": str(exc)})
    _set_status(status)


# FUNCTION: get_data_source_status
# Purpose: Ye function get data source status operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def get_data_source_status() -> dict[str, Any] | None:
    """Return the last data-source status shown in the UI."""
    return st.session_state.get(STATE_STATUS)


# FUNCTION: get_wazuh_status
# Purpose: Ye function get wazuh status operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def get_wazuh_status() -> dict[str, Any] | None:
    """Compatibility alias; the dashboard now uses the generic source status."""
    return get_data_source_status()


# FUNCTION: load_pipeline
# Purpose: Ye function load pipeline operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def load_pipeline() -> pd.DataFrame:
    """Return the analysed DataFrame, loading it once per session when needed."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if STATE_STATUS not in st.session_state or STATE_DF not in st.session_state:
        refresh_data()
    return st.session_state.get(STATE_DF, _empty_df())
