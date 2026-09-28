"""
Streamlit-facing entry point. Both app.py and pages/Investigation.py import
from here, so there is exactly one definition of "how Wazuh alerts become
analysed SOC alerts" in the dashboard.

    Wazuh Indexer -> WazuhService (normalized events) -> core.analysis
                  -> st.session_state

Alerts are fetched from Wazuh only when the analyst clicks "Fetch Latest
Alerts" (and once automatically on first load). The analysed DataFrame is
kept in st.session_state, so typing in the search box or opening the
Investigation page never re-hits the Wazuh API. If you change engine code
while developing, click "Fetch Latest Alerts" again to re-run it.

Failure handling: nothing here raises into the UI. If Wazuh is down or
misconfigured the dashboard keeps working (empty state + a clear
"Wazuh Connection Failed" message); if an earlier fetch succeeded, its
alerts stay on screen.
"""

from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from core.analysis import analyze_events
from services.wazuh_service import WazuhService, WazuhError

STATE_DF = "soc_df"
STATE_STATUS = "wazuh_status"

DEFAULT_LIMIT = 100
DEFAULT_LOOKBACK = "24h"
LOOKBACK_OPTIONS = ["1h", "24h", "7d", "30d"]


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def refresh_alerts():
    """
    Test the Wazuh connection, fetch the latest real alerts, run the SOC
    engine and store the result in session state. Never raises - usable
    directly as a Streamlit on_click callback.
    """
    limit = st.session_state.get("wazuh_limit", DEFAULT_LIMIT)
    lookback = st.session_state.get("wazuh_lookback", DEFAULT_LOOKBACK)

    service = WazuhService.from_env()
    status = service.test_connection()
    status.update({"checked_at": _now(), "error": None, "count": None,
                   "lookback": lookback, "kept_previous": False})

    if status["connected"]:
        try:
            events = service.fetch_alerts(limit=limit, lookback=lookback)
            st.session_state[STATE_DF] = analyze_events(events)
            status["count"] = len(events)
        except WazuhError as exc:
            status["connected"] = False
            status["message"] = "Wazuh Connection Failed"
            status["error"] = str(exc)
        except Exception as exc:  # engine/data bug - keep the dashboard alive
            status["error"] = f"Could not process Wazuh alerts ({type(exc).__name__}: {exc})"
    else:
        status["error"] = "; ".join(status["details"]) or "Wazuh is unreachable."

    if status["error"] and STATE_DF in st.session_state and not st.session_state[STATE_DF].empty:
        status["kept_previous"] = True

    st.session_state[STATE_STATUS] = status


def run_connection_test():
    """Connection test only (no alert fetch). Never raises - usable as an on_click callback."""
    status = WazuhService.from_env().test_connection()
    previous = st.session_state.get(STATE_STATUS) or {}
    status.update({
        "checked_at": _now(),
        "error": None if status["connected"] else ("; ".join(status["details"]) or "Wazuh is unreachable."),
        "count": previous.get("count"),
        "lookback": previous.get("lookback", st.session_state.get("wazuh_lookback", DEFAULT_LOOKBACK)),
        "kept_previous": (not status["connected"]) and not st.session_state.get(STATE_DF, pd.DataFrame()).empty,
    })
    st.session_state[STATE_STATUS] = status


def get_wazuh_status():
    """Last connection/fetch status dict (or None if nothing has run yet)."""
    return st.session_state.get(STATE_STATUS)


def load_pipeline():
    """Return the analysed alerts DataFrame (empty DataFrame if nothing is loaded)."""
    if STATE_STATUS not in st.session_state:
        refresh_alerts()  # first load of this session
    return st.session_state.get(STATE_DF, pd.DataFrame())
