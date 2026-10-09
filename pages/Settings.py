"""Safe runtime diagnostics and configuration visibility without exposing secrets."""
from __future__ import annotations

import importlib.util
import platform
import sys

import pandas as pd
import streamlit as st

from core.config import load_settings
from core.diagnostics import readiness_label, runtime_diagnostics
from core.pipeline import get_data_source_status
from core.ui import apply_theme, footer, metric_card, mini_field, nav_brand, navigation_links, operational_strip, page_header, section_title, status_badge
from services.case_store import DB_PATH


def _availability(module: str) -> str:
    return "AVAILABLE" if importlib.util.find_spec(module) else "MISSING"


def main() -> None:
    st.set_page_config(page_title="Settings // SOC L2", page_icon="⚙️", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "read-only environment diagnostics", "SETTINGS", "info")
        navigation_links(st)
    settings = load_settings()
    status = get_data_source_status() or {}
    page_header(st, "Settings & Diagnostics", "safe visibility into runtime configuration, provider readiness and application health")
    operational_strip(st, [("ENVIRONMENT", settings.data_source, "success" if settings.data_source == "MOCK" else "info"), ("PYTHON", platform.python_version(), "success"), ("PLATFORM", platform.system(), "info"), ("CASE STORE", "READY", "success" if DB_PATH.parent.exists() else "warning")])
    with st.container(border=True):
        section_title(st, "Provider Readiness", "Configuration state only — credentials and secret values are never displayed.")
        cols = st.columns(4)
        with cols[0]: metric_card(st, "MOCK", "READY", "success", "local deterministic source")
        with cols[1]: metric_card(st, "WAZUH", "CONFIGURED" if settings.wazuh_host else "NOT CONFIGURED", "success" if settings.wazuh_host else "info", "host only")
        with cols[2]: metric_card(st, "SPLUNK", "CONFIGURED" if settings.splunk_host and settings.splunk_token else "NOT CONFIGURED", "success" if settings.splunk_host and settings.splunk_token else "info", "host/token presence")
        with cols[3]: metric_card(st, "AI", "AVAILABLE" if settings.groq_api_key else "OPTIONAL / OFF", "success" if settings.groq_api_key else "info", settings.groq_model)
    with st.container(border=True):
        section_title(st, "Runtime Diagnostics", "Read-only validator for dependencies, required files and optional integrations; secrets are never rendered.")
        diag = runtime_diagnostics()
        readiness = readiness_label(diag)
        cols = st.columns(4)
        with cols[0]: metric_card(st, "READINESS", readiness, "success" if readiness == "READY" else "warning", "local validator")
        with cols[1]: metric_card(st, "CORE DEPS", f"{sum(diag['dependencies'].values())}/{len(diag['dependencies'])}", "success" if all(diag['dependencies'].values()) else "warning", "installed")
        with cols[2]: metric_card(st, "AI", "READY" if diag["ai_ready"] else "OPTIONAL / OFF", "success" if diag["ai_ready"] else "info", "advisory only")
        with cols[3]: metric_card(st, "CASE STORE", "READY", "success", "SQLite persistence")
        rows = []
        rows += [{"Scope": "Dependency", "Check": name, "Status": "PASS" if ok else "MISSING"} for name, ok in diag["dependencies"].items()]
        rows += [{"Scope": "Optional", "Check": name, "Status": "AVAILABLE" if ok else "NOT INSTALLED"} for name, ok in diag["optional"].items()]
        rows += [{"Scope": "File", "Check": name, "Status": "PASS" if ok else "MISSING"} for name, ok in diag["files"].items()]
        rows += [{"Scope": "Source", "Check": name, "Status": "CONFIGURED" if ok else "NOT CONFIGURED"} for name, ok in diag["source_ready"].items()]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    with st.container(border=True):
        section_title(st, "Runtime Dependencies")
        st.dataframe([{"Component": name, "Status": _availability(module)} for name, module in [("Streamlit", "streamlit"), ("Pandas", "pandas"), ("Requests", "requests"), ("Plotly", "plotly"), ("PDF Engine", "fpdf"), ("Dotenv", "dotenv"), ("SQLite", "sqlite3")]], use_container_width=True, hide_index=True)
    with st.container(border=True):
        section_title(st, "Safe Configuration Snapshot")
        mini_field(st, "Data Source", settings.data_source)
        mini_field(st, "Wazuh Verify SSL", settings.wazuh_verify_ssl)
        mini_field(st, "Wazuh API Port", settings.wazuh_api_port)
        mini_field(st, "Wazuh Indexer Port", settings.wazuh_indexer_port)
        mini_field(st, "Splunk Port", settings.splunk_port)
        mini_field(st, "AI Model", settings.groq_model)
        mini_field(st, "Current Source Status", status.get("message", "Not checked"))
    with st.container(border=True):
        section_title(st, "Build Information")
        mini_field(st, "Build ID", "SOC-2026.10.08-MASTER")
        mini_field(st, "Application Version", "1.1")
        mini_field(st, "Case Store Schema", "1.1")
        mini_field(st, "Telemetry Schema", "1.2")
    with st.expander("Architecture"):
        try:
            st.code((__import__("pathlib").Path(__file__).resolve().parents[1] / "ARCHITECTURE.md").read_text(encoding="utf-8"), language="markdown")
        except OSError:
            st.info("Architecture document unavailable.")
    with st.expander("Changelog"):
        try:
            st.code((__import__("pathlib").Path(__file__).resolve().parents[1] / "CHANGELOG.md").read_text(encoding="utf-8"), language="markdown")
        except OSError:
            st.info("Changelog unavailable.")
    with st.expander("Security posture"):
        status_badge(st, "SECRETS NOT RENDERED", "success")
        st.caption("The settings console intentionally hides passwords, tokens, API keys and other secret material. External sources must be configured through .env or deployment secrets.")
    footer(st, "SOC_L2 // SETTINGS // SAFE DIAGNOSTICS // NO SECRET EXPOSURE")

if __name__ == "__main__":
    main()
