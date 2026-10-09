"""Safe runtime diagnostics for the SOC L2 Agent."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from core.config import PROJECT_ROOT, load_settings

REQUIRED = ["pandas", "requests", "streamlit", "plotly", "fpdf"]
OPTIONAL = ["groq"]

def _installed(name: str) -> bool:
    return importlib.util.find_spec(name) is not None

def runtime_diagnostics() -> dict[str, Any]:
    settings = load_settings()
    files = {
        "mock_data": settings.mock_data_path.exists(),
        "rules": (PROJECT_ROOT / "rules" / "detection_rules.json").exists(),
        "env_example": (PROJECT_ROOT / ".env.example").exists(),
        "report_engine": _installed("fpdf"),
    }
    deps = {name: _installed(name) for name in REQUIRED}
    optional = {name: _installed(name) for name in OPTIONAL}
    source_ready = {
        "MOCK": files["mock_data"],
        "WAZUH": bool(settings.wazuh_host and settings.wazuh_api_user and settings.wazuh_api_password),
        "SPLUNK": bool(settings.splunk_host and settings.splunk_token),
    }
    ai_ready = bool(settings.groq_api_key) and optional["groq"]
    return {"dependencies": deps, "optional": optional, "files": files, "source_ready": source_ready, "ai_ready": ai_ready, "active_source": settings.data_source}


def readiness_label(diag: dict[str, Any]) -> str:
    required_ok = all(diag["dependencies"].values()) and all(diag["files"].values())
    return "READY" if required_ok else "DEGRADED"
