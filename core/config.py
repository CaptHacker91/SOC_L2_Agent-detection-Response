"""Central configuration for the SOC L2 Agent.

All runtime settings are read from environment variables so the application can
run in MOCK mode without any external service credentials.
"""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Environment variables se application configuration safely load aur validate karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]


# FUNCTION: _bool_env
# Purpose: Ye internal helper ka main kaam bool env se related processing ko centrally handle karna hai.
# Input: name, default.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


# FUNCTION: _int_env
# Purpose: Ye internal helper ka main kaam int env se related processing ko centrally handle karna hai.
# Input: name, default.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
    try:
        return int(raw) if raw is not None else default
    except (TypeError, ValueError):
        return default


# FUNCTION: resolve_path
# Purpose: Ye function resolve path operation handle karta hai.
# Input: path_value, default.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def resolve_path(path_value: str | None, default: str) -> Path:
    """Resolve a configured path relative to the project root when needed."""
    value = (path_value or default).strip()
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True)
# CLASS: Settings
# Role: Ye class ka main kaam Settings se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class Settings:
    """Immutable application settings loaded from environment variables."""

    data_source: str
    mock_data_path: Path

    wazuh_host: str
    wazuh_api_port: int
    wazuh_api_user: str
    wazuh_api_password: str
    wazuh_indexer_port: int
    wazuh_indexer_user: str
    wazuh_indexer_password: str
    wazuh_verify_ssl: bool

    splunk_host: str
    splunk_port: int
    splunk_token: str
    splunk_search_query: str
    splunk_verify_ssl: bool

    groq_api_key: str
    groq_model: str


# FUNCTION: load_settings
# Purpose: Ye function load settings operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def load_settings() -> Settings:
    """Load `.env` and return the normalized configuration used by the app."""
    load_dotenv(dotenv_path=PROJECT_ROOT / ".env", override=False)
    source = os.getenv("DATA_SOURCE", "MOCK").strip().upper() or "MOCK"
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if source not in {"MOCK", "WAZUH", "SPLUNK"}:
        source = "MOCK"

    return Settings(
        data_source=source,
        mock_data_path=resolve_path(os.getenv("MOCK_DATA_PATH"), "data/wazuh_events.jsonl"),
        wazuh_host=os.getenv("WAZUH_HOST", "").strip(),
        wazuh_api_port=_int_env("WAZUH_API_PORT", 55000),
        wazuh_api_user=os.getenv("WAZUH_API_USER", "").strip(),
        wazuh_api_password=os.getenv("WAZUH_API_PASSWORD", ""),
        wazuh_indexer_port=_int_env("WAZUH_INDEXER_PORT", 9200),
        wazuh_indexer_user=os.getenv("WAZUH_INDEXER_USER", "").strip(),
        wazuh_indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD", ""),
        wazuh_verify_ssl=_bool_env("WAZUH_VERIFY_SSL", True),
        splunk_host=os.getenv("SPLUNK_HOST", "").strip(),
        splunk_port=_int_env("SPLUNK_PORT", 8089),
        splunk_token=os.getenv("SPLUNK_TOKEN", ""),
        splunk_search_query=os.getenv("SPLUNK_SEARCH_QUERY", "").strip(),
        splunk_verify_ssl=_bool_env("SPLUNK_VERIFY_SSL", True),
        groq_api_key=os.getenv("GROQ_API_KEY", ""),
        groq_model=os.getenv("GROQ_MODEL", "openai/gpt-oss-20b").strip() or "openai/gpt-oss-20b",
    )
