"""Factories for MOCK, WAZUH and SPLUNK data sources."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Configured data source ke hisaab se MOCK, WAZUH ya SPLUNK loader/service provide karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from typing import Any

from core.config import Settings, load_settings
from core.file_loader import FileLoader
from core.splunk_loader import SplunkLoader
from services.wazuh_service import WazuhService


# FUNCTION: get_data_source
# Purpose: Ye function get data source operation handle karta hai.
# Input: settings.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def get_data_source(settings: Settings | None = None) -> Any:
    """Return the source client selected by DATA_SOURCE."""
    cfg = settings or load_settings()
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if cfg.data_source == "WAZUH":
        return WazuhService.from_settings(cfg)
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if cfg.data_source == "SPLUNK":
        return SplunkLoader.from_settings(cfg)
    return FileLoader(cfg.mock_data_path)
