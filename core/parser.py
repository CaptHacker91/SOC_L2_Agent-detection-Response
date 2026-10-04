"""Source-neutral parser and event categorization."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Raw records ko basic validation aur source/category classification deta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from typing import Any


# CLASS: DetectionParser
# Role: Ye class ka main kaam Detection Parser se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class DetectionParser:
    """Validate records and classify them for the detection engine."""

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(self) -> None:
        self.errors: list[str] = []

    # FUNCTION: parse
    # Purpose: Ye function parse operation handle karta hai.
    # Input: raw_records.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def parse(self, raw_records: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        self.errors = []
        parsed: list[dict[str, Any]] = []
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for index, record in enumerate(raw_records or []):
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if not isinstance(record, dict) or not record:
                self.errors.append(f"Record {index}: ignored because it is not a non-empty object.")
                continue
            clean = dict(record)
            clean["event_category"] = self._categorize(clean)
            parsed.append(clean)
        return parsed

    @staticmethod
    # FUNCTION: _categorize
    # Purpose: Ye internal helper ka main kaam categorize se related processing ko centrally handle karna hai.
    # Input: record.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _categorize(record: dict[str, Any]) -> str:
        """Identify event type using structural evidence, not only a source label."""
        source = str(record.get("source", "")).strip().lower()

        # Genuine Wazuh telemetry me aam taur par rule + agent + decoder/manager keys milti hain; in structural signals se source identify hota hai.
        wazuh_keys = {"rule", "agent", "manager", "decoder", "full_log", "location", "mitre"}
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if (
            source in {"wazuh", "wazuh-indexer", "wazuh_alert"}
            or len(wazuh_keys.intersection(record.keys())) >= 2
            or isinstance(record.get("rule"), dict) and isinstance(record.get("agent"), dict)
        ):
            return "wazuh"

        sourcetype = str(record.get("sourcetype", "")).lower()
        host = str(record.get("host", "")).lower()
        source_field = str(record.get("source", "")).lower()

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if "vendor_sales" in sourcetype or host == "vendor_sales":
            return "vendor_sales"
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if (
            "access_combined" in sourcetype
            or "access_log" in sourcetype
            or "clientip" in record
            or "uri" in record
            or "http_status" in record
            or "status" in record and "method" in record
        ):
            return "web_access"
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if "vendor_sales" in source_field:
            return "vendor_sales"
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if "threat" in record and "signature" in record:
            return "synthetic_soc"
        return "other"
