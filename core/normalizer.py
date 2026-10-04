"""Convert Wazuh, Splunk and synthetic records to one normalized SOC event model."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Different telemetry formats ko ek common normalized SOC event structure me convert karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from typing import Any

import pandas as pd

from core.models import NORMALIZED_FIELDS, clean_value, ensure_contract_columns
from services.wazuh_service import normalize_wazuh_alert, looks_like_wazuh_event


# CLASS: DataNormalizer
# Role: Ye class ka main kaam Data Normalizer se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class DataNormalizer:
    """Normalize source-specific dictionaries while preserving original telemetry."""

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(self) -> None:
        self.errors: list[str] = []

    # FUNCTION: normalize
    # Purpose: Ye function normalize operation handle karta hai.
    # Input: parsed_data, source_mode.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def normalize(self, parsed_data: list[dict[str, Any]] | None, source_mode: str = "MOCK") -> pd.DataFrame:
        self.errors = []
        rows: list[dict[str, Any]] = []
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for index, record in enumerate(parsed_data or []):
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                rows.append(self.normalize_record(record, source_mode=source_mode))
            except Exception as exc:
                # Ek malformed event ki wajah se poora dataset fail nahi hona chahiye.
                self.errors.append(f"Record {index}: normalization failed ({type(exc).__name__}).")
                rows.append(self._safe_fallback(record, source_mode))

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not rows:
            return pd.DataFrame(columns=NORMALIZED_FIELDS)

        df = ensure_contract_columns(pd.DataFrame(rows))
        df = self._ensure_unique_ids(df)
        df = df.reset_index(drop=True)
        return df

    # FUNCTION: normalize_record
    # Purpose: Ye function normalize record operation handle karta hai.
    # Input: record, source_mode.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def normalize_record(self, record: dict[str, Any], source_mode: str = "MOCK") -> dict[str, Any]:
        """Normalize a single record and retain the raw event exactly enough for investigation."""
        source_mode = (source_mode or "MOCK").upper()
        category = record.get("event_category") or "other"

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if category == "wazuh" or looks_like_wazuh_event(record):
            # Jo record pehle se normalized hai use unnecessary transformation ke bina preserve kiya jaata hai.
            # Raw Wazuh documents ke liye neeche diya gaya integration extractor use hota hai.
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if record.get("raw_event") is not None and any(record.get(key) is not None for key in ("hostname", "source_ip", "rule_id")):
                normalized = self._normalize_existing_contract(record, source_mode)
            else:
                normalized = normalize_wazuh_alert(record, display_source=source_mode)
        else:
            normalized = self._normalize_generic(record, source_mode)

        normalized["event_category"] = category
        normalized["source"] = source_mode
        normalized["source_type"] = category
        return normalized


    # FUNCTION: _normalize_existing_contract
    # Purpose: Ye internal helper normalize existing contract operation handle karta hai.
    # Input: record, source_mode.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _normalize_existing_contract(self, record: dict[str, Any], source_mode: str) -> dict[str, Any]:
        """Keep already-normalized records stable when the core pipeline is called repeatedly."""
        row = {key: clean_value(record.get(key)) for key in NORMALIZED_FIELDS}
        row["raw_event"] = record.get("raw_event")
        row["source"] = source_mode.upper()
        row["source_type"] = record.get("source_type") or record.get("event_category") or "other"
        row["destination_ip"] = clean_value(record.get("destination_ip") or record.get("dst_ip"))
        row["dst_ip"] = row["destination_ip"]
        row["command"] = clean_value(record.get("command") or record.get("command_line"))
        row["command_line"] = row["command"]
        return row

    # FUNCTION: _normalize_generic
    # Purpose: Ye internal helper normalize generic operation handle karta hai.
    # Input: record, source_mode.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _normalize_generic(self, record: dict[str, Any], source_mode: str) -> dict[str, Any]:
        row = {key: None for key in NORMALIZED_FIELDS}

        row["id"] = self._first(record, "id", "event_id", "eventid", "_cd")
        row["timestamp"] = self._first(record, "timestamp", "event_time", "_time", "time")
        row["threat"] = clean_value(record.get("threat"))
        row["signature"] = clean_value(record.get("signature"))
        row["rule_type"] = clean_value(record.get("rule_type"))
        row["tool"] = clean_value(record.get("tool"))
        row["hostname"] = self._first(record, "hostname", "host")
        row["username"] = self._clean_user(self._first(record, "username", "user", "srcuser"))
        row["source_ip"] = self._first(record, "source_ip", "src_ip", "clientip", "srcip")
        row["destination_ip"] = self._first(record, "destination_ip", "dst_ip", "dest_ip", "dstip")
        row["dst_ip"] = row["destination_ip"]
        row["event_type"] = self._first(record, "event_type", "event_type_name", "sourcetype", "type")
        row["description"] = self._first(record, "description", "message", "msg", "threat")
        row["rule_id"] = self._first(record, "rule_id", "rule") if not isinstance(record.get("rule"), dict) else None
        row["rule_level"] = self._first(record, "rule_level", "level")
        row["rule_groups"] = self._first(record, "rule_groups", "groups")
        row["mitre_technique"] = self._first(record, "mitre_technique", "mapped_technique", "mitre")
        row["mitre_tactic"] = self._first(record, "mitre_tactic")
        row["process"] = self._first(record, "process", "process_name")
        row["command"] = self._first(record, "command", "command_line")
        row["command_line"] = row["command"]
        row["url"] = self._first(record, "url", "uri")
        row["domain"] = self._first(record, "domain", "referer_domain")
        row["filename"] = self._first(record, "filename", "file")
        row["file_hash"] = self._first(record, "file_hash", "hash", "sha256", "sha1", "md5")
        row["http_method"] = self._first(record, "http_method", "method")
        row["http_status"] = self._to_int(self._first(record, "http_status", "status"))
        row["uri_path"] = self._first(record, "uri_path")
        row["uri_query"] = self._first(record, "uri_query")
        row["referer"] = self._first(record, "referer")
        row["user_agent"] = self._first(record, "user_agent", "useragent")
        row["original_log"] = self._first(record, "original_log", "_raw")
        row["raw_event"] = record
        return {k: clean_value(v) for k, v in row.items()}

    @staticmethod
    # FUNCTION: _first
    # Purpose: Ye internal helper ka main kaam first se related processing ko centrally handle karna hai.
    # Input: record, *keys.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _first(record: dict[str, Any], *keys: str) -> Any:
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for key in keys:
            value = record.get(key)
            value = clean_value(value)
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if value is not None:
                return value
        return None

    @staticmethod
    # FUNCTION: _clean_user
    # Purpose: Ye internal helper clean user operation handle karta hai.
    # Input: value.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _clean_user(value: Any) -> Any:
        value = clean_value(value)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if value is None:
            return None
        return str(value).strip() or None

    @staticmethod
    # FUNCTION: _to_int
    # Purpose: Ye internal helper ka main kaam to int se related processing ko centrally handle karna hai.
    # Input: value.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _to_int(value: Any) -> int | None:
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    # FUNCTION: _ensure_unique_ids
    # Purpose: Ye internal helper ensure unique ids operation handle karta hai.
    # Input: df.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _ensure_unique_ids(df: pd.DataFrame) -> pd.DataFrame:
        ids: list[str] = []
        seen: dict[str, int] = {}
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for index, value in enumerate(df["id"].tolist()):
            base = str(value).strip() if clean_value(value) is not None else f"event-{index + 1:04d}"
            count = seen.get(base, 0)
            seen[base] = count + 1
            ids.append(base if count == 0 else f"{base}-{count + 1}")
        df["id"] = ids
        return df

    @staticmethod
    # FUNCTION: _safe_fallback
    # Purpose: Ye internal helper ka main kaam safe fallback se related processing ko centrally handle karna hai.
    # Input: record, source_mode.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _safe_fallback(record: Any, source_mode: str) -> dict[str, Any]:
        return {
            **{key: None for key in NORMALIZED_FIELDS},
            "source": source_mode.upper(),
            "source_type": "other",
            "event_category": "other",
            "raw_event": record,
            "description": "Event could not be fully normalized; original telemetry was preserved.",
        }
