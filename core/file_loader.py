"""Robust local JSON/JSONL loader used for MOCK mode and exported data."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Local JSON/JSONL files ko resilient tareeke se read karta hai, taaki ek bad record poora dataset fail na kare.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


# CLASS: FileLoadError
# Role: Ye class ka main kaam File Load Error se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class FileLoadError(Exception):
    """Raised when a source file cannot be read at all."""


# CLASS: FileLoader
# Role: Ye class ka main kaam File Loader se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class FileLoader:
    """Load JSON, wrapped JSON or JSONL without letting one bad record kill the dataset."""

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: file_path.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)
        self.errors: list[str] = []
        self.records_loaded = 0

    # FUNCTION: load
    # Purpose: Ye function load operation handle karta hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def load(self) -> list[dict[str, Any]]:
        """Return clean dictionaries and preserve parse diagnostics in ``errors``."""
        self.errors = []
        self.records_loaded = 0
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not self.file_path.exists():
            raise FileLoadError(f"Data file not found: {self.file_path}")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not self.file_path.is_file():
            raise FileLoadError(f"Configured data path is not a file: {self.file_path}")

        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            content = self.file_path.read_text(encoding="utf-8-sig").strip()
        except (OSError, UnicodeError) as exc:
            raise FileLoadError(f"Could not read data file: {self.file_path.name}") from exc

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not content:
            return []

        # Pehle poori file ko JSON ke roop me parse karne ki koshish ki jaati hai (array ya object dono).
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            parsed = json.loads(content)
            records = self._extract_records(parsed)
            self.records_loaded = len(records)
            return records
        except json.JSONDecodeError:
            # Kai exports ka extension .json hota hai lekin actual content JSONL hota hai; isliye line-by-line fallback rakha gaya hai.
            pass

        records: list[dict[str, Any]] = []
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for line_number, line in enumerate(content.splitlines(), start=1):
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if not line.strip():
                continue
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                parsed_line = json.loads(line)
                record = self._unwrap(parsed_line)
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if isinstance(record, dict):
                    records.append(record)
                else:
                    self.errors.append(f"Line {line_number}: JSON record is not an object.")
            except json.JSONDecodeError as exc:
                self.errors.append(f"Line {line_number}: malformed JSON ({exc.msg}).")

        self.records_loaded = len(records)
        return records

    # FUNCTION: _extract_records
    # Purpose: Ye internal helper ka main kaam extract records se related processing ko centrally handle karna hai.
    # Input: parsed.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _extract_records(self, parsed: Any) -> list[dict[str, Any]]:
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if isinstance(parsed, list):
            records = []
            # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
            for index, item in enumerate(parsed):
                record = self._unwrap(item)
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if isinstance(record, dict):
                    records.append(record)
                else:
                    self.errors.append(f"Record {index}: JSON value is not an object.")
            return records

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if isinstance(parsed, dict):
            # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
            for key in ("results", "events", "data", "records"):
                value = parsed.get(key)
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if isinstance(value, list):
                    return self._extract_records(value)
            record = self._unwrap(parsed)
            return [record] if isinstance(record, dict) else []

        self.errors.append("Top-level JSON value is neither an object nor a list.")
        return []

    @staticmethod
    # FUNCTION: _unwrap
    # Purpose: Ye internal helper ka main kaam unwrap se related processing ko centrally handle karna hai.
    # Input: obj.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _unwrap(obj: Any) -> Any:
        """Unwrap common Splunk export and API envelopes while keeping raw fields intact."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
            return obj["result"]
        return obj
