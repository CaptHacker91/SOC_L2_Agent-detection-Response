"""Small security helpers for safely displaying/logging telemetry."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Telemetry ko UI, PDF aur AI context me dikhane se pehle secrets/credentials ko redact karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import json
import re
from typing import Any

# Telemetry ko UI/PDF/AI context me dikhane se pehle common credential/token patterns redact kiye jaate hain.
_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)\b\s*[:=]\s*[\"']?)[^\s,;\"']+"), r"\1[REDACTED]"),
]
_SENSITIVE_KEYS = {"password", "passwd", "secret", "api_key", "apikey", "access_token", "auth_token", "token", "authorization"}


# FUNCTION: redact_text
# Purpose: Ye function redact text operation handle karta hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def redact_text(value: Any) -> str:
    """Return a safe string representation with common secrets removed."""
    text = "" if value is None else str(value)
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# FUNCTION: redact_object
# Purpose: Ye function redact object operation handle karta hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def redact_object(value: Any) -> Any:
    """Recursively redact secrets from nested dictionaries/lists used in raw telemetry."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, dict):
        redacted = {}
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for key, item in value.items():
            normalized_key = str(key).strip().lower().replace("-", "_")
            redacted[str(key)] = "[REDACTED]" if normalized_key in _SENSITIVE_KEYS else redact_object(item)
        return redacted
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, list):
        return [redact_object(v) for v in value]
    return redact_text(value)


# FUNCTION: safe_json
# Purpose: Ye function ka main kaam safe json se related processing ko centrally handle karna hai.
# Input: value, max_chars.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def safe_json(value: Any, max_chars: int | None = None) -> str:
    """Serialize telemetry safely after recursive secret redaction."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, str):
        text = redact_text(value)
    else:
        text = json.dumps(redact_object(value), ensure_ascii=False, default=str, indent=2)
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if max_chars and len(text) > max_chars:
        return text[:max_chars] + "\n...[truncated]..."
    return text
