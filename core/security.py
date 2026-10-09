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
]
_SENSITIVE_VALUE_KEYS = (
    "api[_-]?key", "x-api-key", "apikey", "access[_-]?token", "auth[_-]?token",
    "password", "passwd", "secret", "client[_-]?secret", "private[_-]?key",
    "session[_-]?token", "refresh[_-]?token", "token", "authorization",
    "cookie", "set[_-]?cookie", "jsessionid", "sessionid",
)
_SECRET_KEY_VALUE_RE = re.compile(
    r"(?i)(\b(?:" + "|".join(_SENSITIVE_VALUE_KEYS) + r")\b\s*[:=]\s*)(?:\"([^\"]*)\"|'([^']*)'|([^\s,;&\"'}\]]+))"
)
_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "api_key", "apikey", "access_token", "auth_token",
    "client_secret", "private_key", "session_token", "refresh_token", "token",
    "authorization", "cookie", "set_cookie", "jsessionid", "sessionid", "x_api_key",
}


# FUNCTION: redact_text
# Purpose: Ye function redact text operation handle karta hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def redact_text(value: Any) -> str:
    """Return a safe string representation with common secrets removed.

    Text that is actually JSON is recursively redacted first so stringified
    telemetry cannot bypass dictionary-key protection. Remaining plain-text
    and query-string key/value forms are then handled with conservative regexes.
    """
    text = "" if value is None else str(value)

    # Stringified JSON is common in Wazuh ``full_log`` and Splunk ``_raw``.
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = None
    if isinstance(parsed, (dict, list)):
        return json.dumps(redact_object(parsed), ensure_ascii=False, default=str)

    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)

    def _replace_key_value(match: re.Match[str]) -> str:
        prefix = match.group(1)
        if match.group(2) is not None:
            return f'{prefix}"[REDACTED]"'
        if match.group(3) is not None:
            return f"{prefix}'[REDACTED]'"
        return f"{prefix}[REDACTED]"

    text = _SECRET_KEY_VALUE_RE.sub(_replace_key_value, text)
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
