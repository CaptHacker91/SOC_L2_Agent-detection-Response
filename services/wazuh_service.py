"""Wazuh Server API + Indexer integration and Wazuh event extraction."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Wazuh API/Indexer se connection, alert retrieval aur Wazuh event normalization handle karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import os
import re
import time
from typing import Any
from urllib.parse import urlsplit

import requests

try:
    import urllib3
except ImportError:  # pragma: no cover - requests normally brings it in.
    urllib3 = None


# CLASS: WazuhError
# Role: Ye class ka main kaam Wazuh Error se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class WazuhError(Exception):
    """Safe, user-facing Wazuh integration error."""


PLACEHOLDERS = {"", "-", "n/a", "na", "null", "none", "unknown", "(null)"}
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
HASH_RE = re.compile(r"\b(?:SHA256|SHA1|MD5)=([A-Fa-f0-9]{32,64})\b", re.IGNORECASE)


# FUNCTION: clean_scalar
# Purpose: Ye function clean scalar operation handle karta hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def clean_scalar(value: Any) -> Any:
    """Return a scalar value or None for common placeholders."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    text = str(value).strip()
    return None if text.lower() in PLACEHOLDERS else text


# FUNCTION: _dig
# Purpose: Ye internal helper ka main kaam dig se related processing ko centrally handle karna hai.
# Input: obj, path.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _dig(obj: Any, path: str) -> Any:
    """Read nested Wazuh fields, including flattened keys such as ``source.ip``."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(obj, dict) and path in obj:
        return obj[path]
    current = obj
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for part in path.split("."):
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not isinstance(current, dict):
            return None
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if part in current:
            current = current[part]
            continue
        lower = part.lower()
        match = next((value for key, value in current.items() if str(key).lower() == lower), None)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if match is None:
            return None
        current = match
    return current


# FUNCTION: first_value
# Purpose: Ye function ka main kaam first value se related processing ko centrally handle karna hai.
# Input: obj, *paths.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def first_value(obj: Any, *paths: str) -> Any:
    """Return the first non-placeholder scalar found in the supplied paths."""
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for path in paths:
        value = clean_scalar(_dig(obj, path))
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if value is not None:
            return value
    return None


# FUNCTION: as_list
# Purpose: Ye function ka main kaam as list se related processing ko centrally handle karna hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def as_list(value: Any) -> list[str]:
    """Normalize a Wazuh string/list field to a clean list."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if value is None:
        return []
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if clean_scalar(item) is not None]
    cleaned = clean_scalar(value)
    return [cleaned] if cleaned else []


# FUNCTION: to_int
# Purpose: Ye function ka main kaam to int se related processing ko centrally handle karna hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def to_int(value: Any) -> int | None:
    # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# FUNCTION: severity_from_level
# Purpose: Ye function ka main kaam severity from level se related processing ko centrally handle karna hai.
# Input: level.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def severity_from_level(level: int | None) -> str | None:
    """Translate Wazuh rule level to the same severity bands used by SeverityEngine."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if level is None:
        return None
    level = max(0, min(int(level), 15))
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if level >= 14:
        return "Critical"
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if level >= 11:
        return "High"
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if level >= 6:
        return "Medium"
    return "Low"


# FUNCTION: looks_like_wazuh_event
# Purpose: Ye function looks like wazuh event operation handle karta hai.
# Input: event.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def looks_like_wazuh_event(event: Any) -> bool:
    """Detect Wazuh-shaped telemetry without trusting only a ``source`` label."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if not isinstance(event, dict):
        return False
    source = str(event.get("source", "")).lower().strip()
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if source in {"wazuh", "wazuh-indexer", "wazuh_alert", "wazuh alert"}:
        return True
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if isinstance(event.get("_source"), dict):
        return looks_like_wazuh_event(event["_source"])
    structural_keys = {"rule", "agent", "manager", "decoder", "full_log", "location", "mitre"}
    keys = {str(key).strip().lower() for key in event.keys()}
    flattened_keys = {
        "rule.id", "rule.level", "rule.description", "rule.groups",
        "agent.id", "agent.name", "agent.ip", "manager.name", "decoder.name",
    }
    has_flattened_wazuh = len(flattened_keys.intersection(keys)) >= 2 or (
        "rule.id" in keys and any(key in keys for key in {"agent.id", "agent.name", "agent.ip"})
    )
    structural_key_names = {str(key).strip().lower() for key in structural_keys}
    return len(structural_key_names.intersection(keys)) >= 2 or (
        isinstance(event.get("rule"), dict) and isinstance(event.get("agent"), dict)
    ) or has_flattened_wazuh


# FUNCTION: _extract_hash
# Purpose: Ye internal helper ka main kaam extract hash se related processing ko centrally handle karna hai.
# Input: alert.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _extract_hash(alert: dict[str, Any]) -> str | None:
    """Get the strongest file hash present in telemetry, without inventing one."""
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for path in (
        "syscheck.sha256_after",
        "syscheck.sha1_after",
        "syscheck.md5_after",
        "data.win.eventdata.hash",
        "data.win.eventdata.hashes",
        "hash",
    ):
        value = first_value(alert, path)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if value:
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if len(value) in {32, 40, 64} and all(c in "0123456789abcdefABCDEF" for c in value):
                return value
            match = HASH_RE.search(value)
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if match:
                return match.group(1)
    return None


# FUNCTION: normalize_wazuh_alert
# Purpose: Ye function normalize wazuh alert operation handle karta hai.
# Input: hit, display_source.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def normalize_wazuh_alert(hit: dict[str, Any], display_source: str = "WAZUH") -> dict[str, Any]:
    """Normalize one Wazuh hit or bare alert document for the common pipeline."""
    alert = hit.get("_source", hit) if isinstance(hit, dict) else {}
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if not isinstance(alert, dict):
        alert = {}

    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    manager = alert.get("manager") if isinstance(alert.get("manager"), dict) else {}
    decoder = alert.get("decoder") if isinstance(alert.get("decoder"), dict) else {}

    # Kuch OpenSearch/Splunk exports nested fields ko dotted keys ke form me flatten kar dete hain; isliye dono formats support kiye gaye hain.
    flat_rule_id = first_value(alert, "rule.id")
    flat_rule_level = to_int(first_value(alert, "rule.level"))
    flat_rule_description = first_value(alert, "rule.description")
    flat_rule_groups = as_list(first_value(alert, "rule.groups"))

    # Different Wazuh versions/exports MITRE information ko rule.mitre, top-level mitre ya data ke andar rakh sakte hain.
    mitre = {}
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for candidate in (rule.get("mitre"), alert.get("mitre"), _dig(alert, "data.mitre")):
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if isinstance(candidate, dict):
            mitre = candidate
            break

    level = to_int(rule.get("level")) if rule.get("level") is not None else flat_rule_level
    groups = as_list(rule.get("groups")) or flat_rule_groups
    technique_ids = as_list(mitre.get("id") or mitre.get("ids"))
    technique_names = as_list(mitre.get("technique") or mitre.get("techniques") or mitre.get("name"))
    tactics = as_list(mitre.get("tactic") or mitre.get("tactics"))

    url = first_value(alert, "data.url", "data.http.url", "data.win.eventdata.url", "url")
    domain = first_value(
        alert,
        "data.domain",
        "data.win.eventdata.queryName",
        "data.win.eventdata.destinationHostname",
        "domain",
    )
    uri_path = first_value(alert, "data.uri_path", "data.uri", "uri_path")
    uri_query = first_value(alert, "data.uri_query", "uri_query")
    if url:
        # URL/URI path and query are direct evidence-derived fields; no values are inferred.
        try:
            parts = urlsplit(url)
            if not domain and parts.hostname:
                domain = parts.hostname
            if not uri_path and parts.path:
                uri_path = parts.path
            if uri_query is None and parts.query:
                uri_query = parts.query
        except ValueError:
            pass

    http_method = first_value(alert, "data.http_method", "data.method", "data.win.eventdata.httpMethod", "http_method")
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if http_method:
        http_method = http_method.upper() if http_method.upper() in HTTP_METHODS else http_method

    http_status = to_int(first_value(alert, "data.http_status", "data.status", "data.win.eventdata.status", "http_status"))
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if http_status is None and any(group.lower() in {"web", "accesslog", "apache", "nginx", "iis"} for group in groups):
        candidate = to_int(first_value(alert, "data.id", "data.responseCode"))
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if candidate is not None and 100 <= candidate <= 599:
            http_status = candidate

    event_id = clean_scalar(alert.get("id")) or clean_scalar(hit.get("_id") if isinstance(hit, dict) else None)
    agent_id = clean_scalar(agent.get("id")) or first_value(alert, "agent.id", "data.agent.id")
    agent_name = clean_scalar(agent.get("name")) or first_value(alert, "agent.name", "data.agent.name")
    agent_ip = clean_scalar(agent.get("ip")) or first_value(alert, "agent.ip", "data.agent.ip")

    return {
        "id": event_id,
        "timestamp": first_value(alert, "timestamp", "@timestamp"),
        "source": display_source.upper(),
        "source_type": "wazuh",
        "event_type": clean_scalar(decoder.get("name")) or (groups[0] if groups else None),
        "hostname": agent_name or agent_id,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "agent_ip": agent_ip,
        "source_ip": first_value(
            alert,
            "data.srcip",
            "data.src_ip",
            "data.source.ip",
            "data.source_ip",
            "data.win.eventdata.ipAddress",
            "data.win.eventdata.sourceIp",
            "source.ip",
            "srcip",
            "src_ip",
        ),
        "destination_ip": first_value(
            alert,
            "data.dstip",
            "data.dst_ip",
            "data.dest_ip",
            "data.destination.ip",
            "data.destination_ip",
            "data.win.eventdata.destinationIp",
            "destination.ip",
            "dstip",
            "dst_ip",
        ),
        "dst_ip": first_value(
            alert,
            "data.dstip",
            "data.dst_ip",
            "data.dest_ip",
            "data.destination.ip",
            "data.win.eventdata.destinationIp",
            "destination.ip",
            "dstip",
            "dst_ip",
        ),
        "username": first_value(
            alert,
            "data.srcuser",
            "data.dstuser",
            "data.user",
            "data.win.eventdata.targetUserName",
            "data.win.eventdata.user",
            "data.win.eventdata.subjectUserName",
            "data.audit.acct",
        ),
        "description": clean_scalar(rule.get("description")) or flat_rule_description or first_value(alert, "description", "message"),
        "rule_id": clean_scalar(rule.get("id")) or flat_rule_id,
        "rule_level": level,
        "rule_groups": ", ".join(groups) or None,
        "severity": severity_from_level(level),
        "mitre_technique": ", ".join(technique_ids) or None,
        "mitre_technique_name": ", ".join(technique_names) or None,
        "mitre_tactic": ", ".join(tactics) or None,
        "process": first_value(
            alert,
            "data.win.eventdata.image",
            "data.win.eventdata.newProcessName",
            "data.win.eventdata.processName",
            "data.audit.exe",
            "process",
        ),
        "command": first_value(
            alert,
            "data.win.eventdata.commandLine",
            "data.command",
            "data.audit.command",
            "command",
            "command_line",
        ),
        "command_line": first_value(
            alert,
            "data.win.eventdata.commandLine",
            "data.command",
            "data.audit.command",
            "command_line",
        ),
        "file_hash": _extract_hash(alert),
        "filename": first_value(
            alert,
            "syscheck.path",
            "data.path",
            "data.win.eventdata.targetFilename",
            "data.audit.file.name",
            "filename",
        ),
        "url": url,
        "domain": domain,
        "http_method": http_method,
        "http_status": http_status,
        "uri_path": uri_path,
        "uri_query": uri_query,
        "referer": first_value(alert, "data.referer", "referer"),
        "user_agent": first_value(alert, "data.user_agent", "user_agent"),
        "original_log": clean_scalar(alert.get("full_log")),
        "raw_event": alert,
        "wazuh_manager": clean_scalar(manager.get("name")),
    }


# FUNCTION: _env_int
# Purpose: Ye internal helper ka main kaam env int se related processing ko centrally handle karna hai.
# Input: name, default.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _env_int(name: str, default: int) -> int:
    # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


# FUNCTION: _clean_host
# Purpose: Ye internal helper clean host operation handle karta hai.
# Input: host.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _clean_host(host: str | None) -> str:
    value = re.sub(r"^https?://", "", (host or "").strip()).split("/")[0]
    # IPv6 literals ko preserve rakho; sirf simple host:port format ko clean/remove kiya jaata hai.
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if value.count(":") == 1:
        value = value.split(":")[0]
    return value


# CLASS: WazuhService
# Role: Ye class ka main kaam Wazuh Service se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class WazuhService:
    """Failure-safe client for the Wazuh Server API and Indexer."""

    TOKEN_TTL_SECONDS = 800

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: host, api_port, api_user, api_password, verify_ssl, indexer_port, indexer_user, indexer_password, timeout.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(
        self,
        host: str,
        api_port: int = 55000,
        api_user: str | None = None,
        api_password: str | None = None,
        verify_ssl: bool = True,
        indexer_port: int = 9200,
        indexer_user: str | None = None,
        indexer_password: str | None = None,
        timeout: int = 20,
    ) -> None:
        self.host = _clean_host(host)
        self.api_port = int(api_port)
        self.api_user = api_user or ""
        self.api_password = api_password or ""
        self.indexer_port = int(indexer_port)
        self.indexer_user = indexer_user or ""
        self.indexer_password = indexer_password or ""
        self.verify_ssl = bool(verify_ssl)
        self.timeout = timeout
        self._token: str | None = None
        self._token_expiry = 0.0

        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not self.verify_ssl and urllib3 is not None:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @classmethod
    # FUNCTION: from_env
    # Purpose: Ye function ka main kaam from env se related processing ko centrally handle karna hai.
    # Input: cls.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def from_env(cls):
        """Build a client directly from environment variables."""
        return cls(
            host=os.getenv("WAZUH_HOST", ""),
            api_port=_env_int("WAZUH_API_PORT", 55000),
            api_user=os.getenv("WAZUH_API_USER"),
            api_password=os.getenv("WAZUH_API_PASSWORD"),
            verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "true").strip().lower() == "true",
            indexer_port=_env_int("WAZUH_INDEXER_PORT", 9200),
            indexer_user=os.getenv("WAZUH_INDEXER_USER"),
            indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD"),
        )

    @classmethod
    # FUNCTION: from_settings
    # Purpose: Ye function ka main kaam from settings se related processing ko centrally handle karna hai.
    # Input: cls, settings.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def from_settings(cls, settings):
        return cls(
            host=settings.wazuh_host,
            api_port=settings.wazuh_api_port,
            api_user=settings.wazuh_api_user,
            api_password=settings.wazuh_api_password,
            verify_ssl=settings.wazuh_verify_ssl,
            indexer_port=settings.wazuh_indexer_port,
            indexer_user=settings.wazuh_indexer_user,
            indexer_password=settings.wazuh_indexer_password,
        )

    @property
    # FUNCTION: _api_base
    # Purpose: Ye internal helper ka main kaam api base se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _api_base(self) -> str:
        return f"https://{self.host}:{self.api_port}"

    @property
    # FUNCTION: _indexer_base
    # Purpose: Ye internal helper ka main kaam indexer base se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _indexer_base(self) -> str:
        return f"https://{self.host}:{self.indexer_port}"

    # FUNCTION: _require_api_config
    # Purpose: Ye internal helper ka main kaam require api config se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _require_api_config(self) -> None:
        missing = [name for name, value in {
            "WAZUH_HOST": self.host,
            "WAZUH_API_USER": self.api_user,
            "WAZUH_API_PASSWORD": self.api_password,
        }.items() if not value]
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if missing:
            raise WazuhError("Wazuh is not configured. Missing: " + ", ".join(missing) + ".")

    # FUNCTION: _require_indexer_config
    # Purpose: Ye internal helper ka main kaam require indexer config se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _require_indexer_config(self) -> None:
        missing = [name for name, value in {
            "WAZUH_HOST": self.host,
            "WAZUH_INDEXER_USER": self.indexer_user,
            "WAZUH_INDEXER_PASSWORD": self.indexer_password,
        }.items() if not value]
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if missing:
            raise WazuhError("Wazuh Indexer is not configured. Missing: " + ", ".join(missing) + ".")

    # FUNCTION: _send
    # Purpose: Ye internal helper ka main kaam send se related processing ko centrally handle karna hai.
    # Input: method, url, label, **kwargs.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _send(self, method: str, url: str, label: str, **kwargs):
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            return requests.request(method, url, verify=self.verify_ssl, timeout=self.timeout, **kwargs)
        except requests.exceptions.SSLError:
            raise WazuhError(f"{label}: TLS certificate verification failed. Check WAZUH_VERIFY_SSL.") from None
        except requests.exceptions.ConnectTimeout:
            raise WazuhError(f"{label}: connection timed out reaching {self.host}.") from None
        except requests.exceptions.ReadTimeout:
            raise WazuhError(f"{label}: response timed out from {self.host}.") from None
        except requests.exceptions.ConnectionError:
            raise WazuhError(f"{label}: cannot reach {self.host}. Check host, port and firewall.") from None
        except requests.exceptions.RequestException:
            raise WazuhError(f"{label}: request failed.") from None

    # FUNCTION: authenticate
    # Purpose: Ye function authenticate operation handle karta hai.
    # Input: force.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def authenticate(self, force: bool = False) -> str:
        """Request and cache a Wazuh Server API JWT."""
        self._require_api_config()
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not force and self._token and time.time() < self._token_expiry:
            return self._token
        response = self._send(
            "POST",
            f"{self._api_base}/security/user/authenticate",
            "Wazuh API",
            params={"raw": "true"},
            auth=(self.api_user, self.api_password),
        )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code == 401:
            raise WazuhError("Wazuh API authentication failed. Check WAZUH_API_USER and WAZUH_API_PASSWORD.")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code >= 400:
            raise WazuhError(f"Wazuh API returned HTTP {response.status_code} during authentication.")

        token = response.text.strip().strip('"')
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if token.startswith("{"):
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                token = str(response.json().get("data", {}).get("token", ""))
            except (ValueError, TypeError):
                token = ""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not token:
            raise WazuhError("Wazuh API did not return an authentication token.")

        self._token = token
        self._token_expiry = time.time() + self.TOKEN_TTL_SECONDS
        return token

    # FUNCTION: get_api_info
    # Purpose: Ye function get api info operation handle karta hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def get_api_info(self) -> dict[str, Any]:
        """Read basic Server API information using the cached JWT."""
        token = self.authenticate()
        response = self._send(
            "GET",
            f"{self._api_base}/",
            "Wazuh API",
            headers={"Authorization": f"Bearer {token}"},
        )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code == 401:
            token = self.authenticate(force=True)
            response = self._send(
                "GET",
                f"{self._api_base}/",
                "Wazuh API",
                headers={"Authorization": f"Bearer {token}"},
            )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code >= 400:
            raise WazuhError(f"Wazuh API returned HTTP {response.status_code} for GET /.")
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            data = response.json().get("data", {})
        except (ValueError, AttributeError):
            raise WazuhError("Wazuh API returned an unreadable response for GET /.") from None
        return data if isinstance(data, dict) else {}

    # FUNCTION: _indexer_request
    # Purpose: Ye internal helper ka main kaam indexer request se related processing ko centrally handle karna hai.
    # Input: method, path, **kwargs.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _indexer_request(self, method: str, path: str, **kwargs):
        self._require_indexer_config()
        response = self._send(
            method,
            f"{self._indexer_base}{path}",
            "Wazuh Indexer",
            auth=(self.indexer_user, self.indexer_password),
            **kwargs,
        )
        messages = {
            401: "Wazuh Indexer authentication failed. Check WAZUH_INDEXER_USER/PASSWORD.",
            403: "Wazuh Indexer access denied for this user.",
            404: "Wazuh Indexer endpoint or wazuh-alerts-* index was not found.",
        }
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code in messages:
            raise WazuhError(messages[response.status_code])
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code >= 400:
            raise WazuhError(f"Wazuh Indexer returned HTTP {response.status_code}.")
        return response

    # FUNCTION: get_indexer_info
    # Purpose: Ye function get indexer info operation handle karta hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def get_indexer_info(self) -> str | None:
        """Read the Indexer version, mainly for a connection check."""
        response = self._indexer_request("GET", "/")
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            body = response.json()
            return (body.get("version") or {}).get("number") if isinstance(body, dict) else None
        except (ValueError, AttributeError):
            return None

    # FUNCTION: test_connection
    # Purpose: Ye function test connection operation handle karta hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def test_connection(self) -> dict[str, Any]:
        """Test Server API and Indexer independently and return a safe status object."""
        result = {
            "connected": False,
            "api_ok": False,
            "indexer_ok": False,
            "api_version": None,
            "indexer_version": None,
            "message": "Wazuh Connection Failed",
            "details": [],
        }
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            info = self.get_api_info()
            result["api_ok"] = True
            result["api_version"] = info.get("api_version")
            result["details"].append("Server API: OK")
        except WazuhError as exc:
            result["details"].append(f"Server API: {exc}")

        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            result["indexer_version"] = self.get_indexer_info()
            result["indexer_ok"] = True
            result["details"].append("Indexer: OK")
        except WazuhError as exc:
            result["details"].append(f"Indexer: {exc}")

        result["connected"] = result["api_ok"] and result["indexer_ok"]
        result["message"] = "Wazuh Connected" if result["connected"] else "Wazuh Connection Failed"
        return result

    # FUNCTION: fetch_alerts
    # Purpose: Ye function fetch alerts operation handle karta hai.
    # Input: limit, lookback, min_level.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def fetch_alerts(self, limit: int = 100, lookback: str = "24h", min_level: int | None = None) -> list[dict[str, Any]]:
        """Fetch raw Wazuh Indexer hits; normalization remains in the common pipeline."""
        self._require_api_config()
        self._require_indexer_config()
        limit = max(1, min(int(limit), 1000))
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not re.fullmatch(r"\d{1,4}[smhdw]", str(lookback)):
            raise WazuhError("Invalid lookback window. Use values such as 1h, 24h or 7d.")

        filters = [{"range": {"@timestamp": {"gte": f"now-{lookback}"}}}]
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if min_level is not None:
            filters.append({"range": {"rule.level": {"gte": int(min_level)}}})

        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"bool": {"filter": filters}},
        }
        response = self._indexer_request("POST", "/wazuh-alerts-*/_search", json=body)
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            payload = response.json()
        except ValueError:
            raise WazuhError("Wazuh Indexer returned an unreadable JSON response.") from None

        hits = payload.get("hits", {}).get("hits", []) if isinstance(payload, dict) else []
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if hits is None:
            return []
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not isinstance(hits, list):
            raise WazuhError("Wazuh Indexer returned an unexpected alerts structure.")
        return [hit for hit in hits if isinstance(hit, dict)]
