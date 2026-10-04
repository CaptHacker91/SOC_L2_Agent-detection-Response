"""
Wazuh integration service.

This is the ONLY module in the project that knows Wazuh's API layout and
Wazuh's field names. Everything it returns to the rest of the application
follows a Wazuh-independent "normalized event contract" (see
CONTRACT_FIELDS below), so parser / normalizer / engines / UI never touch
Wazuh-specific keys.

Two Wazuh components are involved (both over HTTPS):

  * Server API  (default :55000) - JWT authentication + manager info. Used
    for the connection test:  POST /security/user/authenticate  ->  JWT,
    then  GET /  with  Authorization: Bearer <JWT>.
  * Indexer API (default :9200)  - where Wazuh actually STORES alerts
    (wazuh-alerts-* indices). The Server API has no "list alerts"
    endpoint, so real alerts are fetched with  POST /wazuh-alerts-*/_search.
    The Indexer has its own credentials (e.g. the 'admin' indexer user),
    separate from the Server API user.

Security notes:
  * Credentials are read from environment variables only (never hardcoded)
    and are used server-side only - nothing here is ever sent to the browser.
  * Every error raised is a WazuhError with a message that is safe to show
    in the UI: it never contains passwords, tokens or raw exception text.
  * Nothing is fabricated: any field that is not present in the Wazuh alert
    is None in the normalized event.
"""

import json
import os
import re
import time
from urllib.parse import urlsplit

import requests
import urllib3


class WazuhError(Exception):
    """A failure talking to Wazuh. The message is always safe to display."""


# --------------------------------------------------------------------------
# Normalized event contract (Wazuh-independent)
# --------------------------------------------------------------------------

# The contract required by the SOC pipeline.
CONTRACT_FIELDS = (
    "id", "timestamp", "source", "host", "event_type", "severity",
    "src_ip", "username", "raw_event", "description", "rule_id",
    "mitre_technique",
)

# Optional, source-independent enrichment. Always present as keys, value is
# None whenever the telemetry does not contain the information.
OPTIONAL_FIELDS = (
    "mitre_technique_name", "mitre_tactic", "rule_level", "rule_groups",
    "dst_ip", "process", "command_line", "file_hash", "filename",
    "url", "domain", "http_method", "http_status", "original_log",
)

_PLACEHOLDERS = {"", "-", "n/a", "na", "null", "none", "unknown", "(null)"}
_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"}
_WEB_GROUPS = {"web", "accesslog", "apache", "nginx", "iis", "web-log"}
_LOOKBACK_RE = re.compile(r"^\d{1,4}[smhdw]$")
_HASH_RE = re.compile(r"(SHA256|SHA1|MD5)=([A-Fa-f0-9]{32,64})", re.IGNORECASE)


def severity_from_level(level):
    """
    Wazuh rule level (0-15) -> severity label.

    Same bands as SeverityEngine (level/15*10 -> 0-3.9 Low, 4-6.9 Medium,
    7-8.9 High, 9+ Critical): 0-5 Low, 6-10 Medium, 11-13 High, 14-15 Critical.
    SeverityEngine remains the authority inside the app; this label just
    keeps the contract self-contained.
    """
    if level is None:
        return None
    if level >= 14:
        return "Critical"
    if level >= 11:
        return "High"
    if level >= 6:
        return "Medium"
    return "Low"


# --------------------------------------------------------------------------
# Small helpers for reading nested alert JSON safely
# --------------------------------------------------------------------------

def _scalar(value):
    """Return a cleaned string for a scalar value, or None for missing/placeholder values."""
    if value is None or isinstance(value, (dict, list, tuple, set)):
        return None
    text = str(value).strip()
    return None if text.lower() in _PLACEHOLDERS else text


def _dig(obj, path):
    """Walk 'a.b.c' through nested dicts; key matching is case-insensitive."""
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        if part in cur:
            cur = cur[part]
            continue
        lowered = part.lower()
        for key, val in cur.items():
            if str(key).lower() == lowered:
                cur = val
                break
        else:
            return None
    return cur


def _first(obj, *paths):
    """First non-placeholder scalar found among the given paths, else None."""
    for path in paths:
        value = _scalar(_dig(obj, path))
        if value is not None:
            return value
    return None


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if _scalar(v) is not None]
    text = _scalar(value)
    return [text] if text else []


def _to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_hash(alert):
    """Best hash present in the alert (sha256 > sha1 > md5), or None."""
    for path in ("syscheck.sha256_after", "syscheck.sha1_after", "syscheck.md5_after"):
        value = _first(alert, path)
        if value:
            return value
    hashes = _first(alert, "data.win.eventdata.hashes")
    if hashes:
        found = {m.group(1).upper(): m.group(2) for m in _HASH_RE.finditer(hashes)}
        for kind in ("SHA256", "SHA1", "MD5"):
            if kind in found:
                return found[kind]
    return None


def normalize_wazuh_alert(hit):
    """
    Convert ONE Indexer search hit (or a bare alert document) into the
    normalized event contract. Only values actually present in the alert are
    used - anything missing stays None.
    """
    alert = hit.get("_source", hit) if isinstance(hit, dict) else {}
    if not isinstance(alert, dict):
        alert = {}

    rule = alert.get("rule") if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent") if isinstance(alert.get("agent"), dict) else {}
    mitre = rule.get("mitre") if isinstance(rule.get("mitre"), dict) else {}
    if not mitre and isinstance(alert.get("mitre"), dict):  # top-level mitre (sample file)
        mitre = alert["mitre"]

    level = _to_int(rule.get("level"))
    groups = _as_list(rule.get("groups"))
    technique_ids = _as_list(mitre.get("id"))
    technique_names = _as_list(mitre.get("technique"))
    tactics = _as_list(mitre.get("tactic"))

    url = _first(alert, "data.url")
    domain = _first(alert, "data.win.eventdata.queryName")
    if not domain and url:
        parts = urlsplit(url)
        domain = parts.hostname if parts.scheme and parts.hostname else None

    protocol = _first(alert, "data.protocol")
    http_method = protocol.upper() if protocol and protocol.upper() in _HTTP_METHODS else None

    http_status = None
    if _WEB_GROUPS.intersection(g.lower() for g in groups):
        candidate = _to_int(_first(alert, "data.id"))
        if candidate is not None and 100 <= candidate <= 599:
            http_status = candidate

    event_id = _scalar(alert.get("id")) or _scalar(hit.get("_id") if isinstance(hit, dict) else None)

    return {
        # ---- contract ----
        "id": event_id,
        "timestamp": _scalar(alert.get("timestamp")) or _scalar(alert.get("@timestamp")),
        "source": "wazuh",
        "host": _scalar(agent.get("name")) or _scalar(agent.get("id")),
        "event_type": groups[0] if groups else _first(alert, "decoder.name"),
        "severity": severity_from_level(level),
        "src_ip": _first(alert, "data.srcip", "data.src_ip", "data.win.eventdata.ipAddress",
                         "data.win.eventdata.sourceIp"),
        "username": _first(alert, "data.srcuser", "data.dstuser", "data.win.eventdata.targetUserName",
                           "data.win.eventdata.user", "data.win.eventdata.subjectUserName",
                           "data.audit.acct"),
        "raw_event": alert,
        "description": _scalar(rule.get("description")),
        "rule_id": _scalar(rule.get("id")),
        "mitre_technique": ", ".join(technique_ids) or None,
        # ---- optional enrichment ----
        "mitre_technique_name": ", ".join(technique_names) or None,
        "mitre_tactic": ", ".join(tactics) or None,
        "rule_level": level,
        "rule_groups": ", ".join(groups) or None,
        "dst_ip": _first(alert, "data.dstip", "data.dest_ip", "data.win.eventdata.destinationIp"),
        "process": _first(alert, "data.win.eventdata.image", "data.win.eventdata.newProcessName",
                          "data.win.eventdata.processName", "data.audit.exe"),
        "command_line": _first(alert, "data.win.eventdata.commandLine", "data.command",
                               "data.audit.command"),
        "file_hash": _extract_hash(alert),
        "filename": _first(alert, "syscheck.path", "data.win.eventdata.targetFilename",
                           "data.audit.file.name"),
        "url": url,
        "domain": domain,
        "http_method": http_method,
        "http_status": http_status,
        "original_log": _scalar(alert.get("full_log")),
    }


# --------------------------------------------------------------------------
# Service
# --------------------------------------------------------------------------

def _env_int(name, default):
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _clean_host(host):
    host = re.sub(r"^https?://", "", (host or "").strip()).split("/")[0]
    if host.count(":") == 1:  # host:port typed by mistake (not an IPv6 literal)
        host = host.split(":")[0]
    return host


class WazuhService:
    """Authenticated, failure-safe client for the Wazuh Server API and Indexer."""

    TOKEN_TTL_SECONDS = 800  # Wazuh's default JWT lifetime is 900s

    def __init__(self, host, api_port=55000, api_user=None, api_password=None,
                 verify_ssl=False, indexer_port=9200, indexer_user=None,
                 indexer_password=None, timeout=20):
        self.host = _clean_host(host)
        self.api_port = api_port
        self.api_user = api_user or ""
        self.api_password = api_password or ""
        # The Indexer has its own users; fall back to the API user only so a
        # single-credential setup gets a clear "auth failed" message.
        self.indexer_port = indexer_port
        self.indexer_user = indexer_user or self.api_user
        self.indexer_password = indexer_password or self.api_password
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._token = None
        self._token_expiry = 0.0

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @classmethod
    def from_env(cls):
        """Build the service from environment variables (see .env.example)."""
        return cls(
            host=os.getenv("WAZUH_HOST", ""),
            api_port=_env_int("WAZUH_API_PORT", 55000),
            api_user=os.getenv("WAZUH_API_USER"),
            api_password=os.getenv("WAZUH_API_PASSWORD"),
            verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "false").strip().lower() == "true",
            indexer_port=_env_int("WAZUH_INDEXER_PORT", 9200),
            indexer_user=os.getenv("WAZUH_INDEXER_USER") or None,
            indexer_password=os.getenv("WAZUH_INDEXER_PASSWORD") or None,
        )

    # ---- plumbing -------------------------------------------------------

    @property
    def _api_base(self):
        return f"https://{self.host}:{self.api_port}"

    @property
    def _indexer_base(self):
        return f"https://{self.host}:{self.indexer_port}"

    def _require_config(self):
        if not self.host or not self.api_user or not self.api_password:
            raise WazuhError(
                "Wazuh is not configured. Set WAZUH_HOST, WAZUH_API_USER and "
                "WAZUH_API_PASSWORD in your .env file."
            )

    def _send(self, method, url, label, **kwargs):
        """One HTTP call with every network failure mapped to a safe WazuhError."""
        try:
            return requests.request(method, url, verify=self.verify_ssl,
                                    timeout=self.timeout, **kwargs)
        except requests.exceptions.SSLError:
            raise WazuhError(
                f"{label}: TLS certificate verification failed. Set WAZUH_VERIFY_SSL=false "
                "for self-signed certificates."
            ) from None
        except requests.exceptions.ConnectTimeout:
            raise WazuhError(f"{label}: connection timed out reaching {self.host}.") from None
        except requests.exceptions.ReadTimeout:
            raise WazuhError(f"{label}: no response from {self.host} (read timed out).") from None
        except requests.exceptions.ConnectionError:
            raise WazuhError(f"{label}: cannot reach {self.host} (check WAZUH_HOST, port and firewall).") from None
        except requests.exceptions.RequestException:
            raise WazuhError(f"{label}: request failed.") from None

    # ---- Server API -----------------------------------------------------

    def authenticate(self, force=False):
        """Obtain (and cache) a JWT from the Wazuh Server API."""
        self._require_config()
        if not force and self._token and time.time() < self._token_expiry:
            return self._token

        response = self._send(
            "POST", f"{self._api_base}/security/user/authenticate", "Wazuh API",
            params={"raw": "true"}, auth=(self.api_user, self.api_password),
        )
        if response.status_code == 401:
            raise WazuhError("Wazuh API authentication failed - check WAZUH_API_USER / WAZUH_API_PASSWORD.")
        if response.status_code != 200:
            raise WazuhError(f"Wazuh API returned HTTP {response.status_code} during authentication.")

        token = response.text.strip().strip('"')
        if token.startswith("{"):  # server ignored raw=true and returned JSON
            try:
                token = response.json().get("data", {}).get("token", "")
            except ValueError:
                token = ""
        if not token:
            raise WazuhError("Wazuh API did not return a token.")

        self._token = token
        self._token_expiry = time.time() + self.TOKEN_TTL_SECONDS
        return token

    def get_api_info(self):
        """GET / on the Server API with the JWT. Returns the 'data' block (title, api_version, ...)."""
        token = self.authenticate()
        for attempt in (1, 2):
            response = self._send("GET", f"{self._api_base}/", "Wazuh API",
                                  headers={"Authorization": f"Bearer {token}"})
            if response.status_code == 401 and attempt == 1:  # token expired early
                token = self.authenticate(force=True)
                continue
            break
        if response.status_code != 200:
            raise WazuhError(f"Wazuh API returned HTTP {response.status_code} for GET /.")
        try:
            return response.json().get("data", {}) or {}
        except ValueError:
            raise WazuhError("Wazuh API returned an unreadable response for GET /.") from None

    # ---- Indexer --------------------------------------------------------

    def _indexer_request(self, method, path, **kwargs):
        response = self._send(method, f"{self._indexer_base}{path}", "Wazuh Indexer",
                              auth=(self.indexer_user, self.indexer_password), **kwargs)
        if response.status_code == 401:
            raise WazuhError(
                "Wazuh Indexer authentication failed - set WAZUH_INDEXER_USER / WAZUH_INDEXER_PASSWORD "
                "(the Indexer uses its own credentials, e.g. the 'admin' user, not the Server API user)."
            )
        if response.status_code == 403:
            raise WazuhError("Wazuh Indexer user is not allowed to read wazuh-alerts-*.")
        if response.status_code == 404:
            raise WazuhError("No wazuh-alerts-* index found on the Wazuh Indexer yet.")
        if response.status_code >= 400:
            raise WazuhError(f"Wazuh Indexer returned HTTP {response.status_code}.")
        return response

    def get_indexer_info(self):
        """GET / on the Indexer (requires auth). Returns the version number, or None."""
        response = self._indexer_request("GET", "/")
        try:
            return (response.json().get("version") or {}).get("number")
        except ValueError:
            return None

    # ---- File mode (offline alerts file, no Wazuh server needed) ----------

    @staticmethod
    def file_mode():
        return os.getenv("WAZUH_SOURCE", "api").strip().lower() == "file"

    @staticmethod
    def events_path():
        return os.getenv("WAZUH_EVENTS_FILE", "data/wazuh_events.json")

    def load_file_events(self, limit=100):
        path = self.events_path()
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read().strip()
        except OSError:
            raise WazuhError(f"Events file not found or unreadable: {path}") from None

        records = []
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                parsed = parsed.get("hits", {}).get("hits", [parsed]) if "hits" in parsed else [parsed]
            records = [r for r in parsed if isinstance(r, dict)]
        except json.JSONDecodeError:  # JSONL: one alert per line
            for line in text.splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        events = [normalize_wazuh_alert(r) for r in records]
        events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
        return events[: max(1, min(int(limit), 1000))]

    # ---- Public operations ----------------------------------------------

    def test_connection(self):
        """
        Never raises. Returns:
            {"connected": bool, "api_ok": bool, "indexer_ok": bool,
             "api_version": str|None, "message": str, "details": [str, ...]}
        'connected' is True only if BOTH the Server API (JWT) and the Indexer work,
        because alerts cannot be fetched otherwise.
        """
        result = {"connected": False, "api_ok": False, "indexer_ok": False,
                  "api_version": None, "message": "", "details": []}
        if self.file_mode():
            result.update(connected=True, api_ok=True, indexer_ok=True,
                          message="Wazuh Connected (file mode)",
                          details=[f"File mode: reading {self.events_path()}"])
            return result
        try:
            info = self.get_api_info()
            result["api_ok"] = True
            result["api_version"] = info.get("api_version")
            result["details"].append("Server API: OK")
        except WazuhError as exc:
            result["details"].append(f"Server API: {exc}")

        if self.host:
            try:
                self.get_indexer_info()
                result["indexer_ok"] = True
                result["details"].append("Indexer: OK")
            except WazuhError as exc:
                result["details"].append(f"Indexer: {exc}")

        result["connected"] = result["api_ok"] and result["indexer_ok"]
        result["message"] = "Wazuh Connected" if result["connected"] else "Wazuh Connection Failed"
        return result

    def fetch_alerts(self, limit=100, lookback="24h", min_level=None):
        """
        Fetch real alerts from the Indexer (newest first) and return them as
        normalized events. Raises WazuhError on any failure.
        """
        if self.file_mode():
            return self.load_file_events(limit)
        self._require_config()
        limit = max(1, min(int(limit), 1000))
        if not _LOOKBACK_RE.match(str(lookback)):
            raise WazuhError("Invalid lookback window (use e.g. 1h, 24h, 7d).")

        filters = [{"range": {"@timestamp": {"gte": f"now-{lookback}"}}}]
        if min_level is not None:
            filters.append({"range": {"rule.level": {"gte": int(min_level)}}})
        body = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
            "query": {"bool": {"filter": filters}},
        }

        response = self._indexer_request("POST", "/wazuh-alerts-*/_search", json=body)
        try:
            hits = response.json().get("hits", {}).get("hits", [])
        except ValueError:
            raise WazuhError("Wazuh Indexer returned an unreadable response.") from None

        return [normalize_wazuh_alert(hit) for hit in hits]
