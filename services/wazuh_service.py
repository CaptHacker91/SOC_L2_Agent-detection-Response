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

import gzip
import io
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import boto3
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
    """Failure-safe Wazuh Cloud client with normalized alert output."""

    CLOUD_API_DEFAULT = "https://api.cloud.wazuh.com"
    TOKEN_TTL_SECONDS = 3000

    def __init__(
        self,
        cloud_api_key=None,
        cloud_id=None,
        api_host=None,
        verify_ssl=True,
        timeout=30,
    ):
        self.cloud_api_key = (cloud_api_key or "").strip()
        self.cloud_id = (cloud_id or "").strip()
        self.api_host = (api_host or self.CLOUD_API_DEFAULT).rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout

        self._storage = None
        self._storage_expiry = 0.0

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @classmethod
    def from_env(cls):
        """Build the service from Wazuh Cloud environment variables."""
        return cls(
            cloud_api_key=os.getenv("WAZUH_CLOUD_API_KEY"),
            cloud_id=os.getenv("WAZUH_CLOUD_ID"),
            api_host=os.getenv("WAZUH_CLOUD_API_HOST", cls.CLOUD_API_DEFAULT),
            verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "true").strip().lower() == "true",
            timeout=_env_int("WAZUH_TIMEOUT", 30),
        )

    # ---- plumbing -------------------------------------------------------

    def _require_config(self):
        missing = []
        if not self.cloud_api_key:
            missing.append("WAZUH_CLOUD_API_KEY")
        if not self.cloud_id:
            missing.append("WAZUH_CLOUD_ID")
        if missing:
            raise WazuhError(
                "Wazuh Cloud is not configured. Set " + ", ".join(missing) + " in .env."
            )

    def _send(self, method, url, label, **kwargs):
        """One HTTP call with network failures mapped to safe WazuhError messages."""
        try:
            return requests.request(
                method,
                url,
                verify=self.verify_ssl,
                timeout=self.timeout,
                **kwargs,
            )
        except requests.exceptions.SSLError:
            raise WazuhError(
                f"{label}: TLS certificate verification failed. Check WAZUH_VERIFY_SSL."
            ) from None
        except requests.exceptions.ConnectTimeout:
            raise WazuhError(f"{label}: connection timed out.") from None
        except requests.exceptions.ReadTimeout:
            raise WazuhError(f"{label}: no response (read timed out).") from None
        except requests.exceptions.ConnectionError:
            raise WazuhError(f"{label}: cannot reach Wazuh Cloud API.") from None
        except requests.exceptions.RequestException:
            raise WazuhError(f"{label}: request failed.") from None

    def _cloud_headers(self):
        return {
            "x-api-key": self.cloud_api_key,
            "Accept": "application/json",
        }

    # ---- Wazuh Cloud API ------------------------------------------------

    def get_cloud_info(self):
        """Return Wazuh Cloud API information."""
        self._require_config()
        response = self._send(
            "GET",
            f"{self.api_host}/v2/info",
            "Wazuh Cloud API",
            headers=self._cloud_headers(),
        )
        if response.status_code == 401:
            raise WazuhError("Wazuh Cloud API key authentication failed.")
        if response.status_code >= 400:
            raise WazuhError(
                f"Wazuh Cloud API returned HTTP {response.status_code} for /v2/info."
            )
        try:
            return response.json() or {}
        except ValueError:
            raise WazuhError("Wazuh Cloud API returned an unreadable /v2/info response.") from None

    def _get_storage_credentials(self, force=False):
        """Get and cache temporary AWS credentials for Wazuh Cloud archive data."""
        self._require_config()

        if (
            not force
            and self._storage
            and time.time() < self._storage_expiry
        ):
            return self._storage

        response = self._send(
            "POST",
            f"{self.api_host}/v2/storage/token",
            "Wazuh Cloud archive",
            headers={
                **self._cloud_headers(),
                "Content-Type": "application/json",
            },
            json={
                "environment_cloud_id": self.cloud_id,
                "token_expiration": "3600",
            },
        )

        if response.status_code == 401:
            raise WazuhError("Wazuh Cloud API key authentication failed for archive access.")
        if response.status_code >= 400:
            raise WazuhError(
                f"Wazuh Cloud archive token request returned HTTP {response.status_code}."
            )

        try:
            payload = response.json()
            aws = payload["aws"]
            creds = aws["credentials"]
            storage = {
                "bucket": aws["s3_path"].split("/", 1)[0],
                "prefix": aws["s3_path"].split("/", 1)[1].rstrip("/")
                if "/" in aws["s3_path"]
                else "",
                "region": aws["region"],
                "access_key_id": creds["access_key_id"],
                "secret_access_key": creds["secret_access_key"],
                "session_token": creds["session_token"],
            }
        except (KeyError, TypeError, ValueError):
            raise WazuhError("Wazuh Cloud returned an invalid archive token response.") from None

        self._storage = storage
        self._storage_expiry = time.time() + min(
            3000, max(60, int(creds.get("expires_in", 3600)) - 60)
        )
        return storage

    def _s3_client(self):
        storage = self._get_storage_credentials()
        try:
            return boto3.client(
                "s3",
                region_name=storage["region"],
                aws_access_key_id=storage["access_key_id"],
                aws_secret_access_key=storage["secret_access_key"],
                aws_session_token=storage["session_token"],
            )
        except Exception:
            raise WazuhError("Could not initialize Wazuh Cloud archive storage access.") from None

    # ---- File mode (offline alerts file) -------------------------------

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
                parsed = (
                    parsed.get("hits", {}).get("hits", [parsed])
                    if "hits" in parsed
                    else [parsed]
                )
            records = [r for r in parsed if isinstance(r, dict)]
        except json.JSONDecodeError:
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

    # ---- Archive parsing ------------------------------------------------

    @staticmethod
    def _parse_archive_bytes(raw_bytes):
        """Parse a Wazuh JSON.gz archive object into alert dictionaries."""
        try:
            text = gzip.GzipFile(fileobj=io.BytesIO(raw_bytes)).read().decode(
                "utf-8", errors="replace"
            )
        except (OSError, EOFError):
            raise WazuhError("Wazuh Cloud returned an unreadable compressed archive file.") from None

        records = []

        # Archive output is JSON text; support both JSONL and a JSON array/object.
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                records.extend(r for r in parsed if isinstance(r, dict))
            elif isinstance(parsed, dict):
                if isinstance(parsed.get("hits"), dict):
                    records.extend(parsed["hits"].get("hits", []))
                else:
                    records.append(parsed)
            return records
        except json.JSONDecodeError:
            pass

        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if isinstance(record, dict):
                    records.append(record)
            except json.JSONDecodeError:
                continue

        return records

    @staticmethod
    def _lookback_timedelta(lookback):
        match = _LOOKBACK_RE.match(str(lookback))
        if not match:
            raise WazuhError("Invalid lookback window (use e.g. 1h, 24h, 7d, 30d).")

        amount = int(str(lookback)[:-1])
        unit = str(lookback)[-1]
        return {
            "s": timedelta(seconds=amount),
            "m": timedelta(minutes=amount),
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
            "w": timedelta(weeks=amount),
        }[unit]

    def _archive_keys(self, start_dt, end_dt):
        storage = self._get_storage_credentials()
        prefix_base = storage["prefix"].rstrip("/")

        current = datetime(start_dt.year, start_dt.month, start_dt.day, tzinfo=timezone.utc)
        end_day = datetime(end_dt.year, end_dt.month, end_dt.day, tzinfo=timezone.utc)

        while current <= end_day:
            prefix = (
                f"{prefix_base}/output/alerts/"
                f"{current.year:04d}/{current.month:02d}/{current.day:02d}/"
            )
            yield prefix
            current += timedelta(days=1)

    def _load_archive_events(self, limit, lookback):
        now = datetime.now(timezone.utc)
        start = now - self._lookback_timedelta(lookback)
        s3 = self._s3_client()
        storage = self._get_storage_credentials()

        objects = []
        try:
            for prefix in self._archive_keys(start, now):
                continuation = None
                while True:
                    kwargs = {
                        "Bucket": storage["bucket"],
                        "Prefix": prefix,
                    }
                    if continuation:
                        kwargs["ContinuationToken"] = continuation

                    page = s3.list_objects_v2(**kwargs)
                    objects.extend(
                        obj
                        for obj in page.get("Contents", [])
                        if str(obj.get("Key", "")).endswith(".json.gz")
                    )

                    if not page.get("IsTruncated"):
                        break
                    continuation = page.get("NextContinuationToken")
                    if not continuation:
                        break
        except Exception:
            raise WazuhError("Could not list Wazuh Cloud archive alerts.") from None

        objects.sort(key=lambda obj: obj.get("LastModified") or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

        records = []
        # Download newest files first. A file may contain many events.
        for obj in objects:
            try:
                response = s3.get_object(Bucket=storage["bucket"], Key=obj["Key"])
                records.extend(self._parse_archive_bytes(response["Body"].read()))
            except Exception:
                continue

            if len(records) >= limit * 3:
                break

        events = []
        for record in records:
            event = normalize_wazuh_alert(record)
            timestamp = event.get("timestamp")

            # Keep records that are inside the requested window when a valid timestamp exists.
            if timestamp:
                try:
                    ts = str(timestamp).replace("Z", "+00:00")
                    parsed_ts = datetime.fromisoformat(ts)
                    if parsed_ts.tzinfo is None:
                        parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
                    if parsed_ts < start or parsed_ts > now + timedelta(minutes=5):
                        continue
                except ValueError:
                    pass

            events.append(event)

        events.sort(key=lambda e: e.get("timestamp") or "", reverse=True)
        return events[:limit]

    # ---- Public operations ---------------------------------------------

    def test_connection(self):
        """
        Never raises. Returns a status dictionary compatible with the existing UI.
        """
        result = {
            "connected": False,
            "api_ok": False,
            "indexer_ok": False,
            "api_version": None,
            "message": "",
            "details": [],
        }

        if self.file_mode():
            result.update(
                connected=True,
                api_ok=True,
                indexer_ok=True,
                message="Wazuh Connected (file mode)",
                details=[f"File mode: reading {self.events_path()}"],
            )
            return result

        try:
            info = self.get_cloud_info()
            result["api_ok"] = True
            result["api_version"] = info.get("version")
            result["details"].append("Wazuh Cloud API: OK")

            # Also validate that archive access is available.
            self._get_storage_credentials()
            result["indexer_ok"] = True
            result["details"].append("Wazuh Cloud archive: OK")
            result["connected"] = True
            result["message"] = "Wazuh Cloud Connected"
        except WazuhError as exc:
            result["details"].append(str(exc))
            result["message"] = "Wazuh Cloud Connection Failed"

        return result

    def fetch_alerts(self, limit=100, lookback="24h", min_level=None):
        """
        Fetch recent real Wazuh alerts from Wazuh Cloud archive data.

        Wazuh Cloud archive files are JSON.gz objects delivered to AWS S3.
        """
        if self.file_mode():
            return self.load_file_events(limit)

        limit = max(1, min(int(limit), 1000))
        events = self._load_archive_events(limit=max(limit * 2, limit), lookback=lookback)

        if min_level is not None:
            events = [
                event
                for event in events
                if (event.get("rule_level") or 0) >= int(min_level)
            ]

        return events[:limit]
