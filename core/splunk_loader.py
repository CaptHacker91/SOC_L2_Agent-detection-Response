"""Splunk REST search client used by the common SOC pipeline."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Splunk REST API se search results securely fetch karta hai aur errors ko readable form me convert karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import requests


# CLASS: SplunkError
# Role: Ye class ka main kaam Splunk Error se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class SplunkError(Exception):
    """Safe, user-facing Splunk integration error."""


# CLASS: SplunkLoader
# Role: Ye class ka main kaam Splunk Loader se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class SplunkLoader:
    """Fetch Splunk search results through the oneshot REST API."""

    # FUNCTION: __init__
    # Purpose: Ye function ka main kaam init se related processing ko centrally handle karna hai.
    # Input: host, port, token, search_query, verify_ssl, timeout.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def __init__(self, host, port=8089, token="", search_query="", verify_ssl=True, timeout=20):
        self.host = (host or "").strip().removeprefix("https://").removeprefix("http://").rstrip("/")
        self.port = int(port)
        self.token = token or ""
        self.search_query = (search_query or "").strip()
        self.verify_ssl = bool(verify_ssl)
        self.timeout = timeout

    @classmethod
    # FUNCTION: from_settings
    # Purpose: Ye function ka main kaam from settings se related processing ko centrally handle karna hai.
    # Input: cls, settings.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def from_settings(cls, settings):
        return cls(
            host=settings.splunk_host,
            port=settings.splunk_port,
            token=settings.splunk_token,
            search_query=settings.splunk_search_query,
            verify_ssl=settings.splunk_verify_ssl,
        )

    @property
    # FUNCTION: search_url
    # Purpose: Ye function search url operation handle karta hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def search_url(self):
        return f"https://{self.host}:{self.port}/services/search/jobs"

    @property
    # FUNCTION: management_url
    # Purpose: Ye function ka main kaam management url se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def management_url(self):
        return f"https://{self.host}:{self.port}/services/server/info?output_mode=json"

    # FUNCTION: _require_config
    # Purpose: Ye internal helper ka main kaam require config se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _require_config(self):
        missing = [name for name, value in {
            "SPLUNK_HOST": self.host,
            "SPLUNK_TOKEN": self.token,
            "SPLUNK_SEARCH_QUERY": self.search_query,
        }.items() if not value]
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if missing:
            raise SplunkError("Splunk is not configured. Missing: " + ", ".join(missing) + ".")

    # FUNCTION: _request
    # Purpose: Ye internal helper ka main kaam request se related processing ko centrally handle karna hai.
    # Input: method, url, **kwargs.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def _request(self, method, url, **kwargs):
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            return requests.request(
                method,
                url,
                headers={"Authorization": f"Bearer {self.token}"},
                verify=self.verify_ssl,
                timeout=self.timeout,
                **kwargs,
            )
        except requests.exceptions.SSLError:
            raise SplunkError("Splunk TLS certificate verification failed. Check SPLUNK_VERIFY_SSL.") from None
        except requests.exceptions.ConnectTimeout:
            raise SplunkError(f"Splunk connection timed out reaching {self.host}.") from None
        except requests.exceptions.ReadTimeout:
            raise SplunkError(f"Splunk response timed out from {self.host}.") from None
        except requests.exceptions.ConnectionError:
            raise SplunkError(f"Cannot reach Splunk at {self.host}. Check host, port and firewall.") from None
        except requests.exceptions.RequestException:
            raise SplunkError("Splunk request failed.") from None

    # FUNCTION: test_connection
    # Purpose: Ye function test connection operation handle karta hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def test_connection(self) -> dict:
        """Test Splunk management API without executing the configured search."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not self.host or not self.token:
            return {"connected": False, "message": "Splunk is not configured.", "details": []}
        response = self._request("GET", self.management_url)
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code == 401:
            return {"connected": False, "message": "Splunk authentication failed.", "details": []}
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code == 403:
            return {"connected": False, "message": "Splunk access denied.", "details": []}
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code >= 400:
            return {"connected": False, "message": f"Splunk returned HTTP {response.status_code}.", "details": []}
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            body = response.json()
            version = (body.get("entry") or [{}])[0].get("content", {}).get("version")
        except (ValueError, AttributeError, IndexError, TypeError):
            version = None
        return {"connected": True, "message": "Splunk Connected", "details": [f"Management API: OK{f' (v{version})' if version else ''}"]}

    # FUNCTION: load
    # Purpose: Ye function load operation handle karta hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def load(self):
        """Run the configured search and return raw Splunk result dictionaries."""
        self._require_config()
        query = self.search_query if self.search_query.lower().startswith("search") else f"search {self.search_query}"
        response = self._request(
            "POST",
            self.search_url,
            data={"search": query, "output_mode": "json", "exec_mode": "oneshot"},
        )
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code == 401:
            raise SplunkError("Splunk authentication failed. Check SPLUNK_TOKEN.")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code == 403:
            raise SplunkError("Splunk search access denied for this token.")
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if response.status_code >= 400:
            raise SplunkError(f"Splunk returned HTTP {response.status_code} for the search.")
        # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
        try:
            payload = response.json()
        except ValueError:
            raise SplunkError("Splunk returned malformed JSON.") from None
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not isinstance(payload, dict):
            raise SplunkError("Splunk returned an unexpected response structure.")
        results = payload.get("results", [])
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if results is None:
            return []
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not isinstance(results, list):
            raise SplunkError("Splunk returned a non-list results field.")
        return [item.get("result", item) if isinstance(item, dict) else item for item in results if isinstance(item, dict)]
