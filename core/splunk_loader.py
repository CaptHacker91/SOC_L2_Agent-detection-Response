import requests


class SplunkLoader:
    """
    Fetches detection/alert records from Splunk via the REST Search API.

    Drop-in replacement for FileLoader: same public contract — a
    parameterless .load() that returns list[dict] with keys
    (id, threat, rule_type, signature, tool, mapped_technique).

    Because the shape matches FileLoader's output exactly, nothing
    downstream (DetectionParser, DataNormalizer, DetectionEngine,
    MitreMapper, SeverityEngine, AlertTriangle) needs to change.
    Field-name translation from your real Splunk schema happens once,
    right here, in _map_row().
    """

    def __init__(self, host, port, token, search_query, verify_ssl=True, timeout=30):
        self.search_url = f"https://{host}:{port}/services/search/jobs"
        self.token = token
        self.search_query = (search_query or "").strip()
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def load(self):
        """
        Runs a one-shot Splunk search and returns normalized records.
        Raises on network/auth failure — caller (data_source.py) decides
        whether to fall back to the mock dataset.
        """
        if not self.search_query:
            raise ValueError("SPLUNK_SEARCH_QUERY is not set")

        query = self.search_query
        if not query.lower().startswith("search"):
            query = f"search {query}"

        response = requests.post(
            self.search_url,
            headers={"Authorization": f"Bearer {self.token}"},
            data={
                "search": query,
                "output_mode": "json",
                "exec_mode": "oneshot",
            },
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()

        raw_rows = response.json().get("results", [])
        return [self._map_row(row) for row in raw_rows]

    def _map_row(self, row):
        """
        Translate one Splunk result row into the app's expected schema.
        Edit the right-hand side field names to match your actual
        Splunk index/sourcetype/CIM fields.
        """
        return {
            "id": row.get("id") or row.get("_cd", ""),
            "threat": row.get("threat", "Unknown Threat"),
            "rule_type": row.get("rule_type", "Unknown"),
            "signature": row.get("signature", "Unknown"),
            "tool": row.get("tool", "Unknown"),
            "mapped_technique": row.get("mapped_technique", "Unknown"),
        }
