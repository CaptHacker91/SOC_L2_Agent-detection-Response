import requests


class SplunkLoader:
    """
    Fetch Splunk events without destroying the original Splunk schema.

    Every field returned by Splunk is preserved.
    SOC-specific fields are added later by the normalization/enrichment layer.
    """

    def __init__(
        self,
        host,
        port,
        token,
        search_query,
        verify_ssl=True,
        timeout=30,
    ):
        self.search_url = f"https://{host}:{port}/services/search/jobs"
        self.token = token
        self.search_query = (search_query or "").strip()
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def load(self):
        if not self.search_query:
            raise ValueError("SPLUNK_SEARCH_QUERY is not set")

        query = self.search_query

        if not query.lower().startswith("search"):
            query = f"search {query}"

        response = requests.post(
            self.search_url,
            headers={
                "Authorization": f"Bearer {self.token}"
            },
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

        # IMPORTANT:
        # Do NOT map to a fixed schema.
        # Keep the complete Splunk result exactly as returned.
        return [
            dict(row)
            for row in raw_rows
            if isinstance(row, dict)
        ]
