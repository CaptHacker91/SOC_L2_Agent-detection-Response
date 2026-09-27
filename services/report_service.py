import requests


class SplunkLoader:
    """
    Fetches records from Splunk via the REST Search API. Returns raw
    event dicts exactly as Splunk provides them — field translation
    (clientip -> source_ip, etc.) happens in core/normalizer.py, not
    here, so this loader stays a pure transport layer.
    """

    def __init__(self, host, port, token, search_query, verify_ssl=True, timeout=30):
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
            headers={"Authorization": f"Bearer {self.token}"},
            data={"search": query, "output_mode": "json", "exec_mode": "oneshot"},
            verify=self.verify_ssl,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json().get("results", [])
