import os


def get_data_source():
    """
    Returns the active alert data-source loader. Controlled entirely
    by the DATA_SOURCE env var.

    .env:
        DATA_SOURCE=mock              # or: splunk
        MOCK_DATA_PATH=data/splunk_export.json   # static Splunk export (default)

        # used when DATA_SOURCE=splunk
        SPLUNK_HOST=your-splunk-host
        SPLUNK_PORT=8089
        SPLUNK_TOKEN=your-splunk-auth-token
        SPLUNK_SEARCH_QUERY=search index=... sourcetype=access_combined_wcookie
        SPLUNK_VERIFY_SSL=true

    NOTE: this factory does NOT fall back to mock on Splunk failure —
    that fallback (and the analyst-facing warning) lives in
    core/pipeline.py's load_pipeline(), which is the right layer to
    surface it in the UI.
    """
    source = os.getenv("DATA_SOURCE", "mock").lower()

    if source == "splunk":
        from core.splunk_loader import SplunkLoader

        return SplunkLoader(
            host=os.getenv("SPLUNK_HOST"),
            port=os.getenv("SPLUNK_PORT", "8089"),
            token=os.getenv("SPLUNK_TOKEN"),
            search_query=os.getenv("SPLUNK_SEARCH_QUERY", ""),
            verify_ssl=os.getenv("SPLUNK_VERIFY_SSL", "true").lower() == "true",
        )

    from core.file_loader import FileLoader

    return FileLoader(os.getenv("MOCK_DATA_PATH", "data/splunk_export.json"))
