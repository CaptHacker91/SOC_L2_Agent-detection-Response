from urllib.parse import urlsplit

import pandas as pd


class DataNormalizer:
    """
    Converts parsed records into a DataFrame.

    IMPORTANT: every original source column is preserved untouched. This
    class ADDS a set of normalized fields on top, so the rest of the app has
    a stable interface regardless of which source produced the row:

        source_ip, hostname, username, url, domain, event_time, filename,
        uri_path, uri_query, http_method, http_status, referer, user_agent,
        raw_event, dst_ip, process, command_line, file_hash

    A value is left as None when the source event genuinely does not
    contain the corresponding data - never fabricated.

    Mapping from the normalized event contract (services/wazuh_service.py):
        source_ip  <- src_ip
        hostname   <- host
        event_time <- timestamp
        username   <- username
        url        <- url
        domain     <- domain
        filename   <- filename
        raw_event  <- raw_event
    Legacy access-log style fields (clientip, uri, _time, _raw, ...) are still
    accepted as fallbacks so older-shaped records keep working.
    """

    def normalize(self, parsed_data):
        df = pd.DataFrame(parsed_data)
        if df.empty:
            return df

        df.columns = [c.lower().strip().replace(" ", "_") for c in df.columns]

        df["source_ip"]    = self._first(df, "src_ip", "clientip")
        df["hostname"]     = self._first(df, "host")
        df["username"]     = self._first(df, "username", "user").apply(self._clean_user)
        df["url"]          = self._first(df, "url", "uri")
        df["http_method"]  = self._first(df, "http_method", "method")
        df["http_status"]  = pd.to_numeric(self._first(df, "http_status", "status"), errors="coerce")
        df["referer"]      = self._first(df, "referer")
        df["domain"]       = self._first(df, "domain", "referer_domain", "referer")
        df["user_agent"]   = self._first(df, "user_agent", "useragent")
        df["event_time"]   = self._first(df, "timestamp", "_time")
        df["raw_event"]    = self._first(df, "raw_event", "_raw")
        df["dst_ip"]       = self._first(df, "dst_ip")
        df["process"]      = self._first(df, "process")
        df["command_line"] = self._first(df, "command_line")
        df["file_hash"]    = self._first(df, "file_hash")

        # uri_path / uri_query: use the source's own values, otherwise derive
        # them from the URL that is actually present (nothing is invented).
        derived_path  = df["url"].apply(lambda u: self._split_url(u)[0])
        derived_query = df["url"].apply(lambda u: self._split_url(u)[1])
        uri_path  = self._col(df, "uri_path")
        uri_query = self._col(df, "uri_query")
        df["uri_path"]  = uri_path.where(uri_path.notna(), derived_path)
        df["uri_query"] = uri_query.where(uri_query.notna(), derived_query)

        df["filename"] = df.apply(self._pick_filename, axis=1)

        # raw_event holds a dict for contract events (unhashable), so
        # de-duplicate on the hashable columns only.
        hashable = [c for c in df.columns
                    if not df[c].map(lambda v: isinstance(v, (dict, list, set))).any()]
        df = df.drop_duplicates(subset=hashable)

        # Uniform "missing" representation: None (not NaN / <NA>), so
        # `value or "not available"` checks downstream behave correctly.
        df = df.astype(object).where(df.notna(), None)
        return df.reset_index(drop=True)

    @staticmethod
    def _col(df, name):
        """Returns df[name] if it exists, else an all-None Series of matching length/index."""
        if name in df.columns:
            return df[name]
        return pd.Series([None] * len(df), index=df.index, dtype=object)

    @classmethod
    def _first(cls, df, *names):
        """Row-wise first non-null value among the given columns (None if none exist)."""
        result = pd.Series([None] * len(df), index=df.index, dtype=object)
        for name in names:
            if name in df.columns:
                result = result.where(result.notna(), df[name])
        return result

    @staticmethod
    def _split_url(url):
        if url is None or str(url).strip() in ("", "nan", "None"):
            return (None, None)
        parts = urlsplit(str(url))
        return (parts.path or None, parts.query or None)

    @staticmethod
    def _clean_user(val):
        if val is None:
            return None
        val = str(val).strip()
        return None if val in ("", "-", "nan", "None") else val

    @staticmethod
    def _pick_filename(row):
        for key in ("filename", "file", "uri_path"):
            f = row.get(key)
            if f is not None and str(f).strip() not in ("", "nan", "None"):
                return f
        return None
