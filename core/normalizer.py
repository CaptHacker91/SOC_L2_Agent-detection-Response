import pandas as pd


class DataNormalizer:
    """
    Converts parsed records into a DataFrame.

    IMPORTANT: every original source column (real Splunk field or
    synthetic SOC field) is preserved untouched. This class ADDS a
    set of normalized fields on top, so the rest of the app has a
    stable interface regardless of which source schema produced the
    row:

        source_ip, hostname, username, url, domain, event_time,
        filename, uri_path, uri_query, http_method, http_status,
        referer, user_agent, raw_event

    A value is left as None when the source event genuinely does not
    contain the corresponding data — never fabricated.

    Mapping (per the real access_combined_wcookie schema):
        source_ip  <- clientip
        hostname   <- host
        username   <- user            ("-" is treated as unavailable)
        url        <- uri
        domain     <- referer_domain, falling back to referer
        event_time <- _time
        filename   <- file, falling back to uri_path
    """

    def normalize(self, parsed_data):
        df = pd.DataFrame(parsed_data)
        if df.empty:
            return df

        df.columns = [c.lower().strip().replace(" ", "_") for c in df.columns]

        df["source_ip"]   = self._col(df, "clientip")
        df["hostname"]    = self._col(df, "host")
        df["username"]    = self._col(df, "user").apply(self._clean_user)
        df["url"]         = self._col(df, "uri")
        df["uri_path"]    = self._col(df, "uri_path")
        df["uri_query"]   = self._col(df, "uri_query")
        df["http_method"] = self._col(df, "method")
        df["http_status"] = pd.to_numeric(self._col(df, "status"), errors="coerce")
        df["referer"]     = self._col(df, "referer")
        df["domain"]      = self._col(df, "referer_domain").where(
            self._col(df, "referer_domain").notna(), self._col(df, "referer")
        )
        df["user_agent"]  = self._col(df, "useragent")
        df["event_time"]  = self._col(df, "_time")
        df["raw_event"]   = self._col(df, "_raw")
        df["filename"]    = df.apply(self._pick_filename, axis=1)

        df.drop_duplicates(inplace=True)
        return df

    @staticmethod
    def _col(df, name):
        """Returns df[name] if it exists, else an all-None Series of matching length/index."""
        if name in df.columns:
            return df[name]
        return pd.Series([None] * len(df), index=df.index)

    @staticmethod
    def _clean_user(val):
        if val is None:
            return None
        val = str(val).strip()
        return None if val in ("", "-", "nan", "None") else val

    @staticmethod
    def _pick_filename(row):
        f = row.get("file")
        if f and str(f).strip() not in ("", "nan", "None"):
            return f
        up = row.get("uri_path")
        if up and str(up).strip() not in ("", "nan", "None"):
            return up
        return None
