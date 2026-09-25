import pandas as pd


class DataNormalizer:
    """
    Normalize telemetry without destroying the original Splunk schema.

    Original Splunk fields remain available in the dataframe.
    SOC pipeline fields are derived only when they are missing.
    """

    def normalize(self, parsed_data):

        df = pd.DataFrame(parsed_data)

        if df.empty:
            return df

        # Normalize column names only for dataframe access.
        df.columns = [
            str(column)
            .lower()
            .strip()
            .replace(" ", "_")
            for column in df.columns
        ]

        # Preserve all original columns.
        df.fillna("", inplace=True)
        df.drop_duplicates(inplace=True)
        df.reset_index(drop=True, inplace=True)

        # ------------------------------------------------------------
        # SOC enrichment fields
        # These DO NOT replace the original Splunk telemetry.
        # ------------------------------------------------------------

        if "id" not in df.columns:
            df["id"] = range(1, len(df) + 1)

        if "threat" not in df.columns:
            if "uri_path" in df.columns:
                df["threat"] = df["uri_path"].replace("", "Unknown Threat")
            elif "action" in df.columns:
                df["threat"] = df["action"].replace("", "Unknown Threat")
            elif "sourcetype" in df.columns:
                df["threat"] = df["sourcetype"].replace("", "Unknown Threat")
            else:
                df["threat"] = "Unknown Threat"

        if "rule_type" not in df.columns:
            if "sourcetype" in df.columns:
                df["rule_type"] = df["sourcetype"].replace("", "Telemetry")
            else:
                df["rule_type"] = "Telemetry"

        if "signature" not in df.columns:
            if "uri" in df.columns:
                df["signature"] = df["uri"]
            elif "_raw" in df.columns:
                df["signature"] = df["_raw"]
            else:
                df["signature"] = "Telemetry Event"

        if "tool" not in df.columns:
            if "sourcetype" in df.columns:
                df["tool"] = df["sourcetype"]
            elif "source" in df.columns:
                df["tool"] = df["source"]
            elif "host" in df.columns:
                df["tool"] = df["host"]
            else:
                df["tool"] = "Splunk Telemetry"

        if "mapped_technique" not in df.columns:
            df["mapped_technique"] = "Unknown"

        return df
