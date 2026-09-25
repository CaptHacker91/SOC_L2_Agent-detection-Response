import pandas as pd


class DataNormalizer:
    """
    Normalize Splunk events while preserving all original Splunk fields.
    Adds derived SOC fields only when they can be supported by the event data.
    """

    def normalize(self, parsed_data):
        df = pd.DataFrame(parsed_data)

        if df.empty:
            return df

        # Preserve every original Splunk field.
        df.columns = [
            str(column).lower().strip().replace(" ", "_")
            for column in df.columns
        ]

        df = df.fillna("")
        df = df.drop_duplicates().reset_index(drop=True)

        # Stable event ID without destroying original Splunk fields.
        if "id" not in df.columns:
            df["id"] = range(1, len(df) + 1)

        # Defaults for SOC pipeline.
        df["threat"] = "Normal Event"
        df["rule_type"] = "No Security Rule"
        df["signature"] = ""
        df["tool"] = ""
        df["mapped_technique"] = ""
        df["detection_reason"] = ""
        df["derived_risk_score"] = 0.0

        for i, row in df.iterrows():
            sourcetype = str(row.get("sourcetype", "")).lower()
            uri = str(row.get("uri", "")).lower()
            uri_path = str(row.get("uri_path", "")).lower()
            status = str(row.get("status", ""))

            # vendor_sales is business telemetry, not automatically a threat.
            if sourcetype == "vendor_sales":
                df.at[i, "threat"] = "Normal Business Event"
                df.at[i, "rule_type"] = "Business Telemetry"
                df.at[i, "signature"] = str(row.get("_raw", ""))
                df.at[i, "tool"] = "vendor_sales"
                continue

            # Web-access telemetry.
            if sourcetype == "access_combined_wcookie":
                df.at[i, "tool"] = "Web Access Log"

                # Actual suspicious file request present in the supplied dataset.
                if "/rush/signals.zip" in uri or "/rush/signals.zip" in uri_path:
                    df.at[i, "threat"] = "Suspicious File Access"
                    df.at[i, "rule_type"] = "Suspicious Web Resource"
                    df.at[i, "signature"] = uri
                    df.at[i, "mapped_technique"] = "T1105"
                    df.at[i, "detection_reason"] = (
                        "Request targeted /rush/signals.zip"
                    )
                    df.at[i, "derived_risk_score"] = 9.2
                    continue

                # HTTP 500/503/505 = server-side error anomaly.
                if status in {"500", "503", "505"}:
                    df.at[i, "threat"] = "Web Server Error Anomaly"
                    df.at[i, "rule_type"] = "HTTP Error Detection"
                    df.at[i, "signature"] = f"{status} {uri}"
                    df.at[i, "detection_reason"] = (
                        f"HTTP status {status} observed for web request"
                    )
                    df.at[i, "derived_risk_score"] = 5.5
                    continue

                # 403 = access-control event.
                if status == "403":
                    df.at[i, "threat"] = "Unauthorized Web Access"
                    df.at[i, "rule_type"] = "Access Control Detection"
                    df.at[i, "signature"] = f"{status} {uri}"
                    df.at[i, "detection_reason"] = (
                        "HTTP 403 access-denied response"
                    )
                    df.at[i, "derived_risk_score"] = 7.2
                    continue

                # Other client-side malformed/error responses.
                if status in {"400", "404", "406", "408"}:
                    df.at[i, "threat"] = "Malformed Web Request"
                    df.at[i, "rule_type"] = "HTTP Anomaly Detection"
                    df.at[i, "signature"] = f"{status} {uri}"
                    df.at[i, "detection_reason"] = (
                        f"HTTP status {status} observed"
                    )
                    df.at[i, "derived_risk_score"] = 4.5

        return df
