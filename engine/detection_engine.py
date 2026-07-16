import pandas as pd


class DetectionEngine:
    """
    AI-Assisted SOC V1
    Rule-Based Detection Engine
    """

    def __init__(self):
        self.supported_tools = [
            "Sigma",
            "YARA",
            "Sigma Rule",
            "YARA Rule"
        ]

    def analyze(self, dataframe):

        detections = []

        for _, row in dataframe.iterrows():

            detection = {

                "id": row.get("id", ""),

                "threat": row.get("threat", "Unknown"),

                "description": row.get("description", ""),

                "rule_type": row.get("rule_type", ""),

                "signature": row.get("signature", ""),

                "tool": row.get("tool", ""),

                "mapped_technique": row.get(
                    "mapped_technique",
                    "Unknown"
                ),

                "status": "Detected"

            }

            detections.append(detection)

        return pd.DataFrame(detections)

    def total_detections(self, dataframe):

        return len(dataframe)

    def detection_summary(self, dataframe):

        return {

            "Total Threats": len(dataframe),

            "Unique Threats":
            dataframe["threat"].nunique(),

            "MITRE Techniques":
            dataframe["mapped_technique"].nunique(),

            "Detection Tools":
            dataframe["tool"].nunique()

        }