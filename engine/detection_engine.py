import json
import pandas as pd


class DetectionEngine:
    def __init__(self, rule_file):
        self.rule_file = rule_file
        self.rules = self._load_rules()

    def _load_rules(self):
        try:
            with open(self.rule_file, "r", encoding="utf-8") as file:
                return json.load(file)
        except Exception:
            return []

    def analyze(self, dataframe):
        df = dataframe.copy()

        if df.empty:
            return df

        # Rule matching is based on the derived SOC threat,
        # while all original Splunk fields remain untouched.
        df["rule_match"] = df.apply(self._rule_based_detection, axis=1)

        df["final_detection"] = df.apply(
            self._correlate_results,
            axis=1
        )

        return df

    def _rule_based_detection(self, row):
        threat = str(row.get("threat", ""))

        for rule in self.rules:
            if threat == str(rule.get("threat", "")):
                return True

        # Derived detections from actual Splunk telemetry.
        return threat not in {
            "",
            "Normal Event",
            "Normal Business Event",
        }

    def _correlate_results(self, row):
        threat = str(row.get("threat", ""))
        risk = float(row.get("derived_risk_score", 0) or 0)

        if threat in {"", "Normal Event", "Normal Business Event"}:
            return "Normal"

        if risk >= 9.0:
            return "Confirmed Threat"

        if risk >= 7.0:
            return "Rule Match"

        return "Anomaly"
