import json

import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor


class DetectionEngine:
    """
    Hybrid Detection Engine

    Features:
    - Rule-Based Detection
    - Isolation Forest
    - Local Outlier Factor
    - Detection Correlation
    """

    def __init__(self, rule_file):
        self.rule_file = rule_file
        self.rules = self._load_rules()

    def _load_rules(self):
        """
        Load Detection Rules
        """

        with open(self.rule_file, "r", encoding="utf-8") as file:
            return json.load(file)

    def analyze(self, dataframe):
        """
        Main Detection Pipeline
        """

        df = dataframe.copy()

        df["rule_match"] = df["threat"].apply(
            self._rule_based_detection
        )

        features = self._prepare_features(df)

        df["isolation_prediction"] = (
            self._isolation_forest_detection(features)
        )

        df["lof_prediction"] = (
            self._lof_detection(features)
        )

        df["final_detection"] = df.apply(
            self._correlate_results,
            axis=1
        )

        return df

    def _rule_based_detection(self, threat):
        """
        Rule-Based Detection
        """

        for rule in self.rules:

            if threat == rule["threat"]:
                return True

        return False

    def _prepare_features(self, dataframe):
        """
        Prepare Features
        """

        return pd.DataFrame(
            {
                "id": dataframe["id"].astype(int),
                "tool": dataframe["tool"]
                .astype("category")
                .cat.codes,
                "rule_type": dataframe["rule_type"]
                .astype("category")
                .cat.codes,
            }
        )

    def _isolation_forest_detection(self, features):
        """
        Isolation Forest
        """

        model = IsolationForest(
            contamination=0.10,
            random_state=42,
        )

        return model.fit_predict(features)

    def _lof_detection(self, features):
        """
        Local Outlier Factor
        """

        model = LocalOutlierFactor(
            contamination=0.10
        )

        return model.fit_predict(features)

    def _correlate_results(self, row):
        """
        Hybrid Correlation
        """

        anomaly = (
            row["isolation_prediction"] == -1
            or row["lof_prediction"] == -1
        )

        if row["rule_match"] and anomaly:
            return "Confirmed Threat"

        if row["rule_match"]:
            return "Rule Match"

        if anomaly:
            return "Anomaly"

        return "Normal"

    def summary(self, dataframe):
        """
        Detection Summary
        """

        return {
            "Confirmed Threat": (
                dataframe["final_detection"]
                == "Confirmed Threat"
            ).sum(),

            "Rule Match": (
                dataframe["final_detection"]
                == "Rule Match"
            ).sum(),

            "Anomaly": (
                dataframe["final_detection"]
                == "Anomaly"
            ).sum(),

            "Normal": (
                dataframe["final_detection"]
                == "Normal"
            ).sum(),
        }