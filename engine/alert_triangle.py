class AlertTriangle:
    """
    Final decision layer. Combines the detection engine's Anomaly/
    Normal call with SeverityEngine's band to produce:

        final_detection      'Normal' | 'Anomaly' | 'Confirmed Threat'
        investigation_priority
        business_impact

    Normal events pass through untouched. Critical/High anomalies are
    escalated to 'Confirmed Threat' since evidence-backed severity at
    that level warrants analyst action; Medium/Low stay 'Anomaly'
    (worth reviewing, not yet a confirmed incident).
    """

    def generate(self, df):
        if df.empty:
            return df

        final, priority, impact = [], [], []
        for _, row in df.iterrows():
            detection = row.get("final_detection", "Normal")
            severity = row.get("severity", "Low")

            if detection == "Normal":
                final.append("Normal")
                priority.append("None")
                impact.append("None")
                continue

            if severity == "Critical":
                final.append("Confirmed Threat")
                priority.append("Immediate")
                impact.append("Severe")
            elif severity == "High":
                final.append("Confirmed Threat")
                priority.append("High Priority")
                impact.append("Significant")
            elif severity == "Medium":
                final.append("Anomaly")
                priority.append("Medium Priority")
                impact.append("Moderate")
            else:
                final.append("Anomaly")
                priority.append("Low Priority")
                impact.append("Minimal")

        df["final_detection"] = final
        df["investigation_priority"] = priority
        df["business_impact"] = impact
        return df
