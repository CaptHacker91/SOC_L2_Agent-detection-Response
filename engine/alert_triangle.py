"""Triage metadata layer that never converts severity into confirmation."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Alert ke triage priority aur impact metadata ko confirmation status se independent rakhta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================


# CLASS: AlertTriangle
# Role: Ye class ka main kaam Alert Triangle se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class AlertTriangle:
    """Assign analyst priority and impact while preserving independent confirmation status."""

    # FUNCTION: generate
    # Purpose: Ye function generate operation handle karta hai.
    # Input: df.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def generate(self, df):
        """Add investigation priority, business impact and confirmation fields to analysed events."""
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if df.empty:
            return df

        priorities, impacts, confirmations, triage_reasons = [], [], [], []
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for _, row in df.iterrows():
            detection = row.get("final_detection", "Normal")
            severity = row.get("severity", "Low")
            existing = str(row.get("confirmation_status") or "").strip()

            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if detection == "Normal":
                priorities.append("Not Applicable (Normal Event)")
                impacts.append("Not Applicable (Normal Event)")
                confirmations.append(existing or "Not a security detection")
                triage_reasons.append("Normal telemetry does not require incident confirmation.")
                continue

            confirmations.append(existing or "Unconfirmed")
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if severity == "Critical":
                priorities.append("Immediate Review")
                impacts.append("Potentially Severe")
            # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
            elif severity == "High":
                priorities.append("High Priority")
                impacts.append("Potentially Significant")
            # Yaha previous checks ke fail hone par alternate condition evaluate ki ja rahi hai.
            elif severity == "Medium":
                priorities.append("Medium Priority")
                impacts.append("Potentially Moderate")
            else:
                priorities.append("Low Priority")
                impacts.append("Potentially Limited")
            triage_reasons.append("Priority is based on observed evidence and risk/severity; severity alone does not confirm a threat.")

        df["investigation_priority"] = priorities
        df["business_impact"] = impacts
        df["confirmation_status"] = confirmations
        df["triage_reason"] = triage_reasons
        return df
