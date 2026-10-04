"""Incident Investigation workspace.

The page presents evidence first. Recommendations, AI output and PDF generation
are downstream views of the selected telemetry and are clearly labelled as such.
"""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Selected incident ki evidence-first investigation, AI assistance aur PDF reporting UI provide karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from core.pipeline import load_pipeline, refresh_data
from core.security import safe_json
from core.ui import apply_theme, page_header, section_title
from services.chatbot_service import ChatbotService
from services.incident_context import find_related_events
from services.llm_service import LLMService
from services.report_service import build_report_data, generate_pdf, get_recommendations

load_dotenv(override=False)
NA_TEXT = "Not available in supplied telemetry"


# FUNCTION: _get_chatbot
# Purpose: Ye internal helper get chatbot operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _get_chatbot() -> ChatbotService:
    """Create the optional incident-aware Groq chat service."""
    return ChatbotService(os.getenv("GROQ_API_KEY", ""))


# FUNCTION: _get_investigator
# Purpose: Ye internal helper get investigator operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _get_investigator() -> LLMService:
    """Create the optional Groq investigation-report service."""
    return LLMService(os.getenv("GROQ_API_KEY", ""))


# FUNCTION: value
# Purpose: Ye function ka main kaam value se related processing ko centrally handle karna hai.
# Input: alert, key.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def value(alert: dict, key: str):
    """Return a consistent missing-data placeholder for the Investigation UI."""
    current = alert.get(key)
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if current is None or str(current).strip().lower() in {"", "none", "nan", "null"}:
        return NA_TEXT
    return current


# FUNCTION: _select_alert
# Purpose: Ye internal helper ka main kaam select alert se related processing ko centrally handle karna hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _select_alert(df: pd.DataFrame) -> str | None:
    """Select a detection by ID, while remaining safe for empty datasets and stale state."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if "id" not in df.columns:
        return None
    candidates = df.copy()
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if "final_detection" in candidates.columns:
        detections = candidates[candidates["final_detection"] != "Normal"]
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not detections.empty:
            candidates = detections
    ids = [str(x) for x in candidates["id"].tolist()]
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if not ids:
        return None
    current = str(st.session_state.get("selected_alert_id", ""))
    index = ids.index(current) if current in ids else 0
    selected = st.selectbox(
        "Select incident", ids, index=index,
        format_func=lambda ident: _incident_label(candidates, ident), key="investigation_selector",
    )
    st.session_state["selected_alert_id"] = str(selected)
    return str(selected)


# FUNCTION: _incident_label
# Purpose: Ye internal helper ka main kaam incident label se related processing ko centrally handle karna hai.
# Input: df, ident.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _incident_label(df: pd.DataFrame, ident: str) -> str:
    """Build a compact label showing ID, severity and threat without long wrapping."""
    row = df[df["id"].astype(str) == str(ident)]
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if row.empty:
        return ident
    data = row.iloc[0]
    return f"{ident}  •  {data.get('severity', 'Normal')}  •  {str(data.get('threat', 'Unclassified Event'))[:64]}"


# FUNCTION: _render_metadata
# Purpose: Ye internal helper render metadata operation handle karta hai.
# Input: alert.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _render_metadata(alert: dict) -> None:
    """Render core normalized event metadata in a stable two-column table."""
    fields = {
        "Timestamp": value(alert, "timestamp"),
        "Data Source": value(alert, "source"),
        "Host": value(alert, "hostname"),
        "Agent ID": value(alert, "agent_id"),
        "Agent IP": value(alert, "agent_ip"),
        "Source IP": value(alert, "source_ip"),
        "Destination IP": value(alert, "destination_ip"),
        "Username": value(alert, "username"),
        "Event Type": value(alert, "event_type"),
        "Rule ID": value(alert, "rule_id"),
        "Rule Level": value(alert, "rule_level"),
        "Rule Groups": value(alert, "rule_groups"),
    }
    st.dataframe(pd.DataFrame(list(fields.items()), columns=["Field", "Value"]), use_container_width=True, hide_index=True)


# FUNCTION: _render_sidebar
# Purpose: Ye internal helper render sidebar operation handle karta hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _render_sidebar() -> None:
    """Render navigation and a safe reload action."""
    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.sidebar:
        st.markdown("## Navigation")
        st.page_link("app.py", label="Dashboard", icon="📊")
        st.page_link("pages/Ingestion.py", label="Ingestion Center", icon="📥")
        st.page_link("pages/Investigation.py", label="Investigation", icon="🔎")
        st.divider()
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if st.button("Reload Current Dataset", use_container_width=True, key="investigation_reload"):
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with st.spinner("Reloading telemetry..."):
                refresh_data()
            st.rerun()
        st.caption("Evidence below comes from the currently loaded dataset.")


# FUNCTION: main
# Purpose: Ye function ka main kaam main se related processing ko centrally handle karna hai.
# Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def main() -> None:
    """Render the selected incident, related telemetry, recommendations, AI and PDF."""
    st.set_page_config(page_title="Investigation | SOC L2 Agent", page_icon="🔎", layout="wide")
    apply_theme(st)
    _render_sidebar()
    df = load_pipeline()
    page_header(st, "Incident Investigation", "Evidence → Context → Recommendations → Optional AI → Incident Report")

    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if df is None or df.empty:
        st.warning("No telemetry is loaded. Open Ingestion Center and run MOCK ingestion or a configured live source.")
        return

    inc_id = _select_alert(df)
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if inc_id is None:
        st.info("No incident is available for investigation in the current dataset.")
        return

    match = df[df["id"].astype(str) == str(inc_id)]
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if match.empty:
        st.error(f"Incident {inc_id} is not present in the current dataset.")
        return
    alert = match.iloc[0].to_dict()
    related = find_related_events(df, alert)

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with st.container(border=True):
        section_title(st, "Incident Summary", f"Incident ID: `{inc_id}`  •  Source: **{value(alert, 'source')}**")
        first = st.columns(3)
        second = st.columns(2)
        first[0].metric("Severity", value(alert, "severity"))
        first[1].metric("Risk", f"{alert.get('risk_score')}/10" if alert.get("risk_score") is not None else NA_TEXT)
        first[2].metric("Confidence", value(alert, "confidence_level"))
        second[0].metric("Detection", value(alert, "final_detection"))
        second[1].metric("Confirmation", value(alert, "confirmation_status"))
        st.caption(value(alert, "detection_reason"))

    tabs = st.tabs(["Details", "Evidence", "Related Events", "Recommendations", "AI & Report"])

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[0]:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            section_title(st, "Alert Metadata")
            _render_metadata(alert)
            section_title(st, "Detection Reasoning")
            st.write(value(alert, "detection_reason"))
            st.write(f"**Risk reasoning:** {value(alert, 'risk_justification')}")
            st.write(f"**Confidence reasoning:** {value(alert, 'confidence_reason')}")
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            section_title(st, "MITRE ATT&CK", "Mapping is preserved from supplied telemetry or explicit configured rules.")
            mitre_rows = pd.DataFrame(
                [
                    ["Technique ID", value(alert, "mapped_technique")],
                    ["Technique Name", value(alert, "mitre_technique_name")],
                    ["Tactic", value(alert, "mitre_tactic")],
                    ["Mapping Source", value(alert, "mitre_mapping_source")],
                ],
                columns=["Field", "Value"],
            )
            st.dataframe(mitre_rows, use_container_width=True, hide_index=True)

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[1]:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            section_title(st, "Observed Event Fields")
            evidence_rows = {
                "Process": value(alert, "process"),
                "Command": value(alert, "command"),
                "Filename": value(alert, "filename"),
                "File Hash": value(alert, "file_hash"),
                "Domain": value(alert, "domain"),
                "URL": value(alert, "url"),
                "URI Path": value(alert, "uri_path"),
                "HTTP Method": value(alert, "http_method"),
                "HTTP Status": value(alert, "http_status"),
            }
            st.dataframe(pd.DataFrame(list(evidence_rows.items()), columns=["Field", "Value"]), use_container_width=True, hide_index=True)
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with st.expander("View redacted raw event"):
                st.code(safe_json(alert.get("raw_event"), max_chars=14000), language="json", wrap_lines=True)
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if alert.get("original_log"):
                # Resource/context ko safely open karke operation complete kiya ja raha hai.
                with st.expander("View redacted original log"):
                    st.code(safe_json(alert.get("original_log"), max_chars=9000), wrap_lines=True)

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[2]:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            section_title(st, f"Related Events ({len(related)})")
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if related:
                st.dataframe(pd.DataFrame(related), use_container_width=True, hide_index=True, height=480)
            else:
                st.info("No related events were found using the available source IP / host + rule evidence.")

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[3]:
        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            rec = get_recommendations(alert.get("mitre_tactic"), alert.get("severity"))
            r1, r2, r3 = st.columns(3)
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with r1:
                section_title(st, "Investigation")
                # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
                for item in rec.get("investigation", []):
                    st.write(f"- {item}")
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with r2:
                section_title(st, "Containment")
                # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
                for item in rec.get("containment", []):
                    st.write(f"- {item}")
            # Resource/context ko safely open karke operation complete kiya ja raha hai.
            with r3:
                section_title(st, "Remediation")
                # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
                for item in rec.get("remediation", []):
                    st.write(f"- {item}")

    # Resource/context ko safely open karke operation complete kiya ja raha hai.
    with tabs[4]:
        investigator = _get_investigator()
        chatbot = _get_chatbot()
        report_key = f"ai_report_{inc_id}"
        chat_key = f"chat_history_{inc_id}"
        st.session_state.setdefault(report_key, None)
        st.session_state.setdefault(chat_key, [])

        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            section_title(st, "AI-Assisted Investigation")
            st.caption("Advisory only. AI output never replaces telemetry evidence or analyst confirmation.")
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if not investigator.available:
                st.info(investigator.status_message)
            else:
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if st.button("Generate AI Investigation Report", type="primary", use_container_width=True, key=f"generate_ai_{inc_id}"):
                    # Resource/context ko safely open karke operation complete kiya ja raha hai.
                    with st.spinner("Generating grounded incident analysis..."):
                        st.session_state[report_key] = investigator.investigate(alert, related)
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if st.session_state[report_key]:
                    st.markdown(st.session_state[report_key])
                    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                    if st.button("Regenerate AI Report", use_container_width=True, key=f"regen_ai_{inc_id}"):
                        st.session_state[report_key] = None
                        st.rerun()

        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            section_title(st, "PDF Incident Report")
            # External/file/network ya risky operation ko safely handle karne ke liye yaha exception handling use ho rahi hai.
            try:
                ai_summary = st.session_state.get(report_key) or "AI analysis not generated."
                pdf_bytes = generate_pdf(build_report_data(alert, ai_summary))
                st.download_button(
                    "Download Incident PDF", data=pdf_bytes,
                    file_name=f"SOC_Report_{str(inc_id).replace('/', '_')}.pdf",
                    mime="application/pdf", use_container_width=True, key=f"pdf_{inc_id}",
                )
                st.caption("The PDF is generated from the selected incident, conservative recommendations and optional AI text.")
            except Exception as exc:
                st.error(f"PDF generation failed safely: {type(exc).__name__}.")

        # Resource/context ko safely open karke operation complete kiya ja raha hai.
        with st.container(border=True):
            section_title(st, "SOC AI Chat Assistant")
            # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
            if not chatbot.available:
                st.info(chatbot.status_message)
            else:
                # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
                for msg in st.session_state[chat_key]:
                    # Resource/context ko safely open karke operation complete kiya ja raha hai.
                    with st.chat_message(msg["role"]):
                        st.markdown(msg["content"])
                question = st.chat_input("Ask about the selected incident", key=f"chat_input_{inc_id}")
                # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
                if question:
                    st.session_state[chat_key].append({"role": "user", "content": question})
                    answer = chatbot.ask(question, alert, st.session_state[chat_key], related)
                    st.session_state[chat_key].append({"role": "assistant", "content": answer})
                    st.rerun()


if __name__ == "__main__":
    main()
