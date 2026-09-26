import os
import streamlit as st
from dotenv import load_dotenv

from core.pipeline import load_pipeline
from services.chatbot_service import ChatbotService
from services.llm_service import LLMService
from services.report_service import generate_pdf, get_recommendations, build_report_data

load_dotenv(override=True)
st.set_page_config(page_title="Investigation | SOC L2 Agent", page_icon="🔎", layout="wide")

NA_TEXT = "Not available in supplied telemetry"

CSS = """
<style>
.stApp{ background:#eee8dc; }
.sec-heading{ color:#4f6428; font-size:19px; font-weight:800; margin:22px 0 10px;
       border-bottom:3px solid rosybrown; padding-bottom:8px; }
.field-box{ background:#fffdf8; padding:14px; border-radius:10px; box-shadow:0 2px 8px rgba(65,50,35,.08); }
.field-label{ font-size:11px; font-weight:800; color:saddlebrown; letter-spacing:.04em; }
.field-val{ font-size:14px; color:#2f3e2f; margin-top:2px; }
.field-na{ color:#aaa; font-style:italic; }
.ioc-grid{ display:grid; grid-template-columns:repeat(3,1fr); gap:14px; }
.ioc-item{ background:#fffdf8; padding:14px; border-radius:10px; box-shadow:0 2px 8px rgba(65,50,35,.08); }
.ioc-type{ font-size:11px; font-weight:800; color:saddlebrown; }
.ioc-val{ font-size:14px; margin-top:2px; word-break:break-all; }
.ioc-na{ color:#aaa; font-style:italic; }
.findings-box{ background:#2f3e2f; color:#dce8c4; padding:16px; border-radius:10px; font-family:monospace; font-size:13px; }
.ai-label{ font-size:12px; color:#a15c1c; font-weight:700; margin-bottom:8px; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


@st.cache_resource
def _get_chatbot():
    return ChatbotService(os.getenv("GROQ_API_KEY", ""))


@st.cache_resource
def _get_investigator():
    return LLMService(os.getenv("GROQ_API_KEY", ""))


def field(label, value):
    val_html = f'<div class="field-val">{value}</div>' if value else f'<div class="field-val field-na">{NA_TEXT}</div>'
    return f'<div class="field-box"><div class="field-label">{label}</div>{val_html}</div>'


def ioc_card(label, value):
    val_html = f'<div class="ioc-val">{value}</div>' if value else f'<div class="ioc-val ioc-na">{NA_TEXT}</div>'
    return f'<div class="ioc-item"><div class="ioc-type">{label}</div>{val_html}</div>'


def main():
    df = load_pipeline()
    if df.empty:
        st.error("No data loaded. Go back to the dashboard.")
        return

    inc_id = st.session_state.get("selected_alert_id")
    if inc_id is None:
        st.warning("No alert selected. Go back to the dashboard and click 'Investigate' on an alert.")
        return

    match = df[df["id"] == str(inc_id)]
    if match.empty:
        st.error(f"Alert {inc_id} not found in the current dataset.")
        return
    a = match.iloc[0].to_dict()

    # ── 1. Incident Header ───────────────────────────────────────────────────
    st.markdown(f"## 🔎 Incident {inc_id}")
    c = st.columns(4)
    c[0].markdown(field("ALERT NAME", a.get("threat")), unsafe_allow_html=True)
    c[1].markdown(field("TIMESTAMP", a.get("event_time")), unsafe_allow_html=True)
    c[2].markdown(field("SEVERITY", a.get("severity")), unsafe_allow_html=True)
    c[3].markdown(field("RISK SCORE", f"{a.get('risk_score')}/10" if a.get("risk_score") is not None else None), unsafe_allow_html=True)
    c2 = st.columns(4)
    c2[0].markdown(field("HOST", a.get("hostname")), unsafe_allow_html=True)
    c2[1].markdown(field("SOURCE IP", a.get("source_ip")), unsafe_allow_html=True)
    c2[2].markdown(field("USERNAME", a.get("username")), unsafe_allow_html=True)
    c2[3].markdown(field("DETECTION", a.get("final_detection")), unsafe_allow_html=True)

    # ── 2. MITRE ATT&CK ───────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🎯 MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)
    m = st.columns(2)
    mapped = a.get("mapped_technique") not in (None, "Not mapped from supplied telemetry")
    m[0].markdown(field("TECHNIQUE ID", a.get("mapped_technique") if mapped else None), unsafe_allow_html=True)
    m[1].markdown(field("TECHNIQUE NAME", a.get("mitre_technique_name") if mapped else None), unsafe_allow_html=True)
    m2 = st.columns(2)
    m2[0].markdown(field("TACTIC", a.get("mitre_tactic") if mapped else None), unsafe_allow_html=True)
    m2[1].markdown(field("CONTEXT", a.get("detection_reason")), unsafe_allow_html=True)
    if not mapped:
        st.caption("⚠️ This telemetry does not, by itself, support a confident MITRE ATT&CK mapping.")

    # ── 3. Detection Evidence & Logs ─────────────────────────────────────────
    st.markdown('<div class="sec-heading">📄 Detection Evidence & Logs</div>', unsafe_allow_html=True)
    e = st.columns(3)
    e[0].markdown(field("EVENT TIME", a.get("event_time")), unsafe_allow_html=True)
    e[1].markdown(field("HTTP METHOD", a.get("http_method")), unsafe_allow_html=True)
    e[2].markdown(field("HTTP STATUS", a.get("http_status")), unsafe_allow_html=True)
    e2 = st.columns(3)
    e2[0].markdown(field("URI PATH", a.get("uri_path")), unsafe_allow_html=True)
    e2[1].markdown(field("URI QUERY", a.get("uri_query")), unsafe_allow_html=True)
    e2[2].markdown(field("REFERER", a.get("referer")), unsafe_allow_html=True)

    st.markdown(f"""<div class="findings-box">
Threat          : {a.get('threat')}
Rule Type       : {a.get('rule_type')}
Tool            : {a.get('tool')}
Detection       : {a.get('final_detection')}
Detection Reason: {a.get('detection_reason')}
URI             : {a.get('url') or NA_TEXT}
Raw Event       : {(str(a.get('raw_event'))[:200] + '…') if a.get('raw_event') else NA_TEXT}
</div>""", unsafe_allow_html=True)

    # ── 4. IOC Section ────────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🔴 Indicators of Compromise (IOC)</div>', unsafe_allow_html=True)
    st.markdown(f"""<div class="ioc-grid">
      {ioc_card("Source IP",      a.get("source_ip"))}
      {ioc_card("Destination IP", None)}
      {ioc_card("Hostname",       a.get("hostname"))}
      {ioc_card("Username",       a.get("username"))}
      {ioc_card("Process",        None)}
      {ioc_card("Domain",         a.get("domain"))}
      {ioc_card("URL",            a.get("url"))}
      {ioc_card("File Hash",      None)}
      {ioc_card("Filename",       a.get("filename"))}
    </div>""", unsafe_allow_html=True)
    st.caption("Fields shown as unavailable genuinely are not present in this event's telemetry — nothing here is fabricated.")

    # ── 5. Business Impact & Recommendations ─────────────────────────────────
    st.markdown('<div class="sec-heading">💼 Business Impact & SOC Recommendations</div>', unsafe_allow_html=True)
    st.markdown(field("BUSINESS IMPACT", a.get("business_impact")), unsafe_allow_html=True)
    st.markdown(field("INVESTIGATION PRIORITY", a.get("investigation_priority")), unsafe_allow_html=True)
    rec = get_recommendations(a.get("mitre_tactic"), a.get("severity"))
    st.markdown("**Investigation Steps:**")
    for step in rec.get("investigation", []):
        st.markdown(f"- {step}")
    st.markdown("**Containment Actions:**")
    for step in rec.get("containment", []):
        st.markdown(f"- {step}")
    st.markdown("**Remediation Steps:**")
    for step in rec.get("remediation", []):
        st.markdown(f"- {step}")

    # ── 6. AI Investigation Report ────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🧠 AI Investigation Report</div>', unsafe_allow_html=True)
    st.markdown('<div class="ai-label">⚠️ AI-generated report. Verify against telemetry before acting.</div>', unsafe_allow_html=True)

    report_key = f"ai_report_{inc_id}"
    if report_key not in st.session_state:
        st.session_state[report_key] = None

    if st.session_state[report_key] is None:
        if st.button("🧠 Generate AI Investigation Report"):
            with st.spinner("Generating executive summary, root cause & recommendations…"):
                try:
                    st.session_state[report_key] = _get_investigator().investigate(a)
                except Exception as ex:
                    st.session_state[report_key] = f"Error generating report: {ex}"
            st.rerun()
    else:
        st.markdown(
            f'<div class="findings-box" style="white-space:pre-wrap;line-height:1.7;font-size:13px">'
            f'{st.session_state[report_key]}</div>',
            unsafe_allow_html=True,
        )
        if st.button("🔄 Regenerate Report"):
            st.session_state[report_key] = None
            st.rerun()

    # ── 7. PDF Download ───────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">📑 Incident Report</div>', unsafe_allow_html=True)
    ai_summary_parts = []
    report_text = st.session_state.get(report_key)
    if report_text:
        ai_summary_parts.append(report_text)
    chat_key = f"chat_history_{inc_id}"
    if st.session_state.get(chat_key):
        chat_text = "\n\n".join(
            f"Q: {m['content']}" if m["role"] == "user" else f"A: {m['content']}"
            for m in st.session_state[chat_key]
        )
        ai_summary_parts.append("--- Analyst Chat Log ---\n" + chat_text)
    ai_summary = "\n\n".join(ai_summary_parts)

    try:
        report_data = build_report_data(a, ai_summary)
        pdf_bytes = generate_pdf(report_data)
        st.download_button(
            "⬇️ Download PDF Report",
            data=pdf_bytes,
            file_name=f"SOC_Report_{inc_id}.pdf",
            mime="application/pdf",
        )
    except Exception as ex:
        st.error(f"PDF generation failed: {ex}")

    # ── 8. SOC AI Chatbot ─────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">💬 SOC AI Chat Assistant</div>', unsafe_allow_html=True)
    st.caption("Incident-aware — answers are grounded in THIS alert's telemetry only.")

    if chat_key not in st.session_state:
        st.session_state[chat_key] = []

    for msg in st.session_state[chat_key]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    question = st.chat_input("Ask about this incident…")
    if question:
        st.session_state[chat_key].append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"):
            with st.spinner("Thinking…"):
                answer = _get_chatbot().ask(question, a, st.session_state[chat_key])
            st.markdown(answer)
        st.session_state[chat_key].append({"role": "assistant", "content": answer})


main()
