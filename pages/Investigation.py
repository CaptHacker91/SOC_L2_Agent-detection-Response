import streamlit as st, os
from dotenv import load_dotenv
from services.chatbot_service import ChatbotService

load_dotenv()
st.set_page_config(page_title="Investigation | SOC L2", page_icon="🔍", layout="wide")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
html,body,[data-testid="stApp"],[data-testid="stAppViewContainer"]{background:#0a0e1a!important;color:#e2e8f0!important;font-family:'Inter',sans-serif!important}
[data-testid="stHeader"],[data-testid="stToolbar"],footer,#MainMenu{display:none!important}
.block-container{padding:1.2rem 2rem!important;max-width:100%!important}
.nav{display:flex;justify-content:space-between;align-items:center;background:#0f1629;border:1px solid #1e2d4a;border-radius:10px;padding:.7rem 1.2rem;margin-bottom:1.5rem}
.nav-title{font-size:.95rem;font-weight:700}
.nav-sub{font-size:.65rem;color:#64748b;font-family:'JetBrains Mono',monospace}
.sec{display:flex;align-items:center;gap:.6rem;margin:1.2rem 0 .8rem}
.sec-lbl{font-size:.65rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:#06b6d4;font-family:'JetBrains Mono',monospace;white-space:nowrap}
.sec-line{flex:1;height:1px;background:linear-gradient(90deg,#1a3a6b,transparent)}
.detail-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:.75rem;margin-bottom:.5rem}
.d-card{background:#111827;border:1px solid #1e2d4a;border-radius:10px;padding:.85rem 1rem}
.d-card.full{grid-column:1/-1}
.d-lbl{font-size:.63rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.35rem}
.d-val{font-size:.88rem;font-weight:600;color:#e2e8f0;line-height:1.4}
.badge{display:inline-flex;padding:.2rem .65rem;border-radius:20px;font-size:.65rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;border:1px solid}
.C{color:#ef4444;background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3)}
.H{color:#f97316;background:rgba(249,115,22,.1);border-color:rgba(249,115,22,.3)}
.M{color:#eab308;background:rgba(234,179,8,.1);border-color:rgba(234,179,8,.3)}
.L{color:#22c55e;background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.3)}
.chip{font-size:.66rem;color:#64748b;font-family:'JetBrains Mono',monospace;background:#0f1629;padding:.18rem .5rem;border-radius:5px;border:1px solid #1e2d4a}
.chat-wrap{background:#0f1629;border:1px solid #1e2d4a;border-radius:10px;overflow:hidden;margin-bottom:.75rem}
.chat-body{padding:1rem;min-height:220px;max-height:380px;overflow-y:auto;display:flex;flex-direction:column;gap:.75rem}
.msg{display:flex;flex-direction:column;max-width:82%}
.msg.user{align-self:flex-end;align-items:flex-end}
.msg.assistant{align-self:flex-start;align-items:flex-start}
.bubble{padding:.6rem .9rem;border-radius:12px;font-size:.78rem;line-height:1.6;white-space:pre-wrap}
.msg.user .bubble{background:#2563eb;color:#fff;border-radius:12px 12px 2px 12px}
.msg.assistant .bubble{background:#1e2d4a;color:#e2e8f0;border-radius:2px 12px 12px 12px}
.role-lbl{font-size:.6rem;color:#475569;margin-bottom:.2rem;font-family:'JetBrains Mono',monospace;letter-spacing:.08em;text-transform:uppercase}
div[data-testid="stButton"]>button{background:linear-gradient(135deg,#2563eb,#1d4ed8)!important;color:#fff!important;border:none!important;border-radius:7px!important;padding:.32rem .9rem!important;font-size:.72rem!important;font-weight:600!important;box-shadow:0 2px 8px rgba(37,99,235,.4)!important}
div[data-testid="stButton"]>button:hover{opacity:.88!important;transform:translateY(-1px)!important}
::-webkit-scrollbar{width:4px}::-webkit-scrollbar-thumb{background:#1a3a6b;border-radius:3px}
</style>"""

SEV_CLS = {"Critical":"C","High":"H","Medium":"M","Low":"L"}
SEV_DOT = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}

@st.cache_resource
def get_chatbot():
    return ChatbotService(os.getenv("GEMINI_API_KEY", ""))

def section(lbl):
    st.markdown(f'<div class="sec"><span class="sec-lbl">{lbl}</span><div class="sec-line"></div></div>', unsafe_allow_html=True)

def detail_card(lbl, val, full=False):
    cls = ' full' if full else ''
    return f'<div class="d-card{cls}"><div class="d-lbl">{lbl}</div><div class="d-val">{val}</div></div>'

def chat_bubble(role, text):
    lbl = "You" if role == "user" else "SOC AI"
    return f'<div class="msg {role}"><div class="role-lbl">{lbl}</div><div class="bubble">{text}</div></div>'

def main():
    st.markdown(CSS, unsafe_allow_html=True)

    a = st.session_state.get("selected_alert")
    if not a:
        st.warning("No alert selected. Please go back to Dashboard and click Investigate.")
        if st.button("← Back to Dashboard"):
            st.switch_page("app.py")
        return

    # ── Fields from backend DataFrame row (dict) ──────────────────────────────
    sev    = a.get("severity", "Low")
    cls    = SEV_CLS.get(sev, "L")
    dot    = SEV_DOT.get(sev, "⚪")
    threat = a.get("threat", "Unknown Threat")
    risk   = a.get("risk_score", "N/A")
    tech   = a.get("mapped_technique", "—")      # MitreMapper uses mapped_technique
    tactic = a.get("mitre_tactic", "—")           # MitreMapper adds mitre_tactic
    det    = a.get("final_detection", "—")         # DetectionEngine adds final_detection
    impact = a.get("business_impact", "—")         # AlertTriangle adds business_impact
    prio   = a.get("investigation_priority", "—")  # AlertTriangle adds investigation_priority
    ctx    = a.get("context", "—")                 # AlertTriangle adds context
    sig    = a.get("signature", "—")               # DetectionParser keeps signature
    tool   = a.get("tool", "—")                    # DetectionParser keeps tool
    # logs: not a separate field in this backend — build from available fields
    logs   = f"Threat: {threat}\nTechnique: {tech}\nTool: {tool}\nSignature: {sig}\nContext: {ctx}"

    # ── Navbar ────────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="nav">
      <div>
        <div class="nav-title">🔍 Investigation · {threat[:65]}</div>
        <div class="nav-sub">SOC L2 AGENT · PROTOTYPE V1 · AI-ASSISTED INVESTIGATION</div>
      </div>
      <span class="badge {cls}">{dot} {sev}</span>
    </div>""", unsafe_allow_html=True)

    if st.button("← Back to Dashboard"):
        st.switch_page("app.py")

    # ── Alert Details ─────────────────────────────────────────────────────────
    section("ALERT DETAILS")
    st.markdown(f"""
    <div class="detail-grid">
      {detail_card("Severity",    f'<span class="badge {cls}">{dot} {sev}</span>')}
      {detail_card("Risk Score",  f'<span style="font-size:1.25rem;font-weight:700;color:{"#ef4444" if float(risk) >= 9.0 else "#eab308" if float(risk) >= 7.0 else "#22c55e"}">{risk}</span>'  if str(risk).replace('.','').isdigit() else f'<span style="font-size:1.25rem;font-weight:700;color:#64748b">{risk}</span>')}
      {detail_card("MITRE Technique", f'<span style="color:#06b6d4;font-family:JetBrains Mono,monospace">{tech}</span>')}
      {detail_card("MITRE Tactic", tactic)}
      {detail_card("Business Impact", impact)}
      {detail_card("Investigation Priority", prio)}
      {detail_card("Context", ctx)}
      {detail_card("Detection Tool", tool)}
      {detail_card("Final Detection", det, full=True)}
    </div>""", unsafe_allow_html=True)

    # ── Associated Logs ───────────────────────────────────────────────────────
    section("ASSOCIATED LOGS")
    st.markdown(f"""
    <div style="background:#0a0e1a;border:1px solid #1e2d4a;border-radius:8px;padding:.85rem;margin-bottom:.5rem">
      <pre style="font-size:.72rem;font-family:'JetBrains Mono',monospace;color:#64748b;margin:0;white-space:pre-wrap">{logs}</pre>
    </div>""", unsafe_allow_html=True)

    # ── SOC AI Assistant ──────────────────────────────────────────────────────
    section("SOC AI ASSISTANT")

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    bubbles = "".join(chat_bubble(m["role"], m["content"]) for m in st.session_state.chat_history)
    st.markdown(
        f'<div class="chat-wrap"><div class="chat-body">{bubbles}</div></div>',
        unsafe_allow_html=True
    )

    c_input, c_send, c_clear = st.columns([6, 1, 1])
    with c_input:
        q = st.text_input("", placeholder="Ask the SOC AI about this alert…", label_visibility="collapsed", key="chat_input")
    with c_send:
        send = st.button("Send ➤")
    with c_clear:
        if st.button("🗑 Clear"):
            st.session_state.chat_history = []
            st.rerun()

    if send and q.strip():
        st.session_state.chat_history.append({"role": "user", "content": q.strip()})
        with st.spinner("SOC AI analysing…"):
            try:
                # ChatbotService.ask(question, alert_dict, logs_string)
                reply = get_chatbot().ask(q.strip(), a, logs)
            except Exception as e:
                reply = f"Error: {e}"
        st.session_state.chat_history.append({"role": "assistant", "content": reply})
        st.rerun()

if __name__ == "__main__":
    main()
