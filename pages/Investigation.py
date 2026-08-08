import os
import streamlit as st
from dotenv import load_dotenv
from services.chatbot_service import ChatbotService

load_dotenv()
st.set_page_config(page_title="Investigation | SOAK Agent", page_icon="🔍", layout="wide")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --olive:#6b8e23;--olive-dark:#4f6428;
  --brown:saddlebrown;--background:#eee8dc;--paper:#fffdf8;--dark:#2f3e2f;
}
html,body,[data-testid="stApp"],[data-testid="stAppViewContainer"]{
  background:var(--background)!important;color:var(--dark)!important;
  font-family:'Segoe UI',Arial,sans-serif!important;
}
[data-testid="stHeader"],[data-testid="stToolbar"],footer,#MainMenu{display:none!important}
.block-container{padding:0!important;max-width:100%!important}

.soak-header{
  background:linear-gradient(135deg,#4f6428 0%,#6b8e23 48%,saddlebrown 100%);
  color:white;padding:18px 25px;box-shadow:0 6px 18px rgba(60,40,20,.25);
  margin-bottom:18px;display:flex;justify-content:space-between;align-items:center;
}
.header-left h1{margin:0;font-size:20px;font-weight:800}
.header-left p{margin:4px 0 0;font-size:11px;opacity:.85}

.sec-heading{color:var(--olive-dark);font-size:18px;font-weight:800;
  border-bottom:3px solid rosybrown;padding-bottom:8px;margin:16px 24px 12px}

.detail-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;padding:0 24px;margin-bottom:14px}
.d-card{background:var(--paper);border:1px solid #ddd5c8;border-radius:14px;padding:14px 16px;
  box-shadow:0 3px 10px rgba(65,50,35,.09)}
.d-card.full{grid-column:1/-1}
.d-lbl{font-size:11px;font-weight:700;color:#7a5a3a;text-transform:uppercase;
  letter-spacing:.1em;margin-bottom:5px}
.d-val{font-size:14px;font-weight:600;color:var(--dark);line-height:1.4}

.badge{display:inline-flex;padding:3px 10px;border-radius:20px;
  font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;border:1px solid}
.sev-C{color:#8b0000;background:#ffe0e0;border-color:#ffaaaa}
.sev-H{color:#7a3b00;background:#fff0d8;border-color:#ffcc88}
.sev-M{color:#5a4a00;background:#fff8d8;border-color:#ffe066}
.sev-L{color:#2a5a2a;background:#e0f5e0;border-color:#88cc88}
.chip{font-size:11px;color:#7a5a3a;font-family:'JetBrains Mono',monospace;
  background:#f0ebe3;padding:3px 8px;border-radius:6px;border:1px solid #ddd5c8}

.logs-box{background:#2f3e2f;border-radius:12px;padding:14px 16px;margin:0 24px 14px;
  font-size:12px;font-family:'JetBrains Mono',monospace;color:#c8d8b8;
  border:1px solid #4f6428;white-space:pre-wrap;line-height:1.6;max-height:200px;overflow-y:auto}

.chat-wrap{background:var(--paper);border:2px solid #ddd5c8;border-radius:16px;
  overflow:hidden;margin:0 24px 14px}
.chat-body{padding:14px;min-height:200px;max-height:340px;overflow-y:auto;
  display:flex;flex-direction:column;gap:10px}
.msg{display:flex;flex-direction:column;max-width:84%}
.msg.user{align-self:flex-end;align-items:flex-end}
.msg.assistant{align-self:flex-start;align-items:flex-start}
.bubble{padding:9px 14px;border-radius:14px;font-size:13px;line-height:1.6;white-space:pre-wrap}
.msg.user .bubble{background:linear-gradient(135deg,#4f6428,#6b8e23);color:#fff;
  border-radius:14px 14px 3px 14px}
.msg.assistant .bubble{background:#f5eee3;color:var(--dark);
  border:1px solid #ddd5c8;border-radius:3px 14px 14px 14px}
.role-lbl{font-size:10px;color:#7a5a3a;margin-bottom:3px;
  font-family:'JetBrains Mono',monospace;letter-spacing:.08em;text-transform:uppercase}

div[data-testid="stButton"]>button{
  background:linear-gradient(135deg,#4f6428,#6b8e23)!important;color:#fff!important;
  border:none!important;border-radius:8px!important;padding:.3rem .9rem!important;
  font-size:.72rem!important;font-weight:700!important;
  box-shadow:0 2px 8px rgba(79,100,40,.4)!important;
}
div[data-testid="stButton"]>button:hover{opacity:.88!important;transform:translateY(-1px)!important}
input[type=text],.stTextInput input{
  background:#fffdf8!important;border:2px solid #d5cec2!important;
  color:var(--dark)!important;border-radius:10px!important;font-size:.82rem!important}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-thumb{background:#b5a898;border-radius:4px}
</style>
"""

SEV_CLS = {"Critical":"sev-C","High":"sev-H","Medium":"sev-M","Low":"sev-L"}
SEV_DOT = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}
SEV_COL = {"Critical":"#cc2222","High":"#b86000","Medium":"#a08000","Low":"#2a7a2a"}


@st.cache_resource
def get_chatbot():
    return ChatbotService(os.getenv("GROQ_API_KEY", ""))


def d_card(lbl, val, full=False):
    cls = " full" if full else ""
    return (
        f'<div class="d-card{cls}">'
        f'<div class="d-lbl">{lbl}</div>'
        f'<div class="d-val">{val}</div>'
        f'</div>'
    )


def chat_bubble(role, text):
    lbl = "You" if role == "user" else "🛡 SOAK AI"
    return (
        f'<div class="msg {role}">'
        f'<div class="role-lbl">{lbl}</div>'
        f'<div class="bubble">{text}</div>'
        f'</div>'
    )


def main():
    st.markdown(CSS, unsafe_allow_html=True)

    a = st.session_state.get("selected_alert")
    if not a:
        st.warning("No alert selected. Go back to Dashboard and click Investigate.")
        if st.button("← Back to Dashboard"):
            st.switch_page("app.py")
        return

    sev    = a.get("severity", "Low")
    cls    = SEV_CLS.get(sev, "sev-L")
    dot    = SEV_DOT.get(sev, "⚪")
    col    = SEV_COL.get(sev, "#6b8e23")
    threat = a.get("threat", "Unknown Threat")
    tech   = a.get("mapped_technique", "—")
    tactic = a.get("mitre_tactic", "—")
    sub    = a.get("mitre_sub_name", "—")
    risk   = a.get("risk_score", "—")
    det    = a.get("final_detection", "—")
    impact = a.get("business_impact", "—")
    prio   = a.get("investigation_priority", "—")
    ctx    = a.get("context", "—")
    sig    = a.get("signature", "—")
    tool   = a.get("tool", "—")
    rule_t = a.get("rule_type", "—")

    logs = (
        f"Threat     : {threat}\n"
        f"Technique  : {tech} ({tactic})\n"
        f"Sub-Tech   : {sub}\n"
        f"Tool       : {tool}  |  Rule Type: {rule_t}\n"
        f"Detection  : {det}\n"
        f"Context    : {ctx}\n"
        f"Signature  : {sig}"
    )

    # ── Header ────────────────────────────────────────────────────────────────
    st.markdown(f"""
    <div class="soak-header">
      <div class="header-left">
        <h1>🔍 {threat[:65]}</h1>
        <p>SOAK Agent · SOC L2 AI Investigation Platform · Blue Team Defence</p>
      </div>
      <span class="badge {cls}" style="font-size:13px;padding:6px 14px">{dot} {sev}</span>
    </div>""", unsafe_allow_html=True)

    if st.button("← Back to Dashboard"):
        st.switch_page("app.py")

    # ── Alert Details ─────────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🛡️ Alert Details</div>', unsafe_allow_html=True)

    risk_col = "#cc2222" if float(str(risk)) >= 9.0 else "#a08000" if float(str(risk)) >= 7.0 else "#2a7a2a"
    st.markdown(f"""
    <div class="detail-grid">
      {d_card("Severity",        f'<span class="badge {cls}">{dot} {sev}</span>')}
      {d_card("Risk Score",      f'<span style="font-size:22px;font-weight:800;color:{risk_col}">{risk}</span>')}
      {d_card("MITRE Technique", f'<span style="color:#4f6428;font-family:JetBrains Mono,monospace;font-weight:700">{tech}</span>')}
      {d_card("MITRE Tactic",    tactic)}
      {d_card("Sub-Technique",   sub)}
      {d_card("Detection Tool",  f'{tool} ({rule_t})')}
      {d_card("Business Impact", impact)}
      {d_card("Priority",        prio)}
      {d_card("Context",         ctx)}
      {d_card("Final Detection", f'<span style="color:{col};font-weight:700">{det}</span>')}
    </div>""", unsafe_allow_html=True)

    # ── Associated Logs ───────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">📋 Associated Logs</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="logs-box">{logs}</div>', unsafe_allow_html=True)

    # ── MITRE Info ────────────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🎯 MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="detail-grid">
      {d_card("Technique ID",   f'<span style="font-family:JetBrains Mono,monospace;font-size:16px;font-weight:700;color:#4f6428">{tech}</span>')}
      {d_card("Tactic Phase",   tactic)}
      {d_card("Technique Name", sub)}
      {d_card("Detection Rule", f'<span class="chip">{rule_t}</span>')}
    </div>""", unsafe_allow_html=True)

    # ── SOAK AI Chatbot ───────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🤖 SOAK AI Analyst Assistant</div>', unsafe_allow_html=True)

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    bubbles = "".join(
        chat_bubble(m["role"], m["content"])
        for m in st.session_state.chat_history
    )
    placeholder = (
        "<div style='color:#a08060;font-size:13px;text-align:center;margin:auto'>"
        "Ask the SOAK AI about this alert…"
        "</div>"
    )
    st.markdown(
        f'<div class="chat-wrap"><div class="chat-body">'
        f'{bubbles or placeholder}'
        f'</div></div>',
        unsafe_allow_html=True
    )

    ci, cs, cc = st.columns([6, 1, 1])
    with ci:
        q = st.text_input(
            "", placeholder="e.g. What should the SOC analyst do next?",
            label_visibility="collapsed", key="chat_input"
        )
    with cs:
        send = st.button("Send ➤")
    with cc:
        if st.button("🗑 Clear"):
            st.session_state.chat_history = []
            st.rerun()

    if send and q.strip():
        st.session_state.chat_history.append({"role": "user", "content": q.strip()})
        with st.spinner("🛡 SOAK AI analysing…"):
            try:
                reply = get_chatbot().ask(q.strip(), a, logs)
            except Exception as e:
                reply = f"Error: {e}"
        st.session_state.chat_history.append({"role": "assistant", "content": reply})
        st.rerun()

    # ── Footer ────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="text-align:center;padding:24px;color:saddlebrown;font-weight:700;
      border-top:2px solid #ddd5c8;margin-top:20px">
      🛡️ SOAK Agent · Blue Team Defence Intelligence Dashboard
      <br><small style="color:gray">
        Developed by Drashya Desai · Helee Mistry · Tanmay Pramar
      </small>
    </div>""", unsafe_allow_html=True)


if __name__ == "__main__":
    main()