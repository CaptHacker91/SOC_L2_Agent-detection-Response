import os
import streamlit as st
from datetime import datetime
from dotenv import load_dotenv
from services.chatbot_service import ChatbotService
from services.report_service import generate_pdf, get_recommendations, build_report_data

load_dotenv()
st.set_page_config(
    page_title="Investigation | SOC L2 Agent",
    page_icon="🔍",
    layout="wide",
)

# ── CSS — Same olive/brown/rose theme, SOC name ───────────────────────────────
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --olive:#6b8e23;--olive-dark:#4f6428;
  --brown:saddlebrown;--bg:#eee8dc;--paper:#fffdf8;--dark:#2f3e2f;
}
html,body,[data-testid="stApp"],[data-testid="stAppViewContainer"]{
  background:var(--bg)!important;color:var(--dark)!important;
  font-family:'Segoe UI',Arial,sans-serif!important;
}
[data-testid="stHeader"],[data-testid="stToolbar"],footer,#MainMenu{display:none!important}
.block-container{padding:0!important;max-width:100%!important}

.soc-header{
  background:linear-gradient(135deg,#4f6428 0%,#6b8e23 48%,saddlebrown 100%);
  color:white;padding:16px 24px;
  box-shadow:0 6px 18px rgba(60,40,20,.25);margin-bottom:16px;
  display:flex;justify-content:space-between;align-items:center;
}
.soc-header h1{margin:0;font-size:19px;font-weight:800}
.soc-header p{margin:3px 0 0;font-size:11px;opacity:.85}

.sec-heading{color:var(--olive-dark);font-size:17px;font-weight:800;
  border-bottom:3px solid rosybrown;padding-bottom:7px;margin:14px 22px 10px}

/* Detail grid */
.dg{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:0 22px;margin-bottom:12px}
.dg.cols2{grid-template-columns:repeat(2,1fr)}
.dg.cols3{grid-template-columns:repeat(3,1fr)}
.dc{background:var(--paper);border:1px solid #ddd5c8;border-radius:12px;
  padding:12px 14px;box-shadow:0 3px 10px rgba(65,50,35,.08)}
.dc.span2{grid-column:span 2}
.dc.full{grid-column:1/-1}
.dl{font-size:10px;font-weight:700;color:#7a5a3a;text-transform:uppercase;
  letter-spacing:.1em;margin-bottom:4px}
.dv{font-size:13px;font-weight:600;color:var(--dark);line-height:1.4}

/* Severity badges */
.badge{display:inline-flex;padding:3px 10px;border-radius:20px;
  font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;border:1px solid}
.sev-C{color:#8b0000;background:#ffe0e0;border-color:#ffaaaa}
.sev-H{color:#7a3b00;background:#fff0d8;border-color:#ffcc88}
.sev-M{color:#5a4a00;background:#fff8d8;border-color:#ffe066}
.sev-L{color:#2a5a2a;background:#e0f5e0;border-color:#88cc88}
.chip{font-size:11px;color:#7a5a3a;font-family:'JetBrains Mono',monospace;
  background:#f0ebe3;padding:3px 8px;border-radius:6px;border:1px solid #ddd5c8}

/* Findings box */
.findings-box{background:var(--paper);border:2px solid #4f6428;border-radius:14px;
  padding:16px 18px;margin:0 22px 12px}
.finding-row{display:flex;justify-content:space-between;align-items:center;
  padding:6px 0;border-bottom:1px solid #e8e0d0}
.finding-row:last-child{border-bottom:none}
.fk{font-size:12px;font-weight:700;color:#7a5a3a}
.fv{font-size:12px;font-weight:600;color:var(--dark);text-align:right}

/* Logs */
.logs-box{background:#2f3e2f;border-radius:12px;padding:14px 16px;margin:0 22px 12px;
  font-size:11.5px;font-family:'JetBrains Mono',monospace;color:#c8d8b8;
  border:1px solid #4f6428;white-space:pre-wrap;line-height:1.6;
  max-height:200px;overflow-y:auto}

/* Timeline */
.timeline{padding:0 22px;margin-bottom:12px}
.tl-row{display:flex;gap:14px;padding:8px 0;border-bottom:1px solid #e8e0d0;align-items:flex-start}
.tl-dot{width:10px;height:10px;border-radius:50%;background:#6b8e23;margin-top:4px;flex-shrink:0}
.tl-dot.C{background:#cc2222}.tl-dot.H{background:#b86000}
.tl-dot.M{background:#a08000}.tl-dot.L{background:#2a7a2a}
.tl-time{font-size:11px;font-family:'JetBrains Mono',monospace;color:#7a5a3a;width:160px;flex-shrink:0}
.tl-event{font-size:12px;font-weight:600;color:var(--dark)}
.tl-src{font-size:10px;color:#7a5a3a}

/* IOC */
.ioc-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;padding:0 22px;margin-bottom:12px}
.ioc-item{background:var(--paper);border:1px solid #ddd5c8;border-radius:10px;padding:10px 12px}
.ioc-type{font-size:10px;font-weight:700;color:#4f6428;text-transform:uppercase;margin-bottom:3px}
.ioc-val{font-size:11.5px;font-family:'JetBrains Mono',monospace;color:var(--dark);word-break:break-all}
.ioc-na{color:#bbb;font-style:italic}

/* Recs */
.rec-section{padding:0 22px;margin-bottom:6px}
.rec-item{display:flex;gap:8px;padding:5px 0;align-items:flex-start}
.rec-num{font-size:11px;font-weight:800;color:var(--olive-dark);min-width:20px}
.rec-text{font-size:12px;color:var(--dark);line-height:1.5}

/* Chat */
.chat-wrap{background:var(--paper);border:2px solid #ddd5c8;border-radius:14px;
  overflow:hidden;margin:0 22px 12px}
.chat-body{padding:12px;min-height:180px;max-height:320px;overflow-y:auto;
  display:flex;flex-direction:column;gap:9px}
.msg{display:flex;flex-direction:column;max-width:85%}
.msg.user{align-self:flex-end;align-items:flex-end}
.msg.assistant{align-self:flex-start;align-items:flex-start}
.bubble{padding:9px 13px;border-radius:13px;font-size:12.5px;line-height:1.6;white-space:pre-wrap}
.msg.user .bubble{background:linear-gradient(135deg,#4f6428,#6b8e23);color:#fff;
  border-radius:13px 13px 3px 13px}
.msg.assistant .bubble{background:#f5eee3;color:var(--dark);
  border:1px solid #ddd5c8;border-radius:3px 13px 13px 13px}
.role-lbl{font-size:9px;color:#7a5a3a;margin-bottom:2px;
  font-family:'JetBrains Mono',monospace;letter-spacing:.08em;text-transform:uppercase}
.ai-label{font-size:10px;color:#7a5a3a;font-style:italic;
  margin:0 22px 6px;padding:4px 8px;background:#f0ebe3;
  border-radius:6px;display:inline-block}

/* Buttons */
div[data-testid="stButton"]>button, div[data-testid="stDownloadButton"]>button{
  background:linear-gradient(135deg,#4f6428,#6b8e23)!important;color:#fff!important;
  border:none!important;border-radius:8px!important;padding:.3rem .9rem!important;
  font-size:.72rem!important;font-weight:700!important;
  box-shadow:0 2px 8px rgba(79,100,40,.4)!important;
}
div[data-testid="stButton"]>button:hover, div[data-testid="stDownloadButton"]>button:hover{
  opacity:.88!important;transform:translateY(-1px)!important
}
input[type=text],.stTextInput input{
  background:#fffdf8!important;border:2px solid #d5cec2!important;
  color:var(--dark)!important;border-radius:10px!important;font-size:.82rem!important}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-thumb{background:#b5a898;border-radius:4px}
</style>
"""

SEV_CLS = {"Critical":"sev-C","High":"sev-H","Medium":"sev-M","Low":"sev-L"}
SEV_DOT = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}
SEV_COL = {"Critical":"#cc2222","High":"#b86000","Medium":"#a08000","Low":"#2a7a2a"}
NA_TEXT = "Not available in supplied telemetry"


@st.cache_resource
def _get_chatbot():
    return ChatbotService(os.getenv("GROQ_API_KEY", ""))


def _na(v):
    return v if v and v not in ("—", "", "N/A", None) else NA_TEXT


def dc(lbl, val, span2=False, full=False):
    cls = " span2" if span2 else (" full" if full else "")
    return (
        f'<div class="dc{cls}">'
        f'<div class="dl">{lbl}</div>'
        f'<div class="dv">{val}</div>'
        f'</div>'
    )


def chat_bubble(role, text):
    lbl = "You" if role == "user" else "🛡 SOC AI"
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

    # Extract all fields
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
    inc_id = f"INC-{str(a.get('id','000')).zfill(4)}"
    ts_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # Forensic fields (optional)
    src_ip  = a.get("source_ip")
    dst_ip  = a.get("destination_ip")
    host    = a.get("hostname")
    user    = a.get("username")
    proc    = a.get("process_name")
    domain  = a.get("domain")
    url     = a.get("url")
    fhash   = a.get("file_hash")
    fname   = a.get("filename")

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
    <div class="soc-header">
      <div>
        <h1>🔍 {threat[:60]}</h1>
        <p>SOC L2 Agent · Incident Investigation · {inc_id} · {ts_now}</p>
      </div>
      <span class="badge {cls}" style="font-size:13px;padding:6px 14px">{dot} {sev}</span>
    </div>""", unsafe_allow_html=True)

    # ── FIX: PDF Download Section ─────────────────────────────────────────────
    col_back, col_pdf, _ = st.columns([1, 1.5, 7])
    with col_back:
        if st.button("← Dashboard"):
            st.switch_page("app.py")
    
    with col_pdf:
        # Pura data aur bytes pehle prepare kar lo
        ai_summary = ""
        if st.session_state.get("chat_history"):
            ai_summary = "\n\n".join(
                f"Q: {m['content']}" if m["role"] == "user"
                else f"A: {m['content']}"
                for m in st.session_state.chat_history
            )
        
        try:
            pdf_bytes = generate_pdf(a, ai_summary)
            # Seedha download button use karo, without nesting inside st.button!
            st.download_button(
                label="📄 Download PDF Report",
                data=pdf_bytes,
                file_name=f"SOC_Report_{inc_id}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
            )
        except Exception as e:
            st.error(f"Failed to generate PDF: {e}")

    # ── 1. Incident Metadata ─────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">📋 Incident Metadata</div>', unsafe_allow_html=True)
    risk_col = "#cc2222" if float(str(risk)) >= 9.0 else "#b86000" if float(str(risk)) >= 7.0 else "#a08000"
    st.markdown(f"""
    <div class="dg">
      {dc("Incident ID",    f'<span style="font-family:JetBrains Mono,monospace;font-weight:700;color:#4f6428">{inc_id}</span>')}
      {dc("Status",         '<span style="color:#4f6428;font-weight:700">🟡 Under Investigation</span>')}
      {dc("Severity",       f'<span class="badge {cls}">{dot} {sev}</span>')}
      {dc("Risk Score",     f'<span style="font-size:20px;font-weight:800;color:{risk_col}">{risk}<span style="font-size:12px;color:#888"> /10</span></span>')}
      {dc("Detection Tool", f'{tool}')}
      {dc("Rule Type",      f'{rule_t}')}
      {dc("Detection",      f'<span style="color:{col};font-weight:700">{det}</span>')}
      {dc("Priority",       prio)}
    </div>""", unsafe_allow_html=True)

    # ── 2. Investigation Findings ─────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🔎 Investigation Findings</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="findings-box">
      <div class="finding-row"><span class="fk">Alert Type</span><span class="fv">{threat}</span></div>
      <div class="finding-row"><span class="fk">Severity</span><span class="fv"><span class="badge {cls}">{dot} {sev}</span></span></div>
      <div class="finding-row"><span class="fk">Risk Score</span><span class="fv" style="color:{risk_col};font-weight:800">{risk} / 10</span></div>
      <div class="finding-row"><span class="fk">Detection Source</span><span class="fv">{tool} ({rule_t})</span></div>
      <div class="finding-row"><span class="fk">MITRE Technique</span><span class="fv" style="font-family:JetBrains Mono,monospace;color:#4f6428">{tech}</span></div>
      <div class="finding-row"><span class="fk">MITRE Tactic</span><span class="fv">{tactic}</span></div>
      <div class="finding-row"><span class="fk">Technique Name</span><span class="fv">{sub}</span></div>
      <div class="finding-row"><span class="fk">Business Impact</span><span class="fv">{impact}</span></div>
      <div class="finding-row"><span class="fk">Investigation Priority</span><span class="fv">{prio}</span></div>
      <div class="finding-row"><span class="fk">Context</span><span class="fv">{ctx}</span></div>
      <div class="finding-row"><span class="fk">Final Detection</span><span class="fv" style="color:{col};font-weight:700">{det}</span></div>
    </div>""", unsafe_allow_html=True)

    # ── 3. MITRE ATT&CK ──────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🎯 MITRE ATT&CK Mapping</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="dg cols2" style="padding:0 22px;margin-bottom:12px">
      {dc("Technique ID",   f'<span style="font-family:JetBrains Mono,monospace;font-size:16px;font-weight:700;color:#4f6428">{tech}</span>')}
      {dc("Technique Name", sub)}
      {dc("Tactic Phase",   tactic)}
      {dc("Context",        ctx)}
    </div>""", unsafe_allow_html=True)

    # ── 4. Evidence / Logs ────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">📋 Detection Evidence & Logs</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="dg" style="margin-bottom:10px">
      {dc("Signature", sig, full=True)}
    </div>""", unsafe_allow_html=True)
    st.markdown(f'<div class="logs-box">{logs}</div>', unsafe_allow_html=True)

    # ── 5. IOC Section (COMMENTED OUT FOR NOW) ────────────────────────────────
    # st.markdown('<div class="sec-heading">🔴 Indicators of Compromise (IOC)</div>', unsafe_allow_html=True)
    # def ioc_card(label, value):
    #     val_html = (
    #         f'<div class="ioc-val">{value}</div>'
    #         if value else
    #         f'<div class="ioc-val ioc-na">{NA_TEXT[:30]}…</div>'
    #     )
    #     return f'<div class="ioc-item"><div class="ioc-type">{label}</div>{val_html}</div>'
    #
    # st.markdown(f"""
    # <div class="ioc-grid">
    #   {ioc_card("Source IP",      src_ip)}
    #   {ioc_card("Destination IP", dst_ip)}
    #   {ioc_card("Hostname",       host)}
    #   {ioc_card("Username",       user)}
    #   {ioc_card("Process",        proc)}
    #   {ioc_card("Domain",         domain)}
    #   {ioc_card("URL",            url)}
    #   {ioc_card("File Hash",      fhash)}
    #   {ioc_card("Filename",       fname)}
    # </div>""", unsafe_allow_html=True)

    # ── 6. Incident Timeline ──────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">⏱️ Incident Timeline</div>', unsafe_allow_html=True)
    dot_cls = SEV_CLS.get(sev, "sev-L").replace("sev-", "")
    timeline_events = [
        (ts_now, f"Alert Detected — {threat}", tool, "DETECTION EVENT"),
        (ts_now, f"Severity Assessed — {sev} | Risk: {risk}/10", "SOC Pipeline", "CLASSIFICATION"),
        (ts_now, f"MITRE Mapped — {tech} ({tactic})", "MITRE Engine", "MAPPING"),
        (ts_now, f"Investigation Opened — {inc_id}", "SOC L2 Agent", "INVESTIGATION"),
    ]
    rows = "".join(
        f'<div class="tl-row">'
        f'<div class="tl-dot {dot_cls}"></div>'
        f'<div class="tl-time">{t}</div>'
        f'<div><div class="tl-event">{ev}</div><div class="tl-src">{src} · {sig_}</div></div>'
        f'</div>'
        for t, ev, src, sig_ in timeline_events
    )
    st.markdown(f'<div class="timeline">{rows}</div>', unsafe_allow_html=True)
    st.caption("⚠️ Timeline shows detection events only. Forensic timestamps not available in current telemetry.")

    # ── 7. Business Impact ────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">💼 Business Impact</div>', unsafe_allow_html=True)
    impact_desc = {
        "Very High": (
            f"**Critical business risk.** The threat '{threat}' ({tactic} via {tech}) "
            f"poses a potential risk to credentials, sensitive data, or business operations. "
            f"Immediate executive escalation and incident response activation recommended."
        ),
        "High": (
            f"**Significant security risk.** '{threat}' classified under {tactic} represents "
            f"a high-priority threat requiring immediate investigation and containment. "
            f"Potential for unauthorized access or data exposure."
        ),
        "Moderate": (
            f"**Suspicious activity requiring investigation.** '{threat}' ({tech}) indicates "
            f"potentially malicious behavior. Limited confirmed impact at detection time, "
            f"but escalation possible without timely response."
        ),
        "Low": (
            f"**Low-confidence or low-impact activity.** '{threat}' requires monitoring "
            f"and investigation when capacity allows. Unlikely to cause immediate damage "
            f"but should not be dismissed."
        ),
    }.get(impact,
        f"Business impact for '{threat}' assessed as {impact}. "
        f"Review based on {tactic} tactic and organizational context."
    )
    st.markdown(f"""
    <div style="background:var(--paper);border:1px solid #ddd5c8;border-left:4px solid {col};
      border-radius:12px;padding:14px 18px;margin:0 22px 12px">
      <div style="font-size:12px;line-height:1.7;color:var(--dark)">{impact_desc}</div>
    </div>""", unsafe_allow_html=True)

    # ── 8. SOC Analyst Recommendations ───────────────────────────────────────
    st.markdown('<div class="sec-heading">🛡️ SOC Analyst Recommendations</div>', unsafe_allow_html=True)
    recs = get_recommendations(tactic)

    rec_sections = [
        ("🔍 Investigation",   recs["investigation"], "#4f6428"),
        ("🚨 Containment",     recs["containment"],   "#8b0000"),
        ("✅ Remediation",     recs["remediation"],   "#2a5a2a"),
    ]
    for title, steps, color in rec_sections:
        st.markdown(
            f'<div style="font-size:13px;font-weight:800;color:{color};'
            f'margin:8px 22px 4px">{title}</div>',
            unsafe_allow_html=True
        )
        items = "".join(
            f'<div class="rec-item">'
            f'<div class="rec-num">{i+1}.</div>'
            f'<div class="rec-text">{step}</div>'
            f'</div>'
            for i, step in enumerate(steps)
        )
        st.markdown(f'<div class="rec-section">{items}</div>', unsafe_allow_html=True)

    # ── 9. SOC AI Chatbot ─────────────────────────────────────────────────────
    st.markdown('<div class="sec-heading">🤖 SOC AI Analyst Assistant</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="ai-label">⚠️ SOC AI Analysis — AI-generated content. '
        'Verify against telemetry before acting.</div>',
        unsafe_allow_html=True
    )

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    bubbles = "".join(
        chat_bubble(m["role"], m["content"])
        for m in st.session_state.chat_history
    )
    placeholder = (
        "<div style='color:#a08060;font-size:13px;text-align:center;margin:auto'>"
        "Ask the SOC AI about this alert…"
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
        with st.spinner("🛡 SOC AI analysing…"):
            try:
                # FIX: pass history so multi-turn works + alert injected fresh
                reply = _get_chatbot().ask(
                    q.strip(), a, logs,
                    history=st.session_state.chat_history[:-1]  # exclude current q
                )
            except Exception as e:
                reply = f"Error: {e}"
        st.session_state.chat_history.append({"role": "assistant", "content": reply})
        st.rerun()

    # ── Footer ────────────────────────────────────────────────────────────────
    st.markdown("""
    <div style="text-align:center;padding:22px;color:saddlebrown;font-weight:700;
      border-top:2px solid #ddd5c8;margin-top:18px">
      🛡️ SOC L2 Agent · Blue Team Defence Intelligence Dashboard
      <br><small style="color:gray">
        Developed by Drashya Desai · Helee Mistry · Tanmay Pramar
      </small>
    </div>""", unsafe_allow_html=True)


if __name__ == "__main__":
    main()