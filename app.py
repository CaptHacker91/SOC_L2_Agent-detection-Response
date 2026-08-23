import streamlit as st
from dotenv import load_dotenv
from core.file_loader import FileLoader
from core.parser import DetectionParser
from core.normalizer import DataNormalizer
from engine.detection_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper
from engine.severity_engine import SeverityEngine
from engine.alert_triangle import AlertTriangle

load_dotenv()
st.set_page_config(page_title="SOC L2 Agent | Blue Team Defence", page_icon="🛡️", layout="wide")

# ── Dashboard CSS — SOC L2 Agent olive/brown/rose theme ─────────────────────────
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Segoe+UI:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0}

:root{
  --olive:#6b8e23;--olive-dark:#4f6428;--olive-light:#dce8c4;
  --rose:rosybrown;--rose-light:#ead8d5;
  --gray:gray;--gray-light:#dedede;
  --brown:saddlebrown;--brown-dark:#5a2f18;--brown-light:#ead8c8;
  --background:#eee8dc;--paper:#fffdf8;--dark:#2f3e2f;
}

html,body,[data-testid="stApp"],[data-testid="stAppViewContainer"]{
  background:var(--background)!important;
  color:var(--dark)!important;
  font-family:'Segoe UI',Arial,sans-serif!important;
}
[data-testid="stHeader"],[data-testid="stToolbar"],footer,#MainMenu{display:none!important}
.block-container{padding:0!important;max-width:100%!important}

/* ── Header ── */
.soc-header{
  background:linear-gradient(135deg,#4f6428 0%,#6b8e23 48%,saddlebrown 100%);
  color:white;padding:28px 25px 22px;text-align:center;
  box-shadow:0 6px 18px rgba(60,40,20,0.25);position:relative;overflow:hidden;
  margin-bottom:24px;
}
.soc-header h1{margin:0;font-size:34px;font-weight:800;letter-spacing:.5px}
.soc-header p{margin-top:8px;font-size:15px;opacity:.92}
.header-deco{font-size:20px;letter-spacing:12px;margin-bottom:8px;opacity:.8}

/* ── KPI cards ── */
.kpi-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:18px;padding:0 24px;margin-bottom:20px}
.kpi{background:var(--paper);padding:20px;border-radius:18px;text-align:center;
  box-shadow:0 6px 17px rgba(65,50,35,.14);transition:.3s;border-top:6px solid var(--c,#6b8e23)}
.kpi:hover{transform:translateY(-5px);box-shadow:0 10px 24px rgba(65,50,35,.2)}
.kpi-icon{font-size:28px;margin-bottom:6px}
.kpi-val{font-size:34px;font-weight:800;color:var(--c,#6b8e23);font-family:'JetBrains Mono',monospace}
.kpi-lbl{font-size:13px;font-weight:700;color:var(--brown);margin-top:4px}

/* ── Section heading ── */
.sec-heading{color:var(--olive-dark);font-size:22px;font-weight:800;
  border-bottom:3px solid rosybrown;padding-bottom:10px;margin:20px 24px 14px}

/* ── Alert card ── */
.alert-card{
  background:var(--paper);border-radius:16px;padding:16px 18px;margin:0 24px 14px;
  box-shadow:0 5px 14px rgba(65,50,35,.12);
  border-left:5px solid var(--ac,#6b8e23);transition:.25s;cursor:pointer;
}
.alert-card:hover{transform:translateX(4px);box-shadow:0 8px 20px rgba(65,50,35,.2)}
.ac-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px}
.ac-threat{font-size:15px;font-weight:700;color:var(--dark)}
.ac-meta{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.ac-det{font-size:12px;color:#666;border-left:2px solid #ccc;padding-left:8px}

/* ── Badges & chips ── */
.badge{display:inline-flex;align-items:center;padding:3px 10px;border-radius:20px;
  font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;border:1px solid}
.sev-C{color:#8b0000;background:#ffe0e0;border-color:#ffaaaa}
.sev-H{color:#7a3b00;background:#fff0d8;border-color:#ffcc88}
.sev-M{color:#5a4a00;background:#fff8d8;border-color:#ffe066}
.sev-L{color:#2a5a2a;background:#e0f5e0;border-color:#88cc88}
.chip{font-size:11px;color:#7a5a3a;font-family:'JetBrains Mono',monospace;
  background:#f0ebe3;padding:3px 8px;border-radius:6px;border:1px solid #ddd5c8}

/* ── Search / filter bar ── */
.ctrl-bar{display:grid;grid-template-columns:2fr 1fr 1fr;gap:12px;padding:0 24px;margin-bottom:14px}

/* ── Streamlit overrides ── */
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
.stSelectbox>div>div{
  background:#fffdf8!important;border:2px solid #d5cec2!important;border-radius:10px!important}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:#b5a898;border-radius:4px}

/* ── Footer ── */
.soc-footer{text-align:center;padding:28px;color:var(--brown);font-weight:700;
  border-top:2px solid #ddd5c8;margin-top:24px}
.soc-footer small{color:var(--gray);font-size:12px}
</style>
"""

SEV_COLOR = {"Critical":"#cc2222","High":"#b86000","Medium":"#a08000","Low":"#2a7a2a"}
SEV_CLS   = {"Critical":"sev-C","High":"sev-H","Medium":"sev-M","Low":"sev-L"}
SEV_DOT   = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}

# ── Pipeline ───────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner="Running detection pipeline…")
def load_pipeline():
    raw    = FileLoader("data/BLUE_TEAM_DEFENSE_DATASET.jsonl").load()
    parsed = DetectionParser().parse(raw)
    df     = DataNormalizer().normalize(parsed)
    df     = DetectionEngine("rules/detection_rules.json").analyze(df)
    df     = MitreMapper().map(df)
    df     = SeverityEngine().calculate(df)
    df     = AlertTriangle().generate(df)
    df     = df[df["final_detection"] != "Normal"].reset_index(drop=True)
    return df.to_dict(orient="records")

# ── Header ─────────────────────────────────────────────────────────────────────
def render_header():
    st.markdown(f"""{CSS}
    <div class="soc-header">
      <div class="header-deco">✦ ✧ ✦ ✧ ✦</div>
      <h1>🛡️ SOC L2 Agent</h1>
      <p>Blue Team Defence Intelligence Dashboard · SOC L2 AI Investigation Platform</p>
    </div>""", unsafe_allow_html=True)

# ── KPI cards ──────────────────────────────────────────────────────────────────
def render_kpis(alerts):
    sev = lambda s: sum(1 for a in alerts if a.get("severity") == s)
    cards = [
        ("📋", len(alerts),    "#4f6428", "Total Alerts"),
        ("🔴", sev("Critical"),"#cc2222", "Critical"),
        ("🟠", sev("High"),    "#b86000", "High"),
        ("🟡", sev("Medium"),  "#a08000", "Medium"),
        ("🟢", sev("Low"),     "#2a7a2a", "Low"),
    ]
    html = "".join(
        f'<div class="kpi" style="--c:{c}">'
        f'<div class="kpi-icon">{ic}</div>'
        f'<div class="kpi-val">{v}</div>'
        f'<div class="kpi-lbl">{l}</div></div>'
        for ic,v,c,l in cards
    )
    st.markdown(f'<div class="kpi-grid">{html}</div>', unsafe_allow_html=True)

# ── Alert card ─────────────────────────────────────────────────────────────────
def render_alert_card(a, idx):
    sev    = a.get("severity","Low")
    ac     = SEV_COLOR.get(sev,"#6b8e23")
    cls    = SEV_CLS.get(sev,"sev-L")
    dot    = SEV_DOT.get(sev,"⚪")
    threat = a.get("threat","Unknown")
    tech   = a.get("mapped_technique","—")
    tactic = a.get("mitre_tactic","—")
    risk   = a.get("risk_score","—")
    det    = a.get("final_detection","—")
    sub    = a.get("mitre_sub_name","")
    tool   = a.get("tool","—")

    st.markdown(f"""
    <div class="alert-card" style="--ac:{ac}">
      <div class="ac-header">
        <div class="ac-threat">{threat}</div>
        <span class="chip">via {tool}</span>
      </div>
      <div class="ac-meta">
        <span class="badge {cls}">{dot} {sev}</span>
        <span class="chip">Risk: {risk}</span>
        <span class="chip">MITRE {tech}</span>
        <span class="chip">🎯 {tactic}</span>
        <span class="chip">📋 {det}</span>
      </div>
      <div class="ac-det">{sub}</div>
    </div>""", unsafe_allow_html=True)

    _, col = st.columns([5, 1])
    with col:
        if st.button("🔍 Investigate", key=f"inv_{idx}"):
            st.session_state.selected_alert = a
            st.session_state.chat_history   = []
            st.switch_page("pages/Investigation.py")

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    render_header()
    alerts = load_pipeline()

    if not alerts:
        st.error("No alerts generated.")
        return

    render_kpis(alerts)

    st.markdown('<div class="sec-heading">🔍 Alert Queue</div>', unsafe_allow_html=True)

    # Filters
    c1, c2, c3 = st.columns([2, 1, 1])
    search  = c1.text_input("", placeholder="🔍 Search threats, techniques, tools…", label_visibility="collapsed")
    sevs    = ["All"] + [s for s in ["Critical","High","Medium","Low"] if any(a.get("severity")==s for a in alerts)]
    sf      = c2.selectbox("Severity", sevs, label_visibility="collapsed")
    tactics = ["All Tactics"] + sorted({a.get("mitre_tactic","?") for a in alerts if a.get("mitre_tactic") not in ("Unknown","")})
    tf      = c3.selectbox("Tactic", tactics, label_visibility="collapsed")

    filtered = [
        a for a in alerts if
        (sf=="All" or a.get("severity")==sf) and
        (tf=="All Tactics" or a.get("mitre_tactic")==tf) and
        (not search or search.lower() in str(a).lower())
    ]

    st.markdown(
        f'<div style="font-size:12px;color:#7a5a3a;margin:0 24px 10px;font-family:JetBrains Mono,monospace">'
        f'Showing <b>{len(filtered)}</b> / {len(alerts)} alerts</div>',
        unsafe_allow_html=True
    )

    for i, a in enumerate(filtered):
        render_alert_card(a, i)

    st.markdown("""
    <div class="soc-footer">
      🛡️ SOC L2 Agent · Blue Team Defence Intelligence Dashboard
      <br><small>Developed by Drashya Desai · Helee Mistry · Tanmay Pramar</small>
    </div>""", unsafe_allow_html=True)

if __name__ == "__main__":
    main()