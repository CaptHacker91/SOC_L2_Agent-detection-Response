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
st.set_page_config(page_title="SOC L2 Agent", page_icon="🛡️", layout="wide")

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
html,body,[data-testid="stApp"],[data-testid="stAppViewContainer"]{background:#0a0e1a!important;color:#e2e8f0!important;font-family:'Inter',sans-serif!important}
[data-testid="stHeader"],[data-testid="stToolbar"],footer,#MainMenu{display:none!important}
.block-container{padding:1.2rem 2rem!important;max-width:100%!important}
.nav{display:flex;justify-content:space-between;align-items:center;background:#0f1629;border:1px solid #1e2d4a;border-radius:10px;padding:.7rem 1.2rem;margin-bottom:1.5rem}
.nav-left{display:flex;align-items:center;gap:.75rem}
.nav-logo{width:34px;height:34px;background:linear-gradient(135deg,#2563eb,#06b6d4);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:1rem}
.nav-title{font-size:.95rem;font-weight:700;letter-spacing:.02em}
.nav-sub{font-size:.65rem;color:#64748b;font-family:'JetBrains Mono',monospace;letter-spacing:.08em}
.live{display:flex;align-items:center;gap:.4rem;background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.3);border-radius:20px;padding:.25rem .7rem;font-size:.68rem;color:#22c55e;font-weight:700}
.dot{width:6px;height:6px;background:#22c55e;border-radius:50%;animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.2}}
.sec{display:flex;align-items:center;gap:.6rem;margin:1.2rem 0 .8rem}
.sec-lbl{font-size:.65rem;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:#06b6d4;font-family:'JetBrains Mono',monospace;white-space:nowrap}
.sec-line{flex:1;height:1px;background:linear-gradient(90deg,#1a3a6b,transparent)}
.kpi-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:.8rem;margin-bottom:.5rem}
.kpi{background:#111827;border:1px solid #1e2d4a;border-radius:10px;padding:1rem 1.1rem;position:relative;overflow:hidden}
.kpi::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--c)}
.kpi-val{font-size:1.8rem;font-weight:700;color:var(--c);font-family:'JetBrains Mono',monospace;line-height:1;margin:.3rem 0 .2rem}
.kpi-lbl{font-size:.68rem;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:.1em}
.card{background:#111827;border:1px solid #1e2d4a;border-left:3px solid var(--ac,#2563eb);border-radius:10px;padding:.9rem 1.1rem;margin-bottom:.65rem}
.card:hover{background:#151f35}
.card-hdr{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;margin-bottom:.55rem}
.threat{font-size:.86rem;font-weight:600;flex:1;line-height:1.35}
.ts{font-size:.62rem;color:#475569;font-family:'JetBrains Mono',monospace;white-space:nowrap;margin-top:2px}
.meta{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap;margin-bottom:.55rem}
.badge{display:inline-flex;align-items:center;gap:.25rem;padding:.18rem .6rem;border-radius:20px;font-size:.63rem;font-weight:700;letter-spacing:.07em;text-transform:uppercase;border:1px solid}
.C{color:#ef4444;background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.3)}
.H{color:#f97316;background:rgba(249,115,22,.1);border-color:rgba(249,115,22,.3)}
.M{color:#eab308;background:rgba(234,179,8,.1);border-color:rgba(234,179,8,.3)}
.L{color:#22c55e;background:rgba(34,197,94,.1);border-color:rgba(34,197,94,.3)}
.chip{font-size:.66rem;color:#64748b;font-family:'JetBrains Mono',monospace;background:#0f1629;padding:.18rem .5rem;border-radius:5px;border:1px solid #1e2d4a}
.det{font-size:.73rem;color:#64748b;line-height:1.5;padding-left:.5rem;border-left:2px solid #1a3a6b;margin-bottom:.6rem}
div[data-testid="stButton"]>button{background:linear-gradient(135deg,#2563eb,#1d4ed8)!important;color:#fff!important;border:none!important;border-radius:7px!important;padding:.32rem 1rem!important;font-size:.72rem!important;font-weight:600!important;box-shadow:0 2px 8px rgba(37,99,235,.4)!important}
div[data-testid="stButton"]>button:hover{opacity:.88!important;transform:translateY(-1px)!important}
input[type=text],textarea,.stTextInput input{background:#111827!important;border:1px solid #1e2d4a!important;color:#e2e8f0!important;border-radius:8px!important;font-size:.8rem!important}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-thumb{background:#1a3a6b;border-radius:3px}
</style>"""

SEV_COLOR = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#22c55e"}
SEV_DOT   = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢"}
SEV_CLS   = {"Critical":"C","High":"H","Medium":"M","Low":"L"}

@st.cache_resource(show_spinner="Running detection pipeline…")
def load_pipeline():
    raw    = FileLoader("data/BLUE_TEAM_DEFENSE_DATASET.jsonl").load()
    parsed = DetectionParser().parse(raw)
    df     = DataNormalizer().normalize(parsed)
    df     = DetectionEngine("rules/detection_rules.json").analyze(df)
    df     = MitreMapper().map(df)
    df     = SeverityEngine().calculate(df)
    df     = AlertTriangle().generate(df)
    # Only surface actual detections — drop "Normal" rows
    df     = df[df["final_detection"] != "Normal"].reset_index(drop=True)
    return df.to_dict(orient="records")

def nav():
    st.markdown(CSS, unsafe_allow_html=True)

    st.markdown("""
    <div class="nav">
      <div class="nav-left">
        <div class="nav-logo">🛡️</div>
        <div>
          <div class="nav-title">SOC_L2_Agent-detection-Response</div>
          <div class="nav-sub">PROTOTYPE V1 · AI-ASSISTED INVESTIGATION PLATFORM</div>
        </div>
      </div>
      <div class="live">
        <div class="dot"></div>
        LIVE
      </div>
    </div>
    """, unsafe_allow_html=True)

def section(lbl):
    st.markdown(f'<div class="sec"><span class="sec-lbl">{lbl}</span><div class="sec-line"></div></div>', unsafe_allow_html=True)

def kpi_cards(alerts):
    sev = lambda s: sum(1 for a in alerts if a.get("severity","") == s)
    defs = [
        ("Total Alerts", len(alerts),    "#2563eb", "📋"),
        ("Critical",     sev("Critical"),"#ef4444", "🔴"),
        ("High",         sev("High"),    "#f97316", "🟠"),
        ("Medium",       sev("Medium"),  "#eab308", "🟡"),
        ("Low",          sev("Low"),     "#22c55e", "🟢"),
    ]
    html = "".join(f'<div class="kpi" style="--c:{c}"><div style="font-size:1.1rem">{ic}</div><div class="kpi-val">{v}</div><div class="kpi-lbl">{l}</div></div>' for l,v,c,ic in defs)
    st.markdown(f'<div class="kpi-grid">{html}</div>', unsafe_allow_html=True)

def alert_card(a, idx):
    sev    = a.get("severity", "Low")
    ac     = SEV_COLOR.get(sev, "#2563eb")
    cls    = SEV_CLS.get(sev, "L")
    dot    = SEV_DOT.get(sev, "⚪")
    tech   = a.get("mapped_technique", "—")
    tactic = a.get("mitre_tactic", "—")
    risk   = a.get("risk_score", "N/A")
    det    = a.get("final_detection", "—")
    threat = a.get("threat", "Unknown Threat")
    tool   = a.get("tool", "—")
    st.markdown(f"""
    <div class="card" style="--ac:{ac}">
      <div class="card-hdr">
        <div class="threat">{threat}</div>
        <span class="chip">via {tool}</span>
      </div>
      <div class="meta">
        <span class="badge {cls}">{dot} {sev}</span>
        <span class="chip">Risk: {risk}</span>
        <span class="chip">MITRE {tech}</span>
        <span class="chip">🎯 {tactic}</span>
      </div>
      <div class="det">{det}</div>
    </div>""", unsafe_allow_html=True)
    _, col = st.columns([6, 1])
    with col:
        if st.button("🔍 Investigate", key=f"inv_{idx}"):
            st.session_state.selected_alert = a
            st.switch_page("pages/Investigation.py")

def main():
    nav()
    alerts = load_pipeline()

    if not alerts:
        st.error("No alerts generated. Check your dataset or backend.")
        return

    section("KEY METRICS")
    kpi_cards(alerts)

    section("ALERT QUEUE")
    c1, c2, c3 = st.columns([1.5, 1.5, 3])
    sevs   = ["All"] + [s for s in ["Critical","High","Medium","Low"] if any(a.get("severity") == s for a in alerts)]
    sf     = c1.selectbox("Severity", sevs, label_visibility="collapsed")
    search = c3.text_input("", placeholder="🔍  Search threats, techniques…", label_visibility="collapsed")

    filtered = [a for a in alerts if
        (sf == "All" or a.get("severity") == sf) and
        (not search or search.lower() in str(a).lower())]

    st.markdown(f'<div style="font-size:.7rem;color:#64748b;margin-bottom:.6rem;font-family:JetBrains Mono,monospace">Showing <b style="color:#e2e8f0">{len(filtered)}</b> / {len(alerts)} alerts</div>', unsafe_allow_html=True)

    if not filtered:
        st.info("No alerts match the current filters.")
    else:
        for i, a in enumerate(filtered):
            alert_card(a, i)

if __name__ == "__main__":
    main()