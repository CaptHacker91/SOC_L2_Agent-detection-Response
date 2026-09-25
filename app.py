import os
import streamlit as st
from dotenv import load_dotenv
from core.file_loader import FileLoader
from core.data_source import get_data_source
from core.parser import DetectionParser
from core.normalizer import DataNormalizer
from engine.detection_engine import DetectionEngine
from engine.mitre_mapper import MitreMapper
from engine.severity_engine import SeverityEngine
from engine.alert_triangle import AlertTriangle

load_dotenv()
st.set_page_config(
    page_title="SOC L2 Agent | Blue Team Defence",
    page_icon="🛡️",
    layout="wide",
)

# ── CSS (assigned to variable only, never printed as bare string) ─────────────
CSS = (
    "<style>"
    "@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&display=swap');"
    "*{box-sizing:border-box;margin:0;padding:0}"
    ":root{"
    "--olive:#6b8e23;--olive-dark:#4f6428;--olive-light:#dce8c4;"
    "--rose:rosybrown;--rose-light:#ead8d5;"
    "--gray:gray;--gray-light:#dedede;"
    "--brown:saddlebrown;--background:#eee8dc;--paper:#fffdf8;--dark:#2f3e2f;"
    "}"
    "html,body,[data-testid='stApp'],[data-testid='stAppViewContainer']{"
    "background:var(--background)!important;color:var(--dark)!important;"
    "font-family:'Segoe UI',Arial,sans-serif!important;}"
    "[data-testid='stHeader'],[data-testid='stToolbar'],footer,#MainMenu{display:none!important}"
    ".block-container{padding:0!important;max-width:100%!important}"
    ".soc-header{background:linear-gradient(135deg,#4f6428 0%,#6b8e23 48%,saddlebrown 100%);"
    "color:white;padding:24px 25px 20px;text-align:center;"
    "box-shadow:0 6px 18px rgba(60,40,20,0.25);margin-bottom:20px;}"
    ".soc-header h1{margin:0;font-size:32px;font-weight:800;letter-spacing:.5px}"
    ".soc-header p{margin-top:8px;font-size:14px;opacity:.9}"
    ".header-deco{font-size:18px;letter-spacing:10px;margin-bottom:8px;opacity:.75}"
    ".kpi-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:16px;padding:0 22px;margin-bottom:18px}"
    ".kpi{background:var(--paper);padding:18px;border-radius:16px;text-align:center;"
    "box-shadow:0 5px 14px rgba(65,50,35,.13);transition:.3s;border-top:6px solid var(--c,#6b8e23)}"
    ".kpi:hover{transform:translateY(-5px);box-shadow:0 10px 22px rgba(65,50,35,.2)}"
    ".kpi-icon{font-size:26px;margin-bottom:5px}"
    ".kpi-val{font-size:32px;font-weight:800;color:var(--c,#6b8e23);font-family:'JetBrains Mono',monospace}"
    ".kpi-lbl{font-size:12px;font-weight:700;color:var(--brown);margin-top:3px}"
    ".sec-heading{color:var(--olive-dark);font-size:20px;font-weight:800;"
    "border-bottom:3px solid rosybrown;padding-bottom:7px;margin:16px 22px 12px}"
    ".alert-card{background:var(--paper);border-radius:14px;padding:14px 16px;margin:0 22px 12px;"
    "box-shadow:0 4px 12px rgba(65,50,35,.11);"
    "border-left:5px solid var(--ac,#6b8e23);transition:.25s;}"
    ".alert-card:hover{transform:translateX(4px);box-shadow:0 7px 18px rgba(65,50,35,.2)}"
    ".ac-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:9px}"
    ".ac-threat{font-size:14px;font-weight:700;color:var(--dark)}"
    ".ac-meta{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:7px}"
    ".ac-det{font-size:11px;color:#666;border-left:2px solid #ccc;padding-left:7px}"
    ".badge{display:inline-flex;align-items:center;padding:3px 9px;border-radius:20px;"
    "font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;border:1px solid}"
    ".sev-C{color:#8b0000;background:#ffe0e0;border-color:#ffaaaa}"
    ".sev-H{color:#7a3b00;background:#fff0d8;border-color:#ffcc88}"
    ".sev-M{color:#5a4a00;background:#fff8d8;border-color:#ffe066}"
    ".sev-L{color:#2a5a2a;background:#e0f5e0;border-color:#88cc88}"
    ".chip{font-size:10px;color:#7a5a3a;font-family:'JetBrains Mono',monospace;"
    "background:#f0ebe3;padding:3px 7px;border-radius:5px;border:1px solid #ddd5c8}"
    "div[data-testid='stButton']>button{"
    "background:linear-gradient(135deg,#4f6428,#6b8e23)!important;color:#fff!important;"
    "border:none!important;border-radius:8px!important;padding:.3rem .9rem!important;"
    "font-size:.72rem!important;font-weight:700!important;"
    "box-shadow:0 2px 8px rgba(79,100,40,.4)!important;}"
    "div[data-testid='stButton']>button:hover{opacity:.88!important;transform:translateY(-1px)!important}"
    "input[type=text],.stTextInput input{"
    "background:#fffdf8!important;border:2px solid #d5cec2!important;"
    "color:var(--dark)!important;border-radius:10px!important;font-size:.82rem!important}"
    ".stSelectbox>div>div{background:#fffdf8!important;border:2px solid #d5cec2!important;"
    "border-radius:10px!important}"
    "::-webkit-scrollbar{width:5px;height:5px}"
    "::-webkit-scrollbar-thumb{background:#b5a898;border-radius:4px}"
    ".soc-footer{text-align:center;padding:26px;color:saddlebrown;font-weight:700;"
    "border-top:2px solid #ddd5c8;margin-top:22px}"
    ".soc-footer small{color:gray;font-size:12px}"
    "</style>"
)

SEV_COLOR = {"Critical": "#cc2222", "High": "#b86000", "Medium": "#a08000", "Low": "#2a7a2a"}
SEV_CLS   = {"Critical": "sev-C",   "High": "sev-H",   "Medium": "sev-M",   "Low": "sev-L"}
SEV_DOT   = {"Critical": "🔴",      "High": "🟠",       "Medium": "🟡",      "Low": "🟢"}


# ── Pipeline ───────────────────────────────────────────────────────────────────
@st.cache_resource(show_spinner="Running detection pipeline...")
def load_pipeline():
    # DATA_SOURCE env var picks mock vs Splunk (core/data_source.py).
    # If Splunk is configured but unreachable, fall back to the mock
    # dataset rather than crashing — and tell the analyst honestly,
    # never silently label mock data as live Splunk data.
    try:
        raw = get_data_source().load()
        if os.getenv("DATA_SOURCE", "splunk").lower() == "splunk":
            st.success("Loaded live alerts from Splunk.")
    except Exception as e:
        if os.getenv("DATA_SOURCE", "splunk").lower() == "splunk":
            st.error(f"Splunk connection failed: {e}")
            st.stop()
        raw = FileLoader(
            os.getenv("MOCK_DATA_PATH", "data/BLUE_TEAM_DEFENSE_DATASET.jsonl")
        ).load()

    parsed = DetectionParser().parse(raw)
    df     = DataNormalizer().normalize(parsed)
    df     = DetectionEngine("rules/detection_rules.json").analyze(df)
    df     = MitreMapper().map(df)
    df     = SeverityEngine().calculate(df)
    df     = AlertTriangle().generate(df)
    df     = df[df["final_detection"] != "Normal"].reset_index(drop=True)
    return df.to_dict(orient="records")


# ── Components ─────────────────────────────────────────────────────────────────
def render_header():
    # CSS injected here — single st.markdown call, no bare strings anywhere
    st.markdown(CSS, unsafe_allow_html=True)
    st.markdown(
        '<div class="soc-header">'
        '<div class="header-deco">&#10022; &#10023; &#10022; &#10023; &#10022;</div>'
        '<h1>&#128737;&#65039; SOC L2 Agent</h1>'
        '<p>Blue Team Defence Intelligence Dashboard &middot; SOC L2 AI Investigation Platform</p>'
        '</div>',
        unsafe_allow_html=True,
    )


def render_kpis(alerts):
    sev = lambda s: sum(1 for a in alerts if a.get("severity") == s)
    cards = [
        ("&#128203;", len(alerts),     "#4f6428", "Total Alerts"),
        ("&#128308;", sev("Critical"), "#cc2222", "Critical"),
        ("&#128992;", sev("High"),     "#b86000", "High"),
        ("&#128993;", sev("Medium"),   "#a08000", "Medium"),
        ("&#128994;", sev("Low"),      "#2a7a2a", "Low"),
    ]
    html = "".join(
        f'<div class="kpi" style="--c:{c}">'
        f'<div class="kpi-icon">{ic}</div>'
        f'<div class="kpi-val">{v}</div>'
        f'<div class="kpi-lbl">{l}</div>'
        f'</div>'
        for ic, v, c, l in cards
    )
    st.markdown(f'<div class="kpi-grid">{html}</div>', unsafe_allow_html=True)


def render_alert_card(a, idx):
    sev    = a.get("severity", "Low")
    ac     = SEV_COLOR.get(sev, "#6b8e23")
    cls    = SEV_CLS.get(sev, "sev-L")
    dot    = SEV_DOT.get(sev, "")
    threat = a.get("threat", "Unknown")
    tech   = a.get("mapped_technique", "-")
    tactic = a.get("mitre_tactic", "-")
    risk   = a.get("risk_score", "-")
    det    = a.get("final_detection", "-")
    sub    = a.get("mitre_sub_name", "")
    tool   = a.get("tool", "-")

    st.markdown(
        f'<div class="alert-card" style="--ac:{ac}">'
        f'<div class="ac-header">'
        f'<div class="ac-threat">{threat}</div>'
        f'<span class="chip">via {tool}</span>'
        f'</div>'
        f'<div class="ac-meta">'
        f'<span class="badge {cls}">{dot} {sev}</span>'
        f'<span class="chip">Risk: {risk}</span>'
        f'<span class="chip">MITRE {tech}</span>'
        f'<span class="chip">&#127919; {tactic}</span>'
        f'<span class="chip">&#128203; {det}</span>'
        f'</div>'
        f'<div class="ac-det">{sub}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    _, col = st.columns([5, 1])
    with col:
        if st.button("Investigate", key=f"inv_{idx}"):
            st.session_state.selected_alert = a
            st.session_state.chat_history   = []
            st.switch_page("pages/Investigation.py")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    render_header()

    alerts = load_pipeline()
    if not alerts:
        st.error("No alerts generated. Check dataset or backend.")
        return

    render_kpis(alerts)

    st.markdown('<div class="sec-heading">&#128269; Alert Queue</div>', unsafe_allow_html=True)

    c1, c2, c3 = st.columns([2, 1, 1])
    search  = c1.text_input("", placeholder="Search threats, techniques, tools...",
                            label_visibility="collapsed")
    sev_opts = ["All"] + [s for s in ["Critical","High","Medium","Low"]
                          if any(a.get("severity") == s for a in alerts)]
    sf       = c2.selectbox("Severity", sev_opts, label_visibility="collapsed")
    tac_opts = ["All Tactics"] + sorted({
        a.get("mitre_tactic", "?")
        for a in alerts
        if a.get("mitre_tactic") not in ("Unknown", "", None)
    })
    tf = c3.selectbox("Tactic", tac_opts, label_visibility="collapsed")

    filtered = [
        a for a in alerts if
        (sf == "All" or a.get("severity") == sf) and
        (tf == "All Tactics" or a.get("mitre_tactic") == tf) and
        (not search or search.lower() in str(a).lower())
    ]

    st.markdown(
        f'<div style="font-size:12px;color:#7a5a3a;margin:0 22px 10px;'
        f'font-family:JetBrains Mono,monospace">'
        f'Showing <b>{len(filtered)}</b> / {len(alerts)} alerts</div>',
        unsafe_allow_html=True,
    )

    for i, a in enumerate(filtered):
        render_alert_card(a, i)

    st.markdown(
        '<div class="soc-footer">'
        '&#128737;&#65039; SOC L2 Agent &middot; Blue Team Defence Intelligence Dashboard'
        '<br><small>Developed by Drashya Desai &middot; Helee Mistry &middot; Tanmay Pramar</small>'
        '</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()