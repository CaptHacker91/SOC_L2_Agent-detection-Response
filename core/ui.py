"""Shared hacker-terminal presentation system for the SOC L2 Agent.

The module owns the visual language only: CSS, navigation, headers, cards,
status surfaces, pipeline visualisation and small analyst-facing widgets.
Security, ingestion, detection, triage and reporting logic remain elsewhere.
"""
from __future__ import annotations

import html
from typing import Any, Iterable

import pandas as pd


SOC_COLORS = {
    "bg": "#050A0F",
    "bg_deep": "#020608",
    "sidebar": "#03080D",
    "panel": "#081117",
    "card": "#0A151D",
    "card_active": "#0D1C26",
    "border": "#15303B",
    "border_active": "#1C6474",
    "text": "#E8FFF5",
    "text_soft": "#C8E6DD",
    "muted": "#7CA39B",
    "muted_deep": "#4D6E69",
    "cyan": "#19F0D0",
    "green": "#27E38B",
    "amber": "#FFC857",
    "orange": "#FF8A3D",
    "red": "#FF4D6D",
    "purple": "#B98CFF",
    "blue": "#4FB8FF",
}

SEVERITY_COLORS = {
    "Critical": SOC_COLORS["red"],
    "High": SOC_COLORS["orange"],
    "Medium": SOC_COLORS["amber"],
    "Low": SOC_COLORS["green"],
    "Normal": SOC_COLORS["muted_deep"],
}

UI_CSS = f"""
<style>
:root {{
  --soc-bg:{SOC_COLORS['bg']}; --soc-bg-deep:{SOC_COLORS['bg_deep']};
  --soc-sidebar:{SOC_COLORS['sidebar']}; --soc-panel:{SOC_COLORS['panel']};
  --soc-card:{SOC_COLORS['card']}; --soc-card-active:{SOC_COLORS['card_active']};
  --soc-border:{SOC_COLORS['border']}; --soc-border-active:{SOC_COLORS['border_active']};
  --soc-text:{SOC_COLORS['text']}; --soc-text-soft:{SOC_COLORS['text_soft']};
  --soc-muted:{SOC_COLORS['muted']}; --soc-muted-deep:{SOC_COLORS['muted_deep']};
  --soc-cyan:{SOC_COLORS['cyan']}; --soc-green:{SOC_COLORS['green']};
  --soc-amber:{SOC_COLORS['amber']}; --soc-orange:{SOC_COLORS['orange']};
  --soc-red:{SOC_COLORS['red']}; --soc-purple:{SOC_COLORS['purple']};
  --soc-blue:{SOC_COLORS['blue']};
}}

.stApp {{
  color:var(--soc-text);
  background:
    radial-gradient(circle at 85% 0%, rgba(25,240,208,0.06), transparent 24%),
    radial-gradient(circle at 4% 92%, rgba(79,184,255,0.04), transparent 24%),
    linear-gradient(rgba(25,240,208,0.018) 1px, transparent 1px),
    linear-gradient(90deg, rgba(25,240,208,0.018) 1px, transparent 1px),
    var(--soc-bg);
  background-size:auto,auto,30px 30px,30px 30px,auto;
}}
.stApp::before {{
  content:""; position:fixed; inset:0; pointer-events:none; z-index:0;
  background:linear-gradient(to bottom, transparent 0%, rgba(25,240,208,0.018) 50%, transparent 100%);
  background-size:100% 7px; opacity:.45;
}}
.block-container {{ max-width:1540px; padding-top:4.15rem !important; padding-bottom:3.2rem; position:relative; z-index:1; overflow-x:clip; }}
[data-testid="stHeader"] {{ background:rgba(2,6,8,.82); border-bottom:1px solid rgba(21,48,59,.75); }}

section[data-testid="stSidebar"] {{
  background:linear-gradient(180deg,#02070B 0%,#041017 62%,#020608 100%);
  border-right:1px solid var(--soc-border);
}}
section[data-testid="stSidebar"] > div {{ padding-top:.55rem; }}
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {{ color:var(--soc-text-soft); }}
section[data-testid="stSidebar"] hr {{ border-color:var(--soc-border) !important; margin:.72rem 0; }}
section[data-testid="stSidebar"] .stCaption {{ color:var(--soc-muted-deep); }}
section[data-testid="stSidebar"] [data-testid="stPageLink"] a {{
  border-radius:6px; padding:.44rem .55rem; color:var(--soc-muted);
  border:1px solid transparent; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  letter-spacing:.035em; transition:all .14s ease;
}}
section[data-testid="stSidebar"] [data-testid="stPageLink"] a:hover {{
  color:var(--soc-text); background:rgba(25,240,208,.055); border-color:rgba(25,240,208,.15);
  box-shadow:inset 2px 0 0 rgba(25,240,208,.3);
}}
section[data-testid="stSidebar"] [data-testid="stPageLink"] a[aria-current="page"] {{
  color:var(--soc-text); background:linear-gradient(90deg,rgba(25,240,208,.115),rgba(25,240,208,.025));
  border-color:rgba(25,240,208,.22); box-shadow:inset 2px 0 0 var(--soc-cyan), 0 0 18px rgba(25,240,208,.035);
}}
section[data-testid="stSidebar"]::after {{ display:none !important; }}
section[data-testid="stSidebar"] > div {{ padding-bottom:1.35rem !important; }}
section[data-testid="stSidebar"] {{ position:relative; box-shadow:12px 0 40px rgba(0,0,0,.28), inset -1px 0 rgba(25,240,208,.03); }}

h1,h2,h3,h4 {{ color:var(--soc-text) !important; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace !important; letter-spacing:-.02em; }}
h1 {{ font-size:2rem !important; font-weight:900 !important; }}
h2 {{ font-size:1.18rem !important; font-weight:900 !important; }}
h3 {{ font-size:.98rem !important; font-weight:900 !important; }}
[data-testid="stCaptionContainer"] {{ color:var(--soc-muted) !important; }}
[data-testid="stVerticalBlockBorderWrapper"] {{
  background:linear-gradient(180deg,rgba(8,17,23,.95),rgba(4,11,15,.97));
  border:1px solid var(--soc-border); border-radius:8px;
  box-shadow:0 10px 28px rgba(0,0,0,.20), inset 0 1px 0 rgba(25,240,208,.018);
}}
[data-testid="stVerticalBlockBorderWrapper"]:hover {{
  border-color:rgba(25,240,208,.18);
  box-shadow:0 12px 32px rgba(0,0,0,.28), 0 0 24px rgba(25,240,208,.025), inset 0 1px 0 rgba(25,240,208,.035);
}}
[data-testid="stMetric"] {{
  background:linear-gradient(180deg,rgba(10,21,29,.98),rgba(6,15,20,.98));
  border:1px solid var(--soc-border); border-radius:7px; padding:.65rem .75rem; min-height:6.1rem;
}}
[data-testid="stMetricLabel"] {{ color:var(--soc-muted) !important; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.62rem; font-weight:900; letter-spacing:.1em; }}
[data-testid="stMetricValue"] {{ color:var(--soc-text) !important; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-weight:900; }}

.stButton > button,.stDownloadButton > button {{
  border-radius:5px; min-height:2.35rem; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-weight:900; letter-spacing:.035em; color:var(--soc-text-soft); background:var(--soc-card);
  border:1px solid var(--soc-border); box-shadow:inset 0 0 0 1px rgba(255,255,255,.008); transition:all .14s ease;
}}
.stButton > button:hover,.stDownloadButton > button:hover {{
  color:var(--soc-text); background:var(--soc-card-active); border-color:var(--soc-border-active);
  box-shadow:0 0 16px rgba(25,240,208,.06);
}}
button[kind="primary"] {{ background:linear-gradient(135deg,#0B6F67,#0BA792) !important; border-color:#0DAF99 !important; color:#EFFFFB !important; box-shadow:0 0 18px rgba(25,240,208,.08), inset 0 0 12px rgba(255,255,255,.03) !important; }}
button[kind="primary"]:hover {{ background:linear-gradient(135deg,#0C8177,#10BFA7) !important; box-shadow:0 0 24px rgba(25,240,208,.15) !important; transform:translateY(-1px); }}
.stButton > button:active,.stDownloadButton > button:active {{ transform:translateY(1px); }}
[data-baseweb="input"], [data-baseweb="select"] > div, [data-testid="stTextInput"] input {{
  background:#061016 !important; color:var(--soc-text) !important; border-color:var(--soc-border) !important;
}}
[data-baseweb="select"] span,[data-baseweb="input"] input {{ color:var(--soc-text-soft) !important; }}
label {{ color:var(--soc-muted) !important; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace !important; font-weight:800 !important; letter-spacing:.02em; }}

[data-baseweb="tab-list"] {{ gap:.14rem; border-bottom:1px solid var(--soc-border); }}
[data-baseweb="tab"] {{ color:var(--soc-muted) !important; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.72rem; font-weight:900; }}
[data-baseweb="tab"][aria-selected="true"] {{ color:var(--soc-text) !important; }}
[data-baseweb="tab-highlight"] {{ background:var(--soc-cyan) !important; height:2px !important; box-shadow:0 0 8px rgba(25,240,208,.65); }}
[data-testid="stDataFrame"] {{ border:1px solid var(--soc-border); border-radius:6px; overflow:hidden; background:var(--soc-panel); }}
details[data-testid="stExpander"] {{ background:#050D12; border:1px solid var(--soc-border); border-radius:6px; }}
details[data-testid="stExpander"] summary {{ color:var(--soc-text-soft); font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
[data-testid="stCodeBlock"] {{ background:#020609; border:1px solid var(--soc-border); border-radius:6px; }}
[data-testid="stAlert"] {{ border-radius:6px; }}
hr {{ border-color:var(--soc-border) !important; }}

/* ADVANCED COMMAND-CONSOLE LAYER */
.soc-command-bar {{ display:flex; align-items:center; justify-content:space-between; gap:.6rem; min-width:0; padding:.34rem .52rem; margin:0 0 .58rem; border:1px solid rgba(25,240,208,.14); background:rgba(1,7,10,.82); border-radius:5px; box-shadow:inset 0 0 22px rgba(25,240,208,.018); font:900 .53rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:.08em; text-transform:uppercase; }}
.soc-command-left {{ display:flex; gap:.65rem; align-items:center; color:var(--soc-muted); min-width:0; flex:1 1 auto; overflow:hidden; }}
.soc-command-left b {{ color:var(--soc-green); flex:0 0 auto; }}
.soc-command-left span:last-child {{ min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.soc-command-right {{ color:var(--soc-cyan); white-space:nowrap; flex:0 0 auto; }}
.soc-pulse {{ width:6px; height:6px; border-radius:50%; background:var(--soc-green); box-shadow:0 0 0 0 rgba(39,227,139,.45); animation:socPulse 1.8s infinite; }}
@keyframes socPulse {{ 0% {{ box-shadow:0 0 0 0 rgba(39,227,139,.42); }} 70% {{ box-shadow:0 0 0 7px rgba(39,227,139,0); }} 100% {{ box-shadow:0 0 0 0 rgba(39,227,139,0); }} }}
.soc-corner {{ position:absolute; width:14px; height:14px; border-color:rgba(25,240,208,.55); pointer-events:none; }}
.soc-corner.tl {{ top:7px; left:7px; border-top:1px solid; border-left:1px solid; }}
.soc-corner.tr {{ top:7px; right:7px; border-top:1px solid; border-right:1px solid; }}
.soc-corner.bl {{ bottom:7px; left:7px; border-bottom:1px solid; border-left:1px solid; }}
.soc-corner.br {{ bottom:7px; right:7px; border-bottom:1px solid; border-right:1px solid; }}
.soc-hero-grid {{ position:absolute; inset:0; pointer-events:none; opacity:.32; background-image:linear-gradient(rgba(25,240,208,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(25,240,208,.035) 1px,transparent 1px); background-size:18px 18px; mask-image:linear-gradient(to right,transparent 0%,#000 28%,#000 100%); }}
.soc-scanline {{ position:absolute; left:0; right:0; height:1px; top:-1px; background:linear-gradient(90deg,transparent,var(--soc-cyan),transparent); opacity:.13; animation:socScan 5.5s linear infinite; pointer-events:none; }}
@keyframes socScan {{ from {{ transform:translateY(0); }} to {{ transform:translateY(210px); }} }}
.soc-hero-live {{ color:var(--soc-green); font:900 .54rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:.1em; }}
.soc-hero-live::before {{ content:"●"; margin-right:.3rem; animation:socBlink 1.2s infinite; }}
@keyframes socBlink {{ 50% {{ opacity:.25; }} }}
.soc-metric-card {{ transition:transform .16s ease,border-color .16s ease,box-shadow .16s ease; }}
.soc-metric-card:hover {{ transform:translateY(-2px); border-color:rgba(25,240,208,.24); box-shadow:0 10px 24px rgba(0,0,0,.25),0 0 18px rgba(25,240,208,.035); }}
.soc-metric-value {{ text-shadow:0 0 14px rgba(232,255,245,.06); }}
.soc-stage:hover {{ border-color:rgba(25,240,208,.25); box-shadow:0 0 18px rgba(25,240,208,.035); transform:translateY(-1px); }}
.soc-stage {{ transition:all .16s ease; }}
.soc-strip-item {{ position:relative; overflow:hidden; }}
.soc-strip-item::after {{ content:""; position:absolute; left:0; bottom:0; width:100%; height:1px; background:linear-gradient(90deg,transparent,var(--soc-cyan),transparent); opacity:.16; }}
.soc-terminal {{ position:relative; overflow:hidden; }}
.soc-terminal::before {{ content:"SECURE SHELL // READ-ONLY VISUALIZATION"; display:block; color:#33504D; margin:-.15rem 0 .35rem; font-size:.49rem; letter-spacing:.11em; }}
.soc-footer {{ border-top:1px solid rgba(21,48,59,.55); padding-top:.45rem; }}

.soc-command-matrix {{ display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:.5rem; margin:.1rem 0 .9rem; position:relative; overflow:hidden; }}
.soc-command-matrix::after {{ content:""; position:absolute; top:-35%; right:5px; width:1px; height:170%; background:linear-gradient(to bottom,transparent,rgba(39,227,139,.75),transparent); box-shadow:0 0 9px rgba(39,227,139,.35); opacity:.25; pointer-events:none; animation:socMatrixScan 6.6s ease-in-out infinite; }}
@keyframes socMatrixScan {{ 0%,100% {{ transform:translateY(-14%); }} 50% {{ transform:translateY(14%); }} }}
.soc-matrix-cell {{ min-height:3.2rem; padding:.52rem .58rem; border:1px solid rgba(21,48,59,.95); border-radius:6px; background:linear-gradient(180deg,rgba(5,14,19,.95),rgba(2,8,11,.95)); position:relative; overflow:hidden; }}
.soc-matrix-cell::before {{ content:""; position:absolute; left:0; top:0; width:100%; height:1px; background:linear-gradient(90deg,transparent,rgba(25,240,208,.22),transparent); }}
.soc-matrix-label {{ color:var(--soc-muted-deep); font:900 .48rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:.1em; text-transform:uppercase; }}
.soc-matrix-value {{ color:var(--soc-text-soft); font:900 .57rem/1.35 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; margin-top:.28rem; white-space:normal; overflow-wrap:anywhere; word-break:break-word; }}
.soc-matrix-value .soc-meta-dot,.soc-matrix-value .soc-meta-dot-green,.soc-matrix-value .soc-meta-dot-red,.soc-matrix-value .soc-meta-dot-amber {{ display:inline-block; vertical-align:middle; margin-right:.3rem; }}
@media (max-width:1200px) {{ .soc-command-matrix {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} .soc-strip {{ grid-template-columns:repeat(3,minmax(0,1fr)); }} }}
@media (max-width:700px) {{ .soc-command-matrix {{ grid-template-columns:1fr; }} .soc-strip {{ grid-template-columns:1fr; }} }}
.soc-brand {{ padding:.15rem .05rem .68rem; }}
.soc-brand-row {{ display:flex; align-items:center; justify-content:space-between; gap:.5rem; }}
.soc-brand-title {{ color:var(--soc-text); font:900 1rem/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:.08em; }}
.soc-brand-sub {{ color:var(--soc-muted-deep); font:800 .61rem/1.3 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; text-transform:uppercase; letter-spacing:.12em; margin-top:.25rem; }}
.soc-brand-mark {{ width:33px;height:33px;border-radius:6px;display:flex;align-items:center;justify-content:center;color:var(--soc-cyan);background:rgba(25,240,208,.055);border:1px solid rgba(25,240,208,.2);font:900 .88rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;box-shadow:0 0 15px rgba(25,240,208,.05); }}
.soc-kicker {{ color:var(--soc-cyan); font:900 .64rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:.17em; text-transform:uppercase; margin-bottom:.18rem; }}
.soc-hero {{ position:relative; overflow:hidden; display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:center; gap:1rem; padding:1rem 1.05rem; border:1px solid rgba(25,240,208,.2); border-radius:8px; background:linear-gradient(120deg,rgba(7,18,23,.98),rgba(3,10,14,.98)); box-shadow:0 14px 35px rgba(0,0,0,.22),0 0 25px rgba(25,240,208,.025); margin-bottom:.8rem; }}
.soc-hero::after {{ display:none !important; }}
.soc-hero-title {{ color:var(--soc-text); font:900 1.6rem/1.12 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:-.025em; text-transform:uppercase; }}
.soc-hero-sub {{ color:var(--soc-muted); font:650 .72rem/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; margin-top:.35rem; max-width:950px; }}
.soc-hero-meta {{ display:flex; flex-wrap:wrap; justify-content:flex-end; gap:.36rem; }}
.soc-hero > div:not(.soc-hero-grid):not(.soc-scanline):not(.soc-vscan) {{ position:relative; z-index:4; min-width:0; }}
.soc-vscan {{ position:absolute; left:17%; top:-12%; width:1px; height:124%; z-index:2; pointer-events:none; opacity:.22; background:linear-gradient(to bottom,transparent 0%,rgba(25,240,208,.15) 12%,rgba(39,227,139,.95) 50%,rgba(25,240,208,.12) 88%,transparent 100%); box-shadow:0 0 10px rgba(25,240,208,.45); animation:socVerticalScan 5.8s ease-in-out infinite; }}
@keyframes socVerticalScan {{ 0%,100% {{ transform:translateY(-16%); }} 50% {{ transform:translateY(16%); }} }}
.soc-meta-chip {{ display:inline-flex;align-items:center;gap:.34rem;padding:.36rem .52rem;border-radius:999px;color:var(--soc-text-soft);background:#030A0D;border:1px solid var(--soc-border);font:900 .58rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.065em; }}
.soc-meta-dot {{ width:5px;height:5px;border-radius:50%;background:var(--soc-cyan);box-shadow:0 0 8px rgba(25,240,208,.7); }}
.soc-meta-dot-green {{ width:5px;height:5px;border-radius:50%;background:var(--soc-green);box-shadow:0 0 8px rgba(39,227,139,.6); }}
.soc-meta-dot-red {{ width:5px;height:5px;border-radius:50%;background:var(--soc-red);box-shadow:0 0 8px rgba(255,77,109,.6); }}
.soc-meta-dot-amber {{ width:5px;height:5px;border-radius:50%;background:var(--soc-amber);box-shadow:0 0 8px rgba(255,200,87,.55); }}
.soc-section {{ margin-top:.24rem; margin-bottom:.48rem; position:relative; }}
.soc-section-critical {{ overflow:hidden; padding-right:.1rem; }}
.soc-section-critical::after {{ content:""; position:absolute; right:.18rem; top:0; width:1px; height:100%; background:linear-gradient(to bottom,transparent,rgba(25,240,208,.65),transparent); box-shadow:0 0 8px rgba(25,240,208,.22); opacity:.22; pointer-events:none; animation:socSectionScan 4.6s ease-in-out infinite; }}
@keyframes socSectionScan {{ 0%,100% {{ transform:translateY(-15%); }} 50% {{ transform:translateY(15%); }} }}
.soc-section-title {{ display:flex;align-items:center;gap:.48rem;color:var(--soc-text);font:900 .9rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.02em;text-transform:uppercase; }}
.soc-section-title::before {{ content:"#"; color:var(--soc-cyan); font-weight:900; }}
.soc-section-caption {{ color:var(--soc-muted);font:650 .64rem/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin:.16rem 0 0 .85rem; }}
.soc-status {{ display:inline-flex;align-items:center;gap:.36rem;padding:.28rem .48rem;border:1px solid var(--soc-border);background:#030A0D;border-radius:999px;color:var(--soc-text-soft);font:900 .58rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.06em;text-transform:uppercase; }}
.soc-dot {{ width:6px;height:6px;border-radius:50%;display:inline-block;background:var(--soc-cyan);box-shadow:0 0 8px rgba(25,240,208,.55); }}
.soc-dot-green {{ background:var(--soc-green);box-shadow:0 0 8px rgba(39,227,139,.55); }} .soc-dot-amber {{ background:var(--soc-amber);box-shadow:0 0 8px rgba(255,200,87,.5); }} .soc-dot-red {{ background:var(--soc-red);box-shadow:0 0 8px rgba(255,77,109,.5); }}
.soc-mini-label {{ color:var(--soc-muted-deep);font:900 .57rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase; }}
.soc-mini-value {{ color:var(--soc-text);font:800 .79rem/1.35 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin-top:.08rem;overflow-wrap:anywhere; }}
.soc-metric-card {{ position:relative;padding:.72rem .76rem;border-radius:7px;min-height:6.0rem;border:1px solid var(--soc-border);background:linear-gradient(180deg,#09161D,#061016);overflow:hidden; }}
.soc-metric-card::after {{ content:"";position:absolute;left:0;top:0;width:2px;height:100%;background:var(--soc-cyan);opacity:.82; }}
.soc-metric-card.critical::after {{ background:var(--soc-red); }} .soc-metric-card.high::after {{ background:var(--soc-orange); }} .soc-metric-card.medium::after {{ background:var(--soc-amber); }} .soc-metric-card.low::after {{ background:var(--soc-green); }}
.soc-metric-label {{ color:var(--soc-muted);font:900 .56rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.09em; }}
.soc-metric-value {{ color:var(--soc-text);font:900 1.45rem/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin-top:.35rem;letter-spacing:-.04em; }}
.soc-metric-note {{ color:var(--soc-muted-deep);font:700 .55rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin-top:.17rem; }}
.soc-pipeline {{ display:flex;align-items:stretch;gap:.25rem;flex-wrap:wrap; }}
.soc-stage {{ flex:1 1 112px;min-width:110px;padding:.52rem .48rem;border:1px solid var(--soc-border);background:linear-gradient(180deg,#09161D,#040C11);border-radius:6px;text-align:center;position:relative; }}
.soc-stage .n {{ color:var(--soc-cyan);font:900 .57rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.12em; }}
.soc-stage .t {{ color:var(--soc-text-soft);font:800 .62rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin-top:.12rem;text-transform:uppercase; }}
.soc-arrow {{ color:var(--soc-muted-deep);font-size:.82rem;display:flex;align-items:center; }}
.soc-strip {{ display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:.45rem; }}
.soc-strip-item {{ padding:.56rem .62rem;border:1px solid var(--soc-border);border-radius:6px;background:rgba(2,9,12,.75); }}
.soc-strip-label {{ color:var(--soc-muted-deep);font:900 .52rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;text-transform:uppercase;letter-spacing:.1em; }}
.soc-strip-value {{ color:var(--soc-text);font:900 .72rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;margin-top:.12rem;overflow-wrap:anywhere; }}
.soc-feed {{ display:flex;flex-direction:column;gap:.32rem; }}
.soc-feed-row {{ display:grid;grid-template-columns:62px 78px minmax(0,1fr) 140px;gap:.45rem;align-items:center;padding:.48rem .52rem;border:1px solid var(--soc-border);border-radius:5px;background:rgba(2,8,11,.7); }}
.soc-feed-row:hover {{ border-color:rgba(25,240,208,.25); background:rgba(6,18,23,.85); }}
.soc-feed-time {{ color:var(--soc-muted-deep);font:700 .59rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.soc-feed-threat {{ color:var(--soc-text-soft);font:800 .66rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }}
.soc-feed-meta {{ color:var(--soc-muted-deep);font:600 .57rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }}
.soc-badge {{ display:inline-flex;justify-content:center;align-items:center;min-width:63px;padding:.19rem .34rem;border-radius:999px;font:900 .53rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.055em;border:1px solid currentColor;background:rgba(255,255,255,.01); }}
.soc-badge-critical {{ color:var(--soc-red); }} .soc-badge-high {{ color:var(--soc-orange); }} .soc-badge-medium {{ color:var(--soc-amber); }} .soc-badge-low {{ color:var(--soc-green); }} .soc-badge-normal {{ color:var(--soc-muted); }}
.soc-note {{ color:var(--soc-muted);font:650 .62rem/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.soc-code-label {{ color:var(--soc-cyan);font:900 .58rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.08em;text-transform:uppercase; }}
.soc-terminal {{ color:var(--soc-green);font:800 .66rem/1.6 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:#020709;border:1px solid var(--soc-border);border-radius:6px;padding:.68rem .78rem;box-shadow:inset 0 0 28px rgba(39,227,139,.018); }}
.soc-terminal .prompt {{ color:var(--soc-cyan); }}
.soc-progress {{ height:7px;background:#031015;border:1px solid var(--soc-border);border-radius:999px;overflow:hidden;margin:.28rem 0 .1rem; }}
.soc-progress-fill {{ height:100%;background:linear-gradient(90deg,var(--soc-cyan),var(--soc-green));box-shadow:0 0 10px rgba(25,240,208,.36); }}
.soc-timeline {{ display:flex;flex-direction:column;gap:.25rem; }}
.soc-timeline-item {{ display:grid;grid-template-columns:68px 10px minmax(0,1fr);gap:.45rem;align-items:start; }}
.soc-timeline-time {{ color:var(--soc-muted-deep);font:700 .57rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding-top:.05rem; }}
.soc-timeline-dot {{ width:7px;height:7px;border-radius:50%;margin-top:.18rem;background:var(--soc-cyan);box-shadow:0 0 8px rgba(25,240,208,.52); }}
.soc-timeline-body {{ color:var(--soc-text-soft);font:750 .63rem/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;border-left:1px dashed var(--soc-border);padding-left:.48rem;padding-bottom:.34rem; }}
.soc-ioc {{ display:inline-flex;align-items:center;gap:.28rem;padding:.25rem .35rem;border:1px solid var(--soc-border);border-radius:5px;background:#030A0D;margin:.14rem .16rem .1rem 0;color:var(--soc-text-soft);font:800 .58rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }}
.soc-hint {{ color:var(--soc-muted-deep);font:700 .55rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.04em; }}
.soc-footer {{ color:#33504D;font:700 .54rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.08em;text-align:right;margin-top:.8rem; }}

@media (max-width:1000px) {{
  .soc-hero {{ grid-template-columns:1fr; }} .soc-hero-meta {{ justify-content:flex-start; }}
  .soc-strip {{ grid-template-columns:repeat(2,minmax(0,1fr)); }}
  .soc-feed-row {{ grid-template-columns:60px 72px minmax(0,1fr); }} .soc-feed-meta {{ display:none; }}
}}
@media (max-width:700px) {{
  .block-container {{ padding-left:.62rem; padding-right:.62rem; }} h1 {{ font-size:1.48rem !important; }}
  .soc-hero-title {{ font-size:1.28rem; }} .soc-strip {{ grid-template-columns:1fr; }}
  .soc-feed-row {{ grid-template-columns:58px minmax(0,1fr); }} .soc-feed-time {{ display:none; }}
}}

/* 6X MICRO-DETAIL LAYER // PRESENTATION-FINISH */
:root {{
  --soc-glass:rgba(7,17,23,.76); --soc-line:rgba(25,240,208,.085); --soc-focus:rgba(25,240,208,.42);
}}
::selection {{ background:rgba(25,240,208,.22); color:var(--soc-text); }}
::-webkit-scrollbar {{ width:8px; height:8px; }}
::-webkit-scrollbar-track {{ background:#02070A; }}
::-webkit-scrollbar-thumb {{ background:#12333B; border:2px solid #02070A; border-radius:99px; }}
::-webkit-scrollbar-thumb:hover {{ background:#1A5A64; }}
[data-testid="stMainBlockContainer"] > div {{ max-width:100%; }}
[data-testid="stVerticalBlock"] {{ gap:.34rem; }}
[data-testid="column"] {{ min-width:0; }}
[data-testid="stHorizontalBlock"] {{ align-items:stretch; }}
.stCaption, [data-testid="stCaptionContainer"] {{ letter-spacing:.015em; }}
button:focus-visible, input:focus-visible, textarea:focus-visible, [role="combobox"]:focus-visible {{
  outline:1px solid var(--soc-focus) !important; outline-offset:2px; box-shadow:0 0 0 3px rgba(25,240,208,.07) !important;
}}
.soc-page-index {{ display:inline-flex; align-items:center; gap:.35rem; margin:.08rem 0 .28rem; color:#496D67; font:900 .47rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:.16em; text-transform:uppercase; }}
.soc-page-index::before {{ content:""; width:18px; height:1px; background:var(--soc-cyan); box-shadow:0 0 8px rgba(25,240,208,.35); }}
.soc-hero::before {{ z-index:3; }} .soc-hero-grid {{ mix-blend-mode:screen; }} .soc-hero-meta {{ position:relative; z-index:4; }}
.soc-hero-title {{ text-wrap:balance; }} .soc-hero-sub {{ text-wrap:pretty; }}
/* SELECTIVE CURSOR INTERACTION // small movement + light sweep only on key analyst surfaces */
.soc-hero {{ cursor:default; }}
.soc-hero:hover {{ border-color:rgba(25,240,208,.28); box-shadow:0 16px 38px rgba(0,0,0,.24),0 0 30px rgba(25,240,208,.035); }}
.soc-command-bar {{ transition:border-color .18s ease, box-shadow .18s ease; }}
.soc-command-bar:hover {{ border-color:rgba(25,240,208,.22); box-shadow:inset 0 0 24px rgba(25,240,208,.028), 0 5px 18px rgba(0,0,0,.14); }}
.soc-meta-chip {{ cursor:default; }}
.soc-metric-card {{ will-change:transform; }}
.soc-metric-card::before {{ content:""; position:absolute; top:0; bottom:0; left:-80%; width:42%; z-index:1; transform:skewX(-16deg); background:linear-gradient(90deg,transparent,rgba(25,240,208,.08),transparent); opacity:0; pointer-events:none; }}
.soc-metric-card:hover::before {{ opacity:1; animation:socCardSweep .58s ease-out 1; }}
@keyframes socCardSweep {{ from {{ left:-80%; }} to {{ left:150%; }} }}
.soc-matrix-cell {{ transition:transform .15s ease,border-color .15s ease,box-shadow .15s ease,background .15s ease; }}
.soc-matrix-cell::after {{ content:""; position:absolute; left:12%; right:12%; top:50%; height:1px; background:linear-gradient(90deg,transparent,var(--soc-cyan),transparent); opacity:0; transform:scaleX(.2); pointer-events:none; }}
.soc-matrix-cell:hover {{ transform:translateY(-1px); border-color:rgba(25,240,208,.25); background:linear-gradient(180deg,rgba(7,19,25,.98),rgba(2,10,14,.98)); box-shadow:0 8px 20px rgba(0,0,0,.18),0 0 16px rgba(25,240,208,.028); }}
.soc-matrix-cell:hover::after {{ opacity:.28; animation:socMatrixSweep .72s ease-out 1; }}
@keyframes socMatrixSweep {{ 0% {{ transform:scaleX(.2); opacity:0; }} 35% {{ transform:scaleX(1); opacity:.32; }} 100% {{ transform:scaleX(.2); opacity:0; }} }}
.soc-stage {{ overflow:hidden; }}
.soc-stage::before {{ content:""; position:absolute; left:-30%; right:auto; top:0; width:30%; height:1px; background:linear-gradient(90deg,transparent,var(--soc-cyan),transparent); opacity:0; pointer-events:none; }}
.soc-stage:hover::before {{ opacity:.55; animation:socStageSweep .85s ease-out 1; }}
@keyframes socStageSweep {{ from {{ left:-30%; }} to {{ left:110%; }} }}
.soc-feed-row:hover {{ box-shadow:inset 2px 0 0 rgba(25,240,208,.34), 0 8px 20px rgba(0,0,0,.16); }}
.soc-ioc {{ transition:transform .14s ease,border-color .14s ease,background .14s ease,box-shadow .14s ease; }}
.soc-ioc:hover {{ transform:translateY(-1px); border-color:rgba(25,240,208,.22); background:#061318; box-shadow:0 5px 14px rgba(0,0,0,.14); }}
.soc-status {{ transition:transform .14s ease,border-color .14s ease,box-shadow .14s ease; }}
.soc-status:hover {{ transform:translateY(-1px); border-color:rgba(25,240,208,.20); box-shadow:0 5px 14px rgba(25,240,208,.035); }}
@media (prefers-reduced-motion: reduce) {{
  .soc-metric-card:hover::before, .soc-matrix-cell:hover::after, .soc-stage:hover::before {{ animation:none !important; }}
}}
.soc-meta-chip {{ transition:transform .15s ease,border-color .15s ease,background .15s ease; }}
.soc-meta-chip:hover {{ transform:translateY(-1px); border-color:rgba(25,240,208,.25); background:#061216; }}
.soc-credit {{ position:relative; overflow:hidden; }}
.soc-credit::before {{ content:"CREATOR SIGNATURE"; position:absolute; right:.65rem; top:.38rem; color:rgba(185,140,255,.23); font:900 .4rem ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; letter-spacing:.16em; }}
.soc-credit::after {{ content:""; position:absolute; left:0; bottom:0; width:100%; height:1px; background:linear-gradient(90deg,rgba(185,140,255,.45),rgba(25,240,208,.28),transparent); opacity:.65; }}
.soc-avatar {{ position:relative; }} .soc-avatar::after {{ content:""; position:absolute; inset:3px; border:1px solid rgba(255,255,255,.06); border-radius:10px; pointer-events:none; }}
.soc-ribbon-item {{ transition:transform .14s ease,border-color .14s ease,box-shadow .14s ease; }}
.soc-ribbon-item:hover {{ transform:translateY(-1px); border-color:rgba(25,240,208,.18); box-shadow:0 8px 20px rgba(0,0,0,.18); }}
.soc-ribbon-value {{ white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
.soc-metric-card {{ cursor:default; }} .soc-metric-card::before {{ z-index:2; }}
.soc-metric-card .soc-metric-value {{ font-variant-numeric:tabular-nums; }}
.soc-metric-card::after {{ transition:width .18s ease,opacity .18s ease; }} .soc-metric-card:hover::after {{ width:4px; opacity:1; }}
.stTextInput input, .stNumberInput input, textarea {{ border-radius:7px !important; min-height:2.45rem; font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace !important; font-size:.72rem !important; }}
[data-baseweb="select"] > div {{ border-radius:7px !important; min-height:2.45rem; }}
[data-baseweb="popover"] {{ border:1px solid var(--soc-border) !important; box-shadow:0 18px 48px rgba(0,0,0,.46) !important; }}
[data-baseweb="menu"] {{ background:#061016 !important; }} [data-baseweb="menu"] li {{ font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.68rem; }}
[data-baseweb="menu"] li:hover {{ background:rgba(25,240,208,.07) !important; }}
.stButton > button, .stDownloadButton > button {{ position:relative; overflow:hidden; }}
.stButton > button::after, .stDownloadButton > button::after {{ content:""; position:absolute; inset:0; transform:translateX(-110%); background:linear-gradient(90deg,transparent,rgba(255,255,255,.055),transparent); transition:transform .35s ease; pointer-events:none; }}
.stButton > button:hover::after, .stDownloadButton > button:hover::after {{ transform:translateX(110%); }}
[data-testid="stAlert"] {{ box-shadow:inset 3px 0 0 rgba(25,240,208,.35),0 8px 22px rgba(0,0,0,.16); }}
[data-testid="stStatusWidget"] {{ border-color:var(--soc-border) !important; }}
[data-testid="stDataFrame"] > div {{ background:#050D12; }} [data-testid="stDataFrame"] iframe {{ border-radius:6px; }} [data-testid="stDataFrame"] {{ box-shadow:0 10px 28px rgba(0,0,0,.17); }}
details[data-testid="stExpander"] summary:hover {{ background:rgba(25,240,208,.025); }}
[data-baseweb="tab"] {{ transition:color .14s ease,background .14s ease; border-radius:5px 5px 0 0; padding-left:.65rem !important; padding-right:.65rem !important; }}
[data-baseweb="tab"]:hover {{ background:rgba(25,240,208,.035); }}
.soc-terminal {{ border-left:2px solid rgba(25,240,208,.25); }} .soc-feed-row {{ transition:transform .12s ease,border-color .12s ease,background .12s ease; }}
.soc-feed-row:hover {{ transform:translateX(2px); }} .soc-feed-time {{ font-variant-numeric:tabular-nums; }}
.soc-badge {{ box-shadow:inset 0 0 0 1px rgba(255,255,255,.025); }}
.js-plotly-plot {{ border-radius:8px; overflow:hidden; }}
[data-testid="stVerticalBlockBorderWrapper"] {{ transition:border-color .15s ease,box-shadow .15s ease,transform .15s ease; }}
[data-testid="stVerticalBlockBorderWrapper"]:hover {{ transform:translateY(-1px); }}
.soc-footer {{ position:relative; color:#55756F; font-size:.49rem; letter-spacing:.11em; }}
.soc-footer::after {{ content:"DESAI // SOC_L2 // BUILD 120X"; float:right; color:rgba(185,140,255,.28); }}
@media (max-width:1100px) {{ .soc-hero {{ grid-template-columns:1fr; min-height:0; }} .soc-hero-meta {{ justify-content:flex-start; }} .soc-ribbon {{ grid-template-columns:repeat(2,minmax(0,1fr)); }} }}
@media (max-width:720px) {{
  .block-container {{ padding-left:.7rem !important; padding-right:.7rem !important; }} .soc-hero {{ padding:.95rem .82rem; }} .soc-hero-title {{ font-size:1.48rem; }}
  .soc-hero-meta {{ display:grid; grid-template-columns:1fr 1fr; }} .soc-ribbon {{ grid-template-columns:1fr; }}
  .soc-credit {{ grid-template-columns:48px minmax(0,1fr); }} .soc-avatar {{ width:46px; height:46px; }} .soc-credit-signature {{ display:none; }}
  .soc-feed-row {{ grid-template-columns:52px 68px minmax(0,1fr); }} .soc-feed-meta {{ display:none; }} .soc-strip {{ grid-template-columns:1fr 1fr; }}
}}
@media (prefers-reduced-motion:reduce) {{ *, *::before, *::after {{ scroll-behavior:auto !important; animation-duration:.001ms !important; animation-iteration-count:1 !important; transition-duration:.001ms !important; }} }}

/* FINAL VISUAL QA // HEADER CLEARANCE + OVERFLOW SAFETY */
[data-testid="stHeader"] {{ position:fixed !important; top:0; z-index:1000; }}
[data-testid="stSidebarNav"], nav[data-testid="stSidebarNav"] {{ display:none !important; }}
@media (max-width:900px) {{
  .soc-command-right {{ display:none; }}
  .soc-command-left span:last-child {{ white-space:normal; line-height:1.25; }}
}}
@media (max-width:700px) {{
  .block-container {{ padding-top:3.7rem !important; }}
  .soc-command-bar {{ align-items:flex-start; }}
  .soc-command-left {{ flex-wrap:wrap; gap:.35rem .55rem; }}
  .soc-hero-meta {{ justify-content:flex-start; }}
}}

/* FINAL READABILITY + HORIZONTAL ROOM PASS
   Keep headline/hero fonts unchanged; enlarge only the compact technical copy. */
.block-container {{
  width:100% !important;
  max-width:none !important;
  padding-left:1.05rem !important;
  padding-right:1.05rem !important;
}}
[data-testid="stMainBlockContainer"] {{ width:100% !important; max-width:none !important; }}
[data-testid="stMainBlockContainer"] > div {{ width:100% !important; max-width:none !important; }}
[data-testid="column"] {{ min-width:0 !important; }}

/* Compact text: +1 visual step, while large titles/values remain untouched. */
section[data-testid="stSidebar"] [data-testid="stPageLink"] a {{ font-size:.78rem; }}
[data-testid="stCaptionContainer"], .stCaption {{ font-size:.80rem !important; line-height:1.45 !important; }}
[data-baseweb="tab"] {{ font-size:.78rem !important; }}
label {{ font-size:.78rem !important; }}
.soc-command-bar {{ font-size:.60rem; line-height:1.35; }}
.soc-kicker {{ font-size:.68rem; }}
.soc-brand-sub {{ font-size:.65rem; }}
.soc-hero-sub {{ font-size:.76rem; }}
.soc-section-caption {{ font-size:.70rem; }}
.soc-mini-label {{ font-size:.63rem; }}
.soc-matrix-label {{ font-size:.57rem; }}
.soc-matrix-value {{ font-size:.65rem; line-height:1.4; }}
.soc-stage .n {{ font-size:.62rem; }}
.soc-stage .t {{ font-size:.69rem; }}
.soc-strip-label {{ font-size:.58rem; }}
.soc-strip-value {{ font-size:.78rem; }}
.soc-feed-time {{ font-size:.64rem; }}
.soc-feed-threat {{ font-size:.71rem; }}
.soc-feed-meta {{ font-size:.64rem; }}
.soc-note {{ font-size:.68rem; }}
.soc-timeline-time {{ font-size:.64rem; }}
.soc-timeline-body {{ font-size:.70rem; line-height:1.45; }}
.soc-hint {{ font-size:.61rem; }}
.soc-footer {{ font-size:.55rem; }}
.soc-terminal::before {{ font-size:.55rem; }}
.soc-terminal {{ font-size:.71rem; line-height:1.65; }}
.stTextInput input, .stNumberInput input, textarea {{ font-size:.78rem !important; }}
[data-baseweb="menu"] li {{ font-size:.74rem; }}

@media (max-width:900px) {{
  .block-container {{ padding-left:.82rem !important; padding-right:.82rem !important; }}
}}


</style>
"""


def sort_alerts_newest_first(df: pd.DataFrame) -> pd.DataFrame:
    """Return a copy sorted newest-first by UTC timestamp."""
    if df is None or df.empty or "timestamp" not in df.columns:
        return df.copy() if isinstance(df, pd.DataFrame) else df
    view = df.copy()
    parsed = pd.to_datetime(view["timestamp"], utc=True, errors="coerce")
    view["__ui_sort_timestamp"] = parsed
    view = view.sort_values("__ui_sort_timestamp", ascending=False, na_position="last", kind="stable")
    return view.drop(columns=["__ui_sort_timestamp"])


def apply_theme(st_module: Any) -> None:
    """Apply the shared hacker-terminal SOC theme."""
    st_module.markdown(UI_CSS, unsafe_allow_html=True)


def page_header(st_module: Any, title: str, subtitle: str, kicker: str = "SOC // L2 // COMMAND CONSOLE") -> None:
    """Render a terminal-style hero header."""
    st_module.markdown(
        f'<div class="soc-command-bar"><div class="soc-command-left"><span class="soc-pulse"></span><b>SECURE LINK</b><span>// telemetry surface // analyst workspace // evidence locked</span></div><div class="soc-command-right">L2 / ADVISORY MODE</div></div>'
        f'<div class="soc-hero">'
        f'<div class="soc-hero-grid"></div><div class="soc-scanline"></div><div class="soc-vscan"></div>'
        f'<span class="soc-corner tl"></span><span class="soc-corner tr"></span><span class="soc-corner bl"></span><span class="soc-corner br"></span>'
        f'<div><div class="soc-kicker">{html.escape(str(kicker))}</div>'
        f'<div class="soc-hero-title">{html.escape(str(title))}</div>'
        f'<div class="soc-hero-sub">$ {html.escape(str(subtitle))}</div>'
        f'<div class="soc-hero-live">COMMAND CHANNEL ACTIVE // HUMAN DECISION REQUIRED</div></div>'
        f'<div class="soc-hero-meta">'
        f'<span class="soc-meta-chip"><span class="soc-meta-dot"></span>EVIDENCE FIRST</span>'
        f'<span class="soc-meta-chip"><span class="soc-meta-dot-green"></span>HUMAN IN LOOP</span>'
        f'<span class="soc-meta-chip"><span class="soc-meta-dot-amber"></span>NO AUTO ACTION</span>'
        f'</div></div>', unsafe_allow_html=True,
    )


def section_title(st_module: Any, title: str, caption: str | None = None) -> None:
    """Render a consistent terminal-like section title with selective scanner treatment."""
    safe_title = str(title)
    scanner_titles = {
        "Global Search", "Live SOC Snapshot", "AI SOC Assistant",
        "SOC Command Matrix", "Threat Monitor", "Live Event Stream",
    }
    section_class = "soc-section soc-section-critical" if safe_title in scanner_titles else "soc-section"
    markup = f'<div class="{section_class}"><div class="soc-section-title">{html.escape(safe_title)}</div>'
    if caption:
        markup += f'<div class="soc-section-caption">{html.escape(str(caption))}</div>'
    markup += '</div>'
    st_module.markdown(markup, unsafe_allow_html=True)


def status_badge(st_module: Any, text: str, tone: str = "info") -> None:
    """Render a compact system status badge."""
    dot = {"success": "soc-dot-green", "warning": "soc-dot-amber", "error": "soc-dot-red", "info": ""}.get(tone, "")
    st_module.markdown(
        f'<span class="soc-status"><span class="soc-dot {dot}"></span>{html.escape(str(text))}</span>',
        unsafe_allow_html=True,
    )


def mini_field(st_module: Any, label: str, value: Any) -> None:
    """Render one compact technical field."""
    st_module.markdown(
        f'<div class="soc-mini-label">{html.escape(str(label))}</div><div class="soc-mini-value">{value}</div>',
        unsafe_allow_html=True,
    )


def metric_card(st_module: Any, label: str, value: Any, tone: str = "normal", note: str | None = None) -> None:
    """Render a custom KPI card with severity-aware edge styling."""
    note_html = f'<div class="soc-metric-note">{html.escape(str(note))}</div>' if note else ""
    st_module.markdown(
        f'<div class="soc-metric-card {html.escape(str(tone or "normal").lower())}">'
        f'<div class="soc-metric-label">{html.escape(str(label))}</div>'
        f'<div class="soc-metric-value">{html.escape(str(value))}</div>{note_html}</div>',
        unsafe_allow_html=True,
    )


def render_kv_cards(st_module: Any, items: Iterable[tuple[str, Any]], columns: int = 3) -> None:
    """Render analyst key/value cards using native Streamlit containers."""
    items = list(items)
    for start in range(0, len(items), columns):
        row = items[start:start + columns]
        cols = st_module.columns(columns)
        for idx, (label, value) in enumerate(row):
            with cols[idx]:
                with st_module.container(border=True):
                    mini_field(st_module, label, value)


def show_pipeline(st_module: Any) -> None:
    """Render the end-to-end SOC processing pipeline."""
    stages = [
        ("01", "Source"), ("02", "Parser"), ("03", "Normalizer"), ("04", "Detection"),
        ("05", "Risk / Severity"), ("06", "MITRE"), ("07", "Investigation"), ("08", "AI / Report"),
    ]
    parts = ['<div class="soc-pipeline">']
    for index, (num, title) in enumerate(stages):
        parts.append(f'<div class="soc-stage"><div class="n">{num}</div><div class="t">{html.escape(title)}</div></div>')
        if index < len(stages) - 1:
            parts.append('<div class="soc-arrow">›</div>')
    parts.append('</div>')
    st_module.markdown("".join(parts), unsafe_allow_html=True)


def nav_brand(st_module: Any, subtitle: str, status_text: str = "SYSTEM ONLINE", status_tone: str = "success") -> None:
    """Render the sidebar command-center identity."""
    st_module.markdown(
        f'<div class="soc-brand"><div class="soc-brand-row">'
        f'<div><div class="soc-brand-title">SOC_L2 // AGENT</div>'
        f'<div class="soc-brand-sub">{html.escape(str(subtitle))}</div></div>'
        f'<div class="soc-brand-mark">&gt;_</div></div></div>',
        unsafe_allow_html=True,
    )
    status_badge(st_module, status_text, status_tone)


def navigation_links(st_module: Any, include_system: bool = False) -> None:
    """Render one grouped SOC navigation surface; Streamlit's automatic nav is disabled in config."""
    st_module.markdown("**CORE OPERATIONS //**")
    st_module.page_link("app.py", label="Dashboard", icon="🛡️")
    st_module.page_link("pages/Ingestion.py", label="Ingestion Center", icon="📥")
    st_module.page_link("pages/Investigation.py", label="Investigation", icon="🔎")

    st_module.markdown("**SECURITY INTELLIGENCE //**")
    st_module.page_link("pages/Analytics.py", label="Analytics", icon="📊")
    st_module.page_link("pages/MITRE_Center.py", label="MITRE ATT&CK", icon="🎯")
    st_module.page_link("pages/IOC_Intelligence.py", label="IOC Intelligence", icon="🧬")

    st_module.markdown("**ENGINEERING //**")
    st_module.page_link("pages/Detection_Engineering.py", label="Detection Engineering", icon="🧪")

    st_module.markdown("**GOVERNANCE //**")
    st_module.page_link("pages/Reports.py", label="Reports Center", icon="📄")
    st_module.page_link("pages/Audit_Log.py", label="Audit Log", icon="📜")
    st_module.page_link("pages/Settings.py", label="Settings", icon="⚙️")
    if include_system:
        st_module.markdown("**PRESENTATION //**")
        st_module.caption("Demo mode keeps response actions analyst-controlled.")


def command_matrix(st_module: Any, posture: str, posture_tone: str, events: Any, detections: Any, source: Any, pipeline: str) -> None:
    """Render a compact command-center posture matrix using observable state only."""
    tone_class = {"success": "soc-meta-dot-green", "warning": "soc-meta-dot-amber", "error": "soc-meta-dot-red", "info": "soc-meta-dot"}.get(str(posture_tone), "soc-meta-dot")
    items = [
        ("CURRENT POSTURE", posture, tone_class),
        ("EVIDENCE MODE", "AUTHORITATIVE TELEMETRY", "soc-meta-dot"),
        ("ANALYST CONTROL", "HUMAN APPROVAL", "soc-meta-dot-green"),
        ("PIPELINE STATE", pipeline, "soc-meta-dot-green" if pipeline == "READY" else "soc-meta-dot-amber"),
        ("EVENT SURFACE", f"{int(events):,} EVENTS // {int(detections):,} DETECTIONS", "soc-meta-dot"),
        ("SOURCE CHANNEL", str(source).upper(), "soc-meta-dot"),
    ]
    parts = ['<div class="soc-command-matrix">']
    for label, value, dot in items:
        parts.append(
            f'<div class="soc-matrix-cell"><div class="soc-matrix-label">{html.escape(str(label))}</div>'
            f'<div class="soc-matrix-value"><span class="{dot}"></span>{html.escape(str(value))}</div></div>'
        )
    parts.append('</div>')
    st_module.markdown("".join(parts), unsafe_allow_html=True)


def operational_strip(st_module: Any, items: Iterable[tuple[str, Any, str]]) -> None:
    """Render compact status tiles."""
    parts = ['<div class="soc-strip">']
    for label, value, tone in items:
        dot = {"success": "soc-meta-dot-green", "warning": "soc-meta-dot-amber", "error": "soc-meta-dot-red", "info": "soc-meta-dot"}.get(str(tone), "soc-meta-dot")
        parts.append(
            f'<div class="soc-strip-item"><div class="soc-strip-label">{html.escape(str(label))}</div>'
            f'<div class="soc-strip-value"><span class="{dot}" style="display:inline-block;margin-right:6px;"></span>{html.escape(str(value))}</div></div>'
        )
    parts.append('</div>')
    st_module.markdown("".join(parts), unsafe_allow_html=True)


def alert_feed_html(rows: Iterable[dict[str, Any]]) -> str:
    """Build the terminal-style alert feed."""
    parts = ['<div class="soc-feed">']
    for row in rows:
        severity = str(row.get("severity") or "Normal")
        sev_class = {"Critical": "critical", "High": "high", "Medium": "medium", "Low": "low"}.get(severity, "normal")
        parts.append(
            f'<div class="soc-feed-row">'
            f'<div class="soc-feed-time">{html.escape(str(row.get("time") or "--:--"))}</div>'
            f'<div><span class="soc-badge soc-badge-{sev_class}">{html.escape(severity.upper())}</span></div>'
            f'<div class="soc-feed-threat">{html.escape(str(row.get("threat") or "Unclassified Event"))}</div>'
            f'<div class="soc-feed-meta">{html.escape(str(row.get("meta") or ""))}</div>'
            f'</div>'
        )
    parts.append('</div>')
    return "".join(parts)


def terminal_box(st_module: Any, lines: Iterable[str], prompt: str = "soc@l2:~$") -> None:
    """Render compact terminal-like diagnostic text."""
    safe_lines = [html.escape(str(x)) for x in lines]
    body = "<br>".join([f'<span class="prompt">{html.escape(prompt)}</span> {line}' for line in safe_lines])
    st_module.markdown(f'<div class="soc-terminal">{body}</div>', unsafe_allow_html=True)


def progress_bar(st_module: Any, value: float, label: str, suffix: str | None = None) -> None:
    """Render a compact percentage/progress bar."""
    pct = max(0.0, min(100.0, float(value)))
    safe_label = html.escape(str(label))
    safe_suffix = html.escape(str(suffix if suffix is not None else f"{pct:.0f}%"))
    st_module.markdown(
        f'<div class="soc-mini-label">{safe_label} <span style="float:right;color:var(--soc-text-soft)">{safe_suffix}</span></div>'
        f'<div class="soc-progress"><div class="soc-progress-fill" style="width:{pct:.1f}%"></div></div>',
        unsafe_allow_html=True,
    )


def timeline_html(st_module: Any, items: Iterable[tuple[str, str]]) -> None:
    """Render an analyst workflow timeline."""
    parts = ['<div class="soc-timeline">']
    for time_text, text_value in items:
        parts.append(
            f'<div class="soc-timeline-item"><div class="soc-timeline-time">{html.escape(str(time_text))}</div>'
            f'<div class="soc-timeline-dot"></div><div class="soc-timeline-body">{html.escape(str(text_value))}</div></div>'
        )
    parts.append('</div>')
    st_module.markdown("".join(parts), unsafe_allow_html=True)


def ioc_chip(st_module: Any, kind: str, value: Any) -> None:
    """Render an IOC chip without altering or enriching the underlying evidence."""
    st_module.markdown(
        f'<span class="soc-ioc"><b>{html.escape(str(kind))}</b> {html.escape(str(value))}</span>',
        unsafe_allow_html=True,
    )


def footer(st_module: Any, text: str = "SOC_L2 // EVIDENCE FIRST // AI ADVISORY // HUMAN DECISION") -> None:
    """Render the small command-console footer."""
    st_module.markdown(f'<div class="soc-footer">{html.escape(text)}</div>', unsafe_allow_html=True)


def data_quality_cards(st_module: Any, summary: dict[str, Any]) -> None:
    """Render compact data quality metrics from observable telemetry."""
    items = [
        ("VALID IDS", summary.get("valid_ids", 0), "success" if summary.get("valid_ids", 0) == summary.get("records", 0) else "warning"),
        ("VALID TIMESTAMPS", summary.get("valid_timestamps", 0), "success" if summary.get("valid_timestamps", 0) == summary.get("records", 0) else "warning"),
        ("PARSER ERRORS", summary.get("parser_errors", 0), "success" if not summary.get("parser_errors") else "warning"),
        ("NORMALIZER ERRORS", summary.get("normalizer_errors", 0), "success" if not summary.get("normalizer_errors") else "warning"),
        ("MISSING CORE", summary.get("missing_core_fields", 0), "success" if not summary.get("missing_core_fields") else "warning"),
        ("DUPLICATE EVENTS", summary.get("duplicate_events", 0), "success" if not summary.get("duplicate_events") else "warning"),
    ]
    cols = st_module.columns(6)
    for col, (label, value, tone) in zip(cols, items):
        with col:
            metric_card(st_module, label, f"{int(value):,}", tone, f"of {int(summary.get('records', 0)):,} records")


def command_palette(st_module: Any, options: list[str], *, key: str = "global_command_palette") -> str:
    """Provide a lightweight global search/command selector for the analyst console."""
    choice = st_module.selectbox("COMMAND / SEARCH", ["Type or choose…"] + options, key=key)
    return "" if choice == "Type or choose…" else str(choice)
