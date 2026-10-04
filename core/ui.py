"""Shared Streamlit presentation helpers for the SOC L2 Agent.

This module keeps visual styling and page-level layout conventions in one place.
Production logic remains in the core/engine/services modules; this file is only
for the presentation layer and professor-friendly navigation.
"""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Common Streamlit theme, headings aur pipeline status UI ko ek jagah maintain karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# PRESENTATION THEME - STREAMLIT UI SETTINGS
# ---------------------------------------------------------------------------
# Previous build me custom HTML containers aur native Streamlit blocks mix ho rahe the.
# Native bordered containers safer hain kyunki Streamlit khud unka DOM/layout manage karta hai.
UI_CSS = """
<style>
:root {
  --soc-bg: #f5f7fb;
  --soc-panel: #ffffff;
  --soc-ink: #162033;
  --soc-muted: #667085;
  --soc-line: #dfe5ee;
  --soc-primary: #2563eb;
  --soc-primary-dark: #1d4ed8;
}
.stApp { background: var(--soc-bg); color: var(--soc-ink); }
.block-container { max-width: 1380px; padding-top: 1.1rem; padding-bottom: 2.6rem; }
[data-testid="stHeader"] { background: rgba(0,0,0,0); }
[data-testid="stMetric"] {
  background: var(--soc-panel);
  border: 1px solid var(--soc-line);
  border-radius: 12px;
  padding: 0.72rem 0.85rem;
  box-shadow: 0 3px 12px rgba(16, 24, 40, 0.045);
}
[data-testid="stMetricLabel"] { color: var(--soc-muted); font-weight: 600; }
[data-testid="stMetricValue"] { color: var(--soc-ink); font-weight: 800; }
.stButton > button {
  border-radius: 9px;
  min-height: 2.55rem;
  font-weight: 650;
  border: 1px solid var(--soc-line);
}
.stButton > button:hover { border-color: #b9c5d6; }
button[kind="primary"] {
  background: var(--soc-primary);
  border-color: var(--soc-primary);
}
button[kind="primary"]:hover { background: var(--soc-primary-dark); border-color: var(--soc-primary-dark); }
[data-testid="stDataFrame"] { border: 1px solid var(--soc-line); border-radius: 10px; overflow: hidden; }
[data-baseweb="tab-list"] { gap: 0.25rem; }
[data-baseweb="tab"] { font-weight: 650; }
hr { border-color: var(--soc-line); }
@media (max-width: 768px) {
  .block-container { padding-left: 0.8rem; padding-right: 0.8rem; padding-top: 0.8rem; }
  h1 { font-size: 1.65rem !important; }
  h2 { font-size: 1.35rem !important; }
  h3 { font-size: 1.1rem !important; }
  [data-testid="stMetric"] { padding: 0.62rem 0.7rem; }
}
</style>
"""


# FUNCTION: apply_theme
# Purpose: Ye function apply theme operation handle karta hai.
# Input: st_module.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def apply_theme(st_module: Any) -> None:
    """Apply the shared light SOC theme without creating structural HTML wrappers."""
    st_module.markdown(UI_CSS, unsafe_allow_html=True)


# FUNCTION: page_header
# Purpose: Ye function ka main kaam page header se related processing ko centrally handle karna hai.
# Input: st_module, title, subtitle.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def page_header(st_module: Any, title: str, subtitle: str) -> None:
    """Render a restrained page header suitable for projector, laptop and phone."""
    st_module.title(title)
    st_module.caption(subtitle)
    st_module.divider()


# FUNCTION: section_title
# Purpose: Ye function ka main kaam section title se related processing ko centrally handle karna hai.
# Input: st_module, title, caption.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def section_title(st_module: Any, title: str, caption: str | None = None) -> None:
    """Render a consistent section heading using native Markdown only."""
    st_module.subheader(title)
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if caption:
        st_module.caption(caption)


# FUNCTION: show_pipeline
# Purpose: Ye function show pipeline operation handle karta hai.
# Input: st_module.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def show_pipeline(st_module: Any) -> None:
    """Show the core processing stages as readable documentation for the demo."""
    st_module.caption(
        "Pipeline: Data Source → Parser → Normalizer → Detection → Severity / Risk / Confidence → MITRE → Investigation → AI / PDF"
    )
