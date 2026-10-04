"""Dashboard chart helpers with defensive handling for empty data."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Dashboard ke charts banata hai aur empty/malformed data ko safely handle karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import pandas as pd

try:
    import plotly.express as px
    import plotly.graph_objects as go
except ImportError:  # pragma: no cover - used only in incomplete installs.
    px = None
    go = None


# ---------------------------------------------------------------------------
# VISUAL DESIGN TOKENS - DASHBOARD STYLE VALUES
# ---------------------------------------------------------------------------
PALETTE = {
    "Critical": "#DC2626",
    "High": "#EA580C",
    "Medium": "#D97706",
    "Low": "#2563EB",
    "Normal": "#64748B",
    "Anomaly": "#7C3AED",
}


# FUNCTION: _base_fig
# Purpose: Ye internal helper ka main kaam base fig se related processing ko centrally handle karna hai.
# Input: fig.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _base_fig(fig):
    """Apply a consistent, high-contrast Plotly layout to every chart."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if fig is None:
        return None
    fig.update_layout(
        template="plotly_white",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="#FFFFFF",
        font={"family": "Arial, sans-serif", "color": "#0F172A", "size": 12},
        margin={"l": 18, "r": 18, "t": 48, "b": 20},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.01, "x": 0},
        hoverlabel={"bgcolor": "#0F172A", "font_color": "#FFFFFF"},
    )
    return fig


# FUNCTION: _empty_message
# Purpose: Ye internal helper ka main kaam empty message se related processing ko centrally handle karna hai.
# Input: title.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _empty_message(title: str):
    """Return a placeholder chart instead of throwing on empty telemetry."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if go is None:
        return None
    fig = go.Figure()
    fig.add_annotation(text="No chart data available", x=0.5, y=0.5, showarrow=False)
    fig.update_layout(title=title, xaxis_visible=False, yaxis_visible=False)
    return _base_fig(fig)


# FUNCTION: severity_donut
# Purpose: Ye function ka main kaam severity donut se related processing ko centrally handle karna hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def severity_donut(df: pd.DataFrame):
    """Build the severity distribution donut with labels kept in the legend."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if px is None or df.empty or "severity" not in df.columns:
        return _empty_message("Severity Distribution")
    order = ["Critical", "High", "Medium", "Low", "Normal"]
    counts = df["severity"].fillna("Normal").value_counts().reindex(order, fill_value=0).reset_index()
    counts.columns = ["Severity", "Events"]
    counts = counts[counts["Events"] > 0]
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if counts.empty:
        return _empty_message("Severity Distribution")
    fig = px.pie(
        counts, names="Severity", values="Events", hole=0.62,
        color="Severity", color_discrete_map=PALETTE,
        category_orders={"Severity": order},
    )
    # Chart ka center clean rakha gaya hai; legend aur hover details har slice ko identify kar dete hain.
    fig.update_traces(textinfo="none", hovertemplate="%{label}: %{value}<extra></extra>")
    fig.update_layout(title="Severity Distribution")
    return _base_fig(fig)


# FUNCTION: detection_bar
# Purpose: Ye function ka main kaam detection bar se related processing ko centrally handle karna hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def detection_bar(df: pd.DataFrame):
    """Build the final detection-state bar chart."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if px is None or df.empty or "final_detection" not in df.columns:
        return _empty_message("Detection State")
    counts = df["final_detection"].fillna("Normal").value_counts().reset_index()
    counts.columns = ["Detection", "Events"]
    fig = px.bar(
        counts, x="Events", y="Detection", orientation="h",
        color="Detection", color_discrete_map=PALETTE,
        text="Events",
    )
    fig.update_traces(textposition="outside", cliponaxis=False)
    fig.update_layout(title="Detection State", yaxis_title="", xaxis_title="Events")
    return _base_fig(fig)


# FUNCTION: top_techniques
# Purpose: Ye function ka main kaam top techniques se related processing ko centrally handle karna hai.
# Input: df, limit.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def top_techniques(df: pd.DataFrame, limit: int = 8):
    """Build a compact MITRE-technique frequency chart from supported mappings only."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if px is None or df.empty or "mapped_technique" not in df.columns:
        return _empty_message("Top MITRE Techniques")
    values: list[str] = []
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for raw in df["mapped_technique"].tolist():
        text = str(raw or "").strip()
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if not text or text.lower().startswith("not mapped"):
            continue
        values.extend(part.strip() for part in text.split(",") if part.strip())
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if not values:
        return _empty_message("Top MITRE Techniques")
    counts = pd.Series(values, dtype="string").value_counts().head(limit).sort_values().reset_index()
    counts.columns = ["Technique", "Events"]
    fig = px.bar(counts, x="Events", y="Technique", orientation="h", text="Events")
    fig.update_traces(marker_color="#334155", textposition="outside", cliponaxis=False)
    fig.update_layout(title="Top MITRE Techniques", yaxis_title="", xaxis_title="Events")
    return _base_fig(fig)


# FUNCTION: alert_trend
# Purpose: Ye function ka main kaam alert trend se related processing ko centrally handle karna hai.
# Input: df.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def alert_trend(df: pd.DataFrame):
    """Build a daily telemetry-volume chart using only valid timestamps."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if px is None or df.empty or "timestamp" not in df.columns:
        return _empty_message("Telemetry Volume Over Time")
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    tmp = pd.DataFrame({"timestamp": ts}).dropna(subset=["timestamp"])
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if tmp.empty:
        return _empty_message("Telemetry Volume Over Time")
    tmp["date"] = tmp["timestamp"].dt.floor("D")
    agg = tmp.groupby("date", as_index=False).agg(Events=("date", "size"))
    fig = px.line(agg, x="date", y="Events", markers=True)
    fig.update_traces(line={"color": "#2563EB", "width": 3}, marker={"size": 7})
    fig.update_layout(title="Telemetry Volume Over Time", yaxis_title="Events", xaxis_title="")
    return _base_fig(fig)


# FUNCTION: safe_chart
# Purpose: Ye function ka main kaam safe chart se related processing ko centrally handle karna hai.
# Input: fig, st, height, key.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def safe_chart(fig, st, *, height: int = 300, key: str | None = None) -> None:
    """Render a chart safely with a stable widget key when one is supplied."""
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if fig is None:
        st.info("Install the project requirements to enable interactive charts.")
        return
    fig.update_layout(height=height)
    kwargs = {"use_container_width": True, "config": {"displayModeBar": False}}
    # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
    if key:
        kwargs["key"] = key
    st.plotly_chart(fig, **kwargs)
