"""Dark hacker-console Plotly charts for the SOC L2 Agent."""
from __future__ import annotations

import pandas as pd

try:
    import plotly.express as px
    import plotly.graph_objects as go
except ImportError:  # pragma: no cover
    px = None
    go = None

PALETTE = {
    "Critical": "#FF4D6D", "High": "#FF8A3D", "Medium": "#FFC857",
    "Low": "#27E38B", "Normal": "#4D6E69", "Anomaly": "#B98CFF",
}
SOC_CYAN = "#19F0D0"
SOC_BLUE = "#4FB8FF"
SOC_GRID = "#15303B"
SOC_PANEL = "#081117"
SOC_TEXT = "#E8FFF5"
SOC_MUTED = "#688E87"


def _base_fig(fig, *, title: str | None = None):
    if fig is None:
        return None
    fig.update_layout(
        template=None,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor=SOC_PANEL,
        font={"family": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", "color": SOC_TEXT, "size": 11},
        margin={"l": 18, "r": 18, "t": 48, "b": 28},
        title={"text": title or fig.layout.title.text, "x": 0.02, "xanchor": "left", "font": {"size": 13, "color": SOC_TEXT, "family": "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"}},
        legend={"orientation": "h", "yanchor": "top", "y": -0.13, "x": 0, "font": {"size": 10, "color": SOC_MUTED}},
        hoverlabel={"bgcolor": "#061016", "bordercolor": SOC_GRID, "font": {"color": SOC_TEXT, "family": "ui-monospace, monospace"}},
        uirevision="soc-l2-final",
    )
    fig.update_xaxes(showgrid=True, gridcolor=SOC_GRID, zeroline=False, linecolor=SOC_GRID, tickfont={"color": SOC_MUTED, "size": 10})
    fig.update_yaxes(showgrid=True, gridcolor=SOC_GRID, zeroline=False, linecolor=SOC_GRID, tickfont={"color": SOC_MUTED, "size": 10})
    return fig


def _empty_message(title: str):
    if go is None:
        return None
    fig = go.Figure()
    fig.add_annotation(text="NO CHART DATA AVAILABLE", x=0.5, y=0.5, showarrow=False, font={"color": SOC_MUTED, "size": 11, "family": "ui-monospace, monospace"})
    fig.update_layout(title=title, xaxis_visible=False, yaxis_visible=False)
    return _base_fig(fig, title=title)


def severity_donut(df: pd.DataFrame):
    if px is None or df.empty or "severity" not in df.columns:
        return _empty_message("SEVERITY MATRIX")
    order = ["Critical", "High", "Medium", "Low", "Normal"]
    counts = df["severity"].fillna("Normal").value_counts().reindex(order, fill_value=0).reset_index()
    counts.columns = ["Severity", "Events"]
    counts = counts[counts["Events"] > 0]
    if counts.empty:
        return _empty_message("SEVERITY MATRIX")
    fig = px.pie(counts, names="Severity", values="Events", hole=0.72, color="Severity", color_discrete_map=PALETTE, category_orders={"Severity": order})
    fig.update_traces(textinfo="percent", textposition="inside", textfont={"color": "#FFFFFF", "size": 11}, marker={"line": {"color": "#020609", "width": 2}}, hovertemplate="%{label}: %{value}<extra></extra>")
    fig.update_layout(legend={"orientation": "v", "y": 0.5, "x": 1.0, "font": {"color": SOC_MUTED, "size": 9}})
    fig.add_annotation(text=f"<b>{int(len(df)):,}</b><br><span style='font-size:10px'>EVENTS</span>", x=0.42, y=0.5, showarrow=False, font={"color": SOC_TEXT, "size": 13})
    return _base_fig(fig, title="SEVERITY MATRIX")


def detection_bar(df: pd.DataFrame):
    if px is None or df.empty or "final_detection" not in df.columns:
        return _empty_message("DETECTION STATES")
    counts = df["final_detection"].fillna("Normal").value_counts().reset_index()
    counts.columns = ["Detection", "Events"]
    counts = counts.sort_values("Events", ascending=True)
    fig = px.bar(counts, x="Events", y="Detection", orientation="h", text="Events")
    fig.update_traces(marker_color=SOC_CYAN, marker_line_color="#020609", marker_line_width=1, textposition="outside", textfont={"color": SOC_TEXT, "size": 11}, hovertemplate="%{y}: %{x}<extra></extra>")
    return _base_fig(fig, title="DETECTION STATES")


def top_techniques(df: pd.DataFrame, limit: int = 8):
    if px is None or df.empty or "mapped_technique" not in df.columns:
        return _empty_message("MITRE COVERAGE")
    values: list[str] = []
    for raw in df["mapped_technique"].tolist():
        text = str(raw or "").strip()
        if not text or text.lower().startswith("not mapped"):
            continue
        values.extend(part.strip() for part in text.split(",") if part.strip())
    if not values:
        return _empty_message("MITRE COVERAGE")
    counts = pd.Series(values, dtype="string").value_counts().head(limit).sort_values().reset_index()
    counts.columns = ["Technique", "Events"]
    fig = px.bar(counts, x="Events", y="Technique", orientation="h", text="Events")
    fig.update_traces(marker_color=SOC_BLUE, marker_line_color="#020609", marker_line_width=1, textposition="outside", textfont={"color": SOC_TEXT, "size": 11}, hovertemplate="%{y}: %{x}<extra></extra>")
    return _base_fig(fig, title="MITRE COVERAGE")


def alert_trend(df: pd.DataFrame):
    if px is None or df.empty or "timestamp" not in df.columns:
        return _empty_message("TELEMETRY ACTIVITY")
    ts = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
    tmp = pd.DataFrame({"timestamp": ts}).dropna(subset=["timestamp"])
    if tmp.empty:
        return _empty_message("TELEMETRY ACTIVITY")
    tmp["date"] = tmp["timestamp"].dt.floor("D")
    agg = tmp.groupby("date", as_index=False).agg(Events=("date", "size"))
    fig = px.line(agg, x="date", y="Events", markers=True)
    fig.update_traces(line={"color": SOC_CYAN, "width": 2.5}, marker={"color": SOC_CYAN, "size": 6, "line": {"color": "#020609", "width": 1}}, fill="tozeroy", fillcolor="rgba(25,240,208,0.06)", hovertemplate="%{x|%d %b %Y}: %{y} events<extra></extra>")
    return _base_fig(fig, title="TELEMETRY ACTIVITY")


def risk_distribution(df: pd.DataFrame, bins: int = 6):
    if px is None or df.empty or "risk_score" not in df.columns:
        return _empty_message("RISK DISTRIBUTION")
    series = pd.to_numeric(df["risk_score"], errors="coerce").dropna()
    if series.empty:
        return _empty_message("RISK DISTRIBUTION")
    bucket = pd.cut(series, bins=[-0.01, 2, 4, 6, 7.5, 9, 10], labels=["0–2", "2–4", "4–6", "6–7.5", "7.5–9", "9–10"], include_lowest=True)
    counts = bucket.value_counts().sort_index().reset_index()
    counts.columns = ["Risk", "Events"]
    fig = px.bar(counts, x="Risk", y="Events", text="Events")
    fig.update_traces(marker_color="#B98CFF", marker_line_color="#020609", marker_line_width=1, textposition="outside", textfont={"color": SOC_TEXT, "size": 9}, hovertemplate="Risk %{x}: %{y} events<extra></extra>")
    return _base_fig(fig, title="RISK DISTRIBUTION")


def event_category_bar(df: pd.DataFrame, limit: int = 8):
    if px is None or df.empty or "event_type" not in df.columns:
        return _empty_message("EVENT CATEGORIES")
    counts = df["event_type"].fillna("Unknown").astype(str).value_counts().head(limit).sort_values().reset_index()
    counts.columns = ["Event Type", "Events"]
    fig = px.bar(counts, x="Events", y="Event Type", orientation="h", text="Events")
    fig.update_traces(marker_color="#4FB8FF", marker_line_color="#020609", marker_line_width=1, textposition="outside", textfont={"color": SOC_TEXT, "size": 9}, hovertemplate="%{y}: %{x}<extra></extra>")
    return _base_fig(fig, title="EVENT CATEGORIES")


def source_distribution(df: pd.DataFrame, limit: int = 6):
    """Build a compact source/provider distribution chart."""
    if px is None or df.empty or "source" not in df.columns:
        return _empty_message("DATA SOURCES")
    counts = df["source"].fillna("Unknown").astype(str).value_counts().head(limit).sort_values().reset_index()
    counts.columns = ["Source", "Events"]
    fig = px.bar(counts, x="Events", y="Source", orientation="h", text="Events")
    fig.update_traces(marker_color="#19F0D0", marker_line_color="#020609", marker_line_width=1, textposition="outside", textfont={"color": SOC_TEXT, "size": 9}, hovertemplate="%{y}: %{x}<extra></extra>")
    return _base_fig(fig, title="DATA SOURCES")

def confidence_breakdown(df: pd.DataFrame):
    if px is None or df.empty or "confidence_level" not in df.columns:
        return _empty_message("CONFIDENCE BREAKDOWN")
    counts = df["confidence_level"].fillna("Not available").astype(str).value_counts().reset_index()
    counts.columns = ["Confidence", "Events"]
    fig = px.bar(counts, x="Confidence", y="Events", text="Events")
    fig.update_traces(marker_color="#27E38B", marker_line_color="#020609", marker_line_width=1, textposition="outside", textfont={"color": SOC_TEXT, "size": 9}, hovertemplate="%{x}: %{y}<extra></extra>")
    return _base_fig(fig, title="CONFIDENCE BREAKDOWN")


def safe_chart(fig, st, *, height: int = 290, key: str | None = None) -> None:
    """Render a Plotly figure safely with stable chrome."""
    if fig is None:
        st.info("Interactive chart support is unavailable. Install project requirements.")
        return
    fig.update_layout(height=height)
    kwargs = {"use_container_width": True, "config": {"displayModeBar": False, "scrollZoom": False}}
    if key:
        kwargs["key"] = key
    st.plotly_chart(fig, **kwargs)


def risk_confidence_scatter(df: pd.DataFrame):
    """Risk-confidence matrix; upper-right indicates analyst attention priority, not confirmation."""
    if px is None or df is None or df.empty or "risk_score" not in df.columns or "confidence_score" not in df.columns:
        return _empty_message("RISK × CONFIDENCE MATRIX")
    tmp = df.copy()
    tmp["risk"] = pd.to_numeric(tmp["risk_score"], errors="coerce")
    tmp["confidence_pct"] = pd.to_numeric(tmp["confidence_score"], errors="coerce") * 100
    tmp["confidence_pct"] = tmp["confidence_pct"].where(tmp["confidence_pct"] <= 100, tmp["confidence_pct"])
    tmp = tmp.dropna(subset=["risk", "confidence_pct"])
    if tmp.empty:
        return _empty_message("RISK × CONFIDENCE MATRIX")
    tmp["label"] = tmp.get("threat", "Event").astype(str).str.slice(0, 34)
    fig = px.scatter(tmp, x="confidence_pct", y="risk", size="risk", color="severity" if "severity" in tmp.columns else None,
                     color_discrete_map=PALETTE, hover_data={"id": True, "label": True, "confidence_pct": ":.0f", "risk": ":.1f"})
    fig.update_xaxes(title="Confidence (%)", range=[0, 100])
    fig.update_yaxes(title="Risk (0–10)", range=[0, 10])
    return _base_fig(fig, title="RISK × CONFIDENCE MATRIX")


def mitre_tactic_bar(df: pd.DataFrame, limit: int = 10):
    """Count observed MITRE tactics only when a mapping is present."""
    if px is None or df is None or df.empty or "mitre_tactic" not in df.columns:
        return _empty_message("MITRE TACTIC COVERAGE")
    values = []
    for raw in df["mitre_tactic"].tolist():
        text = str(raw or "").strip()
        if not text or text.lower().startswith("not mapped"):
            continue
        values.extend(part.strip() for part in text.split(",") if part.strip())
    if not values:
        return _empty_message("MITRE TACTIC COVERAGE")
    counts = pd.Series(values, dtype="string").value_counts().head(limit).sort_values().reset_index()
    counts.columns = ["Tactic", "Events"]
    fig = px.bar(counts, x="Events", y="Tactic", orientation="h", text="Events")
    fig.update_traces(marker_color=SOC_BLUE, textposition="outside")
    return _base_fig(fig, title="MITRE TACTIC COVERAGE")


def mitre_heatmap(df: pd.DataFrame):
    """Show mapped MITRE tactic versus severity counts using observed data only."""
    if px is None or df is None or df.empty or "mitre_tactic" not in df.columns or "severity" not in df.columns:
        return _empty_message("MITRE TACTIC × SEVERITY")
    tmp = df.copy()
    tmp = tmp[~tmp["mitre_tactic"].astype(str).str.lower().str.startswith("not mapped")]
    if tmp.empty:
        return _empty_message("MITRE TACTIC × SEVERITY")
    pivot = pd.crosstab(tmp["mitre_tactic"].astype(str), tmp["severity"].astype(str))
    order = [c for c in ["Critical", "High", "Medium", "Low", "Normal"] if c in pivot.columns]
    pivot = pivot.reindex(columns=order, fill_value=0)
    fig = px.imshow(pivot, text_auto=True, aspect="auto")
    return _base_fig(fig, title="MITRE TACTIC × SEVERITY")
