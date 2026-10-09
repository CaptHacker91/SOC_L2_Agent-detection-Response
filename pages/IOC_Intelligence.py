"""IOC intelligence center using indicators extracted from the current telemetry only."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from core.pipeline import load_pipeline
from core.telemetry_quality import is_present
from core.ui import apply_theme, footer, metric_card, nav_brand, navigation_links, page_header, section_title

IOC_FIELDS = [("IP", "source_ip"), ("Destination IP", "destination_ip"), ("Domain", "domain"), ("URL", "url"), ("Hash", "file_hash"), ("File", "filename"), ("Username", "username")]


def _ioc_table(df: pd.DataFrame, column: str) -> pd.DataFrame:
    if column not in df.columns or df.empty:
        return pd.DataFrame()
    rows = []
    ts = pd.to_datetime(df.get("timestamp", pd.Series(index=df.index)), errors="coerce", utc=True)
    for value, idxs in df[df[column].apply(is_present)].groupby(column, sort=False).groups.items():
        idx = list(idxs)
        event_ts = ts.loc[idx].dropna() if not ts.empty else pd.Series(dtype="datetime64[ns, UTC]")
        rows.append({
            "IOC": str(value), "Type": column, "First Seen": event_ts.min().isoformat() if not event_ts.empty else "Not available",
            "Last Seen": event_ts.max().isoformat() if not event_ts.empty else "Not available", "Related Records": len(idx),
            "Related Incidents": df.loc[idx, "id"].nunique() if "id" in df.columns else len(idx),
        })
    return pd.DataFrame(rows).sort_values("Related Records", ascending=False)


def main() -> None:
    st.set_page_config(page_title="IOC Intelligence // SOC L2", page_icon="🧬", layout="wide")
    apply_theme(st)
    with st.sidebar:
        nav_brand(st, "indicator extraction + relationship view", "IOC CENTER", "info")
        navigation_links(st)
    df = load_pipeline()
    page_header(st, "IOC Intelligence Center", "search indicators extracted from observed telemetry without claiming external reputation or threat intelligence")
    if df.empty:
        st.warning("No telemetry loaded.")
        footer(st)
        return
    counts = {name: int(df[col].apply(is_present).sum()) if col in df.columns else 0 for name, col in IOC_FIELDS}
    cols = st.columns(4)
    for col, name in zip(cols, list(counts)[:4]):
        with col: metric_card(st, name.upper(), f"{counts[name]:,}", "info", "observed values")
    cols = st.columns(3)
    for col, name in zip(cols, list(counts)[4:]):
        with col: metric_card(st, name.upper(), f"{counts[name]:,}", "info", "observed values")
    selector = st.selectbox("IOC type", [name for name, _ in IOC_FIELDS], key="ioc_type_selector")
    column = dict(IOC_FIELDS)[selector]
    table = _ioc_table(df, column)
    with st.container(border=True):
        section_title(st, f"Observed {selector}s", "First/last seen are calculated from the loaded event timestamps.")
        if table.empty:
            st.info("No values of this type are present in supplied telemetry.")
        else:
            query = st.text_input("Filter IOC", placeholder="literal search...", key="ioc_literal_search")
            shown = table
            if query.strip():
                shown = table[table["IOC"].astype(str).str.lower().str.contains(query.strip().lower(), regex=False, na=False)]
            st.dataframe(shown, use_container_width=True, hide_index=True, height=480)
            st.download_button("Export IOC CSV", data=shown.to_csv(index=False).encode("utf-8"), file_name=f"IOC_{column}.csv", mime="text/csv", use_container_width=True, key="ioc_export_csv")
    with st.expander("Threat-intelligence boundary"):
        st.caption("This console does not invent reputation, maliciousness or external threat intelligence. External enrichment can be added later through a controlled provider adapter.")
    footer(st, "SOC_L2 // IOC INTELLIGENCE // TELEMETRY-DERIVED ONLY")

if __name__ == "__main__":
    main()
