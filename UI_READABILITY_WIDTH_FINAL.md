# UI Readability + Width Final Pass

- Expanded the main Streamlit canvas to use available horizontal room.
- Kept hero/title/large KPI font sizes unchanged.
- Increased only compact technical text (labels, captions, metadata, matrix copy, navigation, forms, chart ticks/legends).
- Added wrapping/overflow-safe sizing so compact copy does not collide with adjacent elements.
- Added a regression test to protect the width/readability contract.
