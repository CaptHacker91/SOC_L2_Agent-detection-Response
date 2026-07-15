import streamlit as st

st.set_page_config(
    page_title="AI-Assisted SOC Level 2 Investigation Platform",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Assisted SOC Level 2 Investigation Platform")
st.subheader("Version 1 Prototype")

st.markdown("---")

st.write("### Upload Blue Team Defense Dataset")

uploaded_file = st.file_uploader(
    "Upload a JSONL file",
    type=["jsonl"]
)

if uploaded_file is not None:
    st.success("✅ File uploaded successfully!")

    st.write("**File Name:**", uploaded_file.name)
    st.write("**File Size:**", f"{uploaded_file.size} bytes")

    st.info("Next Step ➜ File Loader Module")
else:
    st.warning("Please upload the Blue Team Defense Dataset (.jsonl)")
