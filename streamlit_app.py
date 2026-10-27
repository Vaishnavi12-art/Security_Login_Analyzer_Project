import streamlit as st
from pathlib import Path
from collections import Counter
import re

st.set_page_config(
    page_title="Security Login Analyzer",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Security Login Analyzer")
st.write("Analyze login logs and identify suspicious activity.")

uploaded_file = st.file_uploader(
    "Upload a security log text file",
    type=["txt", "log"]
)

if uploaded_file is not None:
    content = uploaded_file.getvalue().decode(
        "utf-8", errors="replace"
    )
elif Path("security_log.txt").exists():
    content = Path("security_log.txt").read_text(
        encoding="utf-8", errors="replace"
    )
else:
    content = ""

if not content.strip():
    st.info("Upload a .txt or .log file to begin analysis.")
    st.stop()

lines = [line for line in content.splitlines() if line.strip()]

failed = [
    line for line in lines
    if re.search(r"failed|failure|4625", line, re.I)
]

successful = [
    line for line in lines
    if re.search(r"success|successful|4624", line, re.I)
]

st.subheader("📊 Login Summary")

col1, col2, col3 = st.columns(3)
col1.metric("Total Events", len(lines))
col2.metric("Failed Logins", len(failed))
col3.metric("Successful Logins", len(successful))

st.subheader("🚨 Failed Login Events")

if failed:
    st.dataframe(
        {"Failed Login Event": failed},
        use_container_width=True
    )
else:
    st.success("No failed login patterns found.")

st.subheader("📄 Recent Security Events")
st.text("\n".join(lines[-10:]))
