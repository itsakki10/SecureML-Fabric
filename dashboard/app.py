import sys
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)

# ---------------- IMPORTS ----------------
import streamlit as st
import pandas as pd
import joblib
import ipaddress
import time
from collections import defaultdict, deque
from datetime import datetime, UTC

from rule_engine.rule_generator import generate_waf_rules
from rule_engine.response_engine import (
    block_ip,
    unblock_ip,
    is_ip_blocked,
    get_block_remaining
)


st.set_page_config(
    page_title="SecureML Fabric Dashboard",
    layout="wide"
)

st.title("🔐 SecureML Fabric – ML-Enabled Network Anomaly Detection")


REFRESH_INTERVAL = 10  
st.sidebar.markdown("### ⏱ Auto Refresh")
st.sidebar.info(f"Page refreshes every {REFRESH_INTERVAL} seconds")


DEMO_MODE = st.sidebar.checkbox(
    "🧪 Demo Mode (Allow LAN IP Blocking)",
    value=False,
    help="Enable only for demo. Production systems never block private IPs."
)


CONFIDENCE_HITS_REQUIRED = 3
MIN_PACKETS_FOR_BLOCK = 200
MIN_RATE_FOR_BLOCK = 50.0  


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def get_confidence(score):
    if score < -0.12:
        return "HIGH"
    elif score < -0.05:
        return "MEDIUM"
    return "LOW"


if "ip_confidence_history" not in st.session_state:
    st.session_state.ip_confidence_history = defaultdict(lambda: deque(maxlen=5))

if "ip_rate_history" not in st.session_state:
    st.session_state.ip_rate_history = defaultdict(lambda: deque(maxlen=30))


MODEL_PATH = os.path.join(BASE_DIR, "ml_engine", "baseline_model.pkl")
DATA_PATH = os.path.join(BASE_DIR, "ml_engine", "live_traffic.csv")

model = joblib.load(MODEL_PATH)

# ---------------- LOAD DATA ----------------
try:
    data = pd.read_csv(DATA_PATH)
except Exception:
    st.info("⏳ Collecting live traffic data…")
    time.sleep(REFRESH_INTERVAL)
    st.rerun()

if data.empty:
    st.info("⏳ Collecting live traffic data…")
    time.sleep(REFRESH_INTERVAL)
    st.rerun()

# ---------------- PROCESS DATA ----------------
feature_cols = ["duration", "packets", "bytes", "rate"]

latest_per_ip = (
    data.sort_index()
        .groupby("ip", as_index=False)
        .tail(1)
)

st.subheader("📊 Per-IP Live Traffic Analysis")

for _, row in latest_per_ip.iterrows():
    ip = row["ip"]
    features = row[feature_cols].values.reshape(1, -1)

    anomaly_score = model.decision_function(features)[0]
    anomaly = model.predict(features)[0]
    confidence = get_confidence(anomaly_score)

    # -------- HISTORY TRACKING --------
    st.session_state.ip_rate_history[ip].append({
        "time": datetime.now(UTC),
        "rate": row["rate"]
    })

    if anomaly == -1 and confidence == "HIGH" and row["packets"] >= MIN_PACKETS_FOR_BLOCK:
        st.session_state.ip_confidence_history[ip].append(1)
    else:
        st.session_state.ip_confidence_history[ip].append(0)

    confidence_hits = sum(st.session_state.ip_confidence_history[ip])

    # -------- HEADER --------
    st.markdown(f"## 🖥️ Source IP: `{ip}`")

    if is_ip_blocked(ip):
        remaining = get_block_remaining(ip)
        st.error(
            f"🚫 **IP BLOCKED AT KERNEL LEVEL** — ⏳ {remaining}s remaining"
            if remaining > 0 else
            "🚫 **IP BLOCKED AT KERNEL LEVEL**"
        )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Packets", int(row["packets"]))
    col2.metric("Bytes", int(row["bytes"]))
    col3.metric("Rate (pkt/sec)", round(row["rate"], 2))
    col4.metric("Anomaly Score", round(anomaly_score, 4))

    if anomaly == -1:
        st.error("⚠️ Anomalous Behaviour Detected")
    else:
        st.success("✅ Normal Behaviour")

    st.write(f"🧠 **Confidence Level:** `{confidence}`")
    st.write(f"📊 **Attack Confidence Window:** {confidence_hits}/5")

    # -------- AUTOMATED RESPONSE --------
    st.subheader("🚫 Automated Response")

    should_block = (
        confidence_hits >= CONFIDENCE_HITS_REQUIRED
        and row["packets"] >= MIN_PACKETS_FOR_BLOCK
        and row["rate"] >= MIN_RATE_FOR_BLOCK
        and (DEMO_MODE or not is_private_ip(ip))
        and not is_ip_blocked(ip)
    )

    if should_block:
        st.error(f"🚨 Blocking IP `{ip}`")
        block_ip(ip)
    else:
        st.success("No mitigation required")

    # -------- MANUAL UNBLOCK --------
    if is_ip_blocked(ip):
        if st.button(f"🔓 Unblock {ip}", key=f"unblock_{ip}"):
            unblock_ip(ip)
            st.session_state.ip_confidence_history[ip].clear()
            st.session_state.ip_rate_history[ip].clear()
            st.success(f"{ip} unblocked")

    # -------- ATTACK TIMELINE --------
    st.subheader("📈 Attack Timeline (Packet Rate)")
    timeline_df = pd.DataFrame(list(st.session_state.ip_rate_history[ip]))
    if not timeline_df.empty:
        st.line_chart(timeline_df.set_index("time"))

    # -------- WAF RULES --------
    st.subheader("🛡️ WAF Rule Recommendations")
    if anomaly == -1:
        rules = generate_waf_rules(anomaly_score, row.to_dict())
        if rules:
            for r in rules:
                st.warning(f"**{r['type']}**: {r['description']}")
                st.code(r["rule"])
        else:
            st.info("No rule action required")

    st.markdown("---")

st.subheader("📄 Live Traffic Data (Latest per IP)")
st.dataframe(latest_per_ip.reset_index(drop=True))

# ---------------- AUTO REFRESH ----------------
time.sleep(REFRESH_INTERVAL)
st.rerun()
