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
import plotly.express as px
import plotly.graph_objects as go

# Assuming these exist in your project structure
from rule_engine.rule_generator import generate_waf_rules
from rule_engine.response_engine import (
    block_ip,
    unblock_ip,
    is_ip_blocked,
    get_block_remaining
)

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="SecureML Fabric | SOC", layout="wide", initial_sidebar_state="expanded")

# ---------------- THEME ENGINE (LIGHT/DARK) ----------------
st.sidebar.markdown("### 🎨 UI Preferences")
theme = st.sidebar.radio("Theme Mode", ["Dark Mode", "Light Mode"], horizontal=True)

# Define dynamic colors based on theme selection
if theme == "Light Mode":
    bg_main = "#f4f7f9"          # Soft light gray background
    bg_card = "#ffffff"          # Pure white cards
    text_main = "#0f172a"        # Dark slate text
    text_muted = "#64748b"       # Muted slate text
    accent = "#0284c7"           # Professional Cobalt Blue
    accent_rgba = "rgba(2, 132, 199, 0.2)"
    border = "#e2e8f0"           # Light border
    plot_template = "plotly_white"
    threat_color = "#ef4444"     # Red
    safe_color = "#10b981"       # Green
else:
    bg_main = "#0b1120"          # Deep navy/slate background
    bg_card = "#1e293b"          # Dark slate cards
    text_main = "#f8fafc"        # Off-white text
    text_muted = "#94a3b8"       # Muted light slate text
    accent = "#38bdf8"           # Bright Sky Blue
    accent_rgba = "rgba(56, 189, 248, 0.2)"
    border = "#334155"           # Dark border
    plot_template = "plotly_dark"
    threat_color = "#f87171"     # Soft Red
    safe_color = "#34d399"       # Soft Green

# Inject Dynamic CSS
st.markdown(f"""
<style>
/* Core Background & Layout */
[data-testid="stAppViewContainer"] {{
    background-color: {bg_main};
}}
header {{visibility: hidden;}}
.block-container {{ padding: 1.5rem 3rem; max-width: 1600px; }}

/* Typography */
.main-title {{ font-size: 2.2rem; font-weight: 800; color: {text_main}; margin-bottom: 0px; }}
.accent-text {{ color: {accent}; }}
.sub-title {{ font-size: 1rem; color: {text_muted}; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 20px; }}
p, div, span, label {{ color: {text_main}; }}

/* Cards */
.stCard {{
    background-color: {bg_card};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
}}

/* Metric Overrides */
[data-testid="stMetricValue"] div {{ color: {accent} !important; font-size: 2rem !important; font-weight: 700 !important; }}
[data-testid="stMetricLabel"] p {{ color: {text_muted} !important; font-size: 1rem !important; font-weight: 600 !important; }}

/* Dataframes */
[data-testid="stDataFrame"] {{
    background-color: {bg_card};
    border-radius: 8px;
}}

/* Alerts */
.stAlert {{ border-radius: 6px; }}

/* Sidebar */
section[data-testid="stSidebar"] {{
    background-color: {bg_card} !important; border-right: 1px solid {border};
}}
</style>
""", unsafe_allow_html=True)

# ---------------- CONFIG & SETUP ----------------
CONFIDENCE_HITS_REQUIRED = 3
MIN_PACKETS_FOR_BLOCK = 200
MIN_RATE_FOR_BLOCK = 50.0
REFRESH_INTERVAL = 10

def hex_to_rgba(hex_color, alpha=0.2):
    """Converts a hex color string to an rgba string for Plotly."""
    hex_color = hex_color.lstrip('#')
    r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    return f"rgba({r}, {g}, {b}, {alpha})"

def is_private_ip(ip):
    try: return ipaddress.ip_address(ip).is_private
    except: return False

def get_confidence(score):
    if score < -0.12: return "HIGH", threat_color
    elif score < -0.05: return "MEDIUM", "#f59e0b" # Amber
    return "LOW", safe_color

# Session State Initialization
if "ip_confidence_history" not in st.session_state:
    st.session_state.ip_confidence_history = defaultdict(lambda: deque(maxlen=5))
if "ip_rate_history" not in st.session_state:
    st.session_state.ip_rate_history = defaultdict(lambda: deque(maxlen=30))

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("---")
    st.markdown("### ⚙️ Engine Controls")
    DEMO_MODE = st.checkbox("🧪 Demo Mode (Allow LAN Block)", value=False)
    st.markdown(f"**Refresh Rate:** `{REFRESH_INTERVAL}s`")
    st.markdown("---")
    st.markdown("**Thresholds:**")
    st.code(f"Hits: {CONFIDENCE_HITS_REQUIRED}\nPkts: >{MIN_PACKETS_FOR_BLOCK}\nRate: >{MIN_RATE_FOR_BLOCK}", language="text")

# ---------------- DATA & MODEL LOADING ----------------
MODEL_PATH = os.path.join(BASE_DIR, "ml_engine", "baseline_model.pkl")
DATA_PATH = os.path.join(BASE_DIR, "ml_engine", "live_traffic.csv")

@st.cache_resource
def load_ml_model():
    return joblib.load(MODEL_PATH)

try:
    model = load_ml_model()
    data = pd.read_csv(DATA_PATH)
except Exception as e:
    st.warning("⏳ Waiting for traffic stream or model initialization...")
    time.sleep(REFRESH_INTERVAL)
    st.rerun()

if data.empty:
    st.info("⏳ Traffic queue is currently empty. Listening...")
    time.sleep(REFRESH_INTERVAL)
    st.rerun()

feature_cols = ["duration", "packets", "bytes", "rate"]

# Process Latest Traffic
latest_per_ip = data.sort_index().groupby("ip", as_index=False).tail(1)
latest_per_ip["anomaly_score"] = model.decision_function(latest_per_ip[feature_cols])
latest_per_ip["prediction"] = model.predict(latest_per_ip[feature_cols])
latest_per_ip["Status"] = latest_per_ip["prediction"].apply(lambda x: "🚨 Threat" if x == -1 else "✅ Normal")

# Global Metrics
total_ips = len(latest_per_ip)
threats = sum(latest_per_ip["prediction"] == -1)
blocked = sum(1 for ip in latest_per_ip["ip"] if is_ip_blocked(ip))
avg_risk = latest_per_ip["anomaly_score"].mean()

# ---------------- HEADER SECTION ----------------
col_h1, col_h2 = st.columns([3, 1])
with col_h1:
    st.markdown(f'<div class="main-title"><span class="accent-text">SecureML</span> Fabric</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Enterprise Network Threat Operations</div>', unsafe_allow_html=True)
with col_h2:
    st.markdown(
        f'<div style="text-align: right; margin-top: 15px; padding: 10px; border-radius: 8px; border: 1px solid {accent}; background-color: {accent_rgba};">'
        f'<span style="font-weight: bold; color: {accent};">● REAL-TIME MONITORING ACTIVE</span>'
        f'</div>', unsafe_allow_html=True
    )

# ---------------- KPI ROW ----------------
st.markdown('<div class="stCard">', unsafe_allow_html=True)
m1, m2, m3, m4 = st.columns(4)
m1.metric("Active Endpoints", total_ips)
m2.metric("Detected Threats", threats, delta=f"{threats} active" if threats > 0 else "Clear", delta_color="inverse")
m3.metric("Blocked Connections", blocked)
m4.metric("Avg Global Risk Score", f"{avg_risk:.3f}")
st.markdown('</div><br>', unsafe_allow_html=True)

# ---------------- VISUALIZATION ROW ----------------
col_v1, col_v2 = st.columns([2, 1])

with col_v1:
    st.markdown('<div class="stCard">', unsafe_allow_html=True)
    st.markdown(f"<h3 style='color: {text_main}; margin-top:0;'>🎯 Threat Matrix (Rate vs. Packets)</h3>", unsafe_allow_html=True)
    
    fig = px.scatter(
        latest_per_ip, x="rate", y="packets", color="Status", hover_name="ip",
        color_discrete_map={"🚨 Threat": threat_color, "✅ Normal": safe_color},
        size="bytes", size_max=20, template=plot_template,
        labels={"rate": "Packet Rate (pkt/s)", "packets": "Total Packets"}
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=0, r=0, t=30, b=0), height=350,
        font=dict(color=text_main)
    )
    st.plotly_chart(fig, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_v2:
    st.markdown('<div class="stCard" style="height: 100%;">', unsafe_allow_html=True)
    st.markdown(f"<h3 style='color: {text_main}; margin-top:0;'>📡 Live Feed</h3>", unsafe_allow_html=True)
    st.dataframe(
        latest_per_ip[["ip", "Status", "rate", "anomaly_score"]].sort_values("anomaly_score"),
        use_container_width=True, hide_index=True, height=350
    )
    st.markdown('</div>', unsafe_allow_html=True)

# ---------------- INVESTIGATION BAY ----------------
st.markdown("---")
st.markdown(f'<div class="main-title" style="font-size: 1.8rem;">🔍 Target Investigation Bay</div><br>', unsafe_allow_html=True)

selected_ip = st.selectbox("Select IP for Deep Packet Inspection:", latest_per_ip["ip"])

if selected_ip:
    row = latest_per_ip[latest_per_ip["ip"] == selected_ip].iloc[0]
    score = row["anomaly_score"]
    is_anomaly = row["prediction"] == -1
    conf_text, conf_color = get_confidence(score)
    
    st.session_state.ip_rate_history[selected_ip].append({"time": datetime.now(UTC), "rate": row["rate"]})
    if is_anomaly and conf_text == "HIGH":
        st.session_state.ip_confidence_history[selected_ip].append(1)
    else:
        st.session_state.ip_confidence_history[selected_ip].append(0)
    
    hits = sum(st.session_state.ip_confidence_history[selected_ip])

    i1, i2, i3 = st.columns([1, 1.5, 1])
    
    with i1:
        st.markdown('<div class="stCard">', unsafe_allow_html=True)
        st.markdown(f"<h4 style='color: {text_main}; margin-top:0;'>📊 Telemetry</h4>", unsafe_allow_html=True)
        st.write(f"**Packets:** `{int(row['packets'])}`")
        st.write(f"**Bytes:** `{int(row['bytes'])}`")
        st.write(f"**Rate:** `{round(row['rate'], 2)} pkt/s`")
        st.write(f"**Duration:** `{round(row['duration'], 2)}s`")
        st.markdown('</div>', unsafe_allow_html=True)

    with i2:
        st.markdown('<div class="stCard">', unsafe_allow_html=True)
        st.markdown(f"<h4 style='color: {text_main}; margin-top:0;'>📈 Network Velocity</h4>", unsafe_allow_html=True)
        timeline_df = pd.DataFrame(list(st.session_state.ip_rate_history[selected_ip]))
        if not timeline_df.empty:
            area_fig = px.area(timeline_df, x="time", y="rate", template=plot_template)
            area_fig.update_traces(line_color=accent, fillcolor=accent_rgba)
            area_fig.update_layout(
                plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=0, r=0, t=0, b=0), height=200, xaxis_title=None, yaxis_title=None,
                font=dict(color=text_main)
            )
            st.plotly_chart(area_fig, use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with i3:
        st.markdown('<div class="stCard">', unsafe_allow_html=True)
        st.markdown(f"<h4 style='color: {text_main}; margin-top:0;'>🛡️ AI Assessment</h4>", unsafe_allow_html=True)
        
        meter_fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = score,
            title = {'text': f"Risk: {conf_text}", 'font': {'size': 14, 'color': text_main}},
            number = {'font': {'color': text_main}},
            gauge = {
                'axis': {'range': [-1, 1], 'tickcolor': text_main},
                'bar': {'color': conf_color},
                'bgcolor': bg_main,
                'steps': [
                    {'range': [-1, -0.1], 'color': hex_to_rgba(threat_color, 0.2)},
                    {'range': [-0.1, 1], 'color': hex_to_rgba(safe_color, 0.2)}
                ],
            }
        ))
        meter_fig.update_layout(height=150, margin=dict(l=10, r=10, t=30, b=10), paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(meter_fig, use_container_width=True)
        
        should_block = (
            hits >= CONFIDENCE_HITS_REQUIRED and row["packets"] >= MIN_PACKETS_FOR_BLOCK
            and row["rate"] >= MIN_RATE_FOR_BLOCK and (DEMO_MODE or not is_private_ip(selected_ip))
            and not is_ip_blocked(selected_ip)
        )

        if should_block:
            st.error("🚨 Triggering Autonomous Block")
            block_ip(selected_ip)

        if is_ip_blocked(selected_ip):
            rem = get_block_remaining(selected_ip)
            st.error(f"🛑 BLOCKED (T-{rem}s)")
            if st.button("🔓 Override & Unblock", use_container_width=True):
                unblock_ip(selected_ip)
                st.session_state.ip_confidence_history[selected_ip].clear()
                st.rerun()
        else:
            if is_anomaly: st.warning(f"⚠️ Tracking Threat ({hits}/5 hits)")
            else: st.success("✅ Clean Traffic")
            
        st.markdown('</div>', unsafe_allow_html=True)

    if is_anomaly:
        st.markdown(f"<h4 style='color: {text_main};'>🤖 Auto-Generated WAF Intelligence</h4>", unsafe_allow_html=True)
        rules = generate_waf_rules(score, row.to_dict())
        if rules:
            for r in rules:
                st.warning(f"**{r['type']}**: {r['description']}")
                st.code(r["rule"], language="json")
        else:
            st.info("No actionable rule payloads extracted yet.")

# ---------------- AUTO REFRESH ----------------
time.sleep(REFRESH_INTERVAL)
st.rerun()
