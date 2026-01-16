"""
Live Detection Page - Real-time Network Monitoring
Shows live traffic analysis and detects intrusions in real-time
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from components.charts import (
    plot_traffic_timeline, plot_attack_distribution_pie,
    plot_protocol_breakdown, plot_live_metrics_line
)
from components.metrics import calculate_detection_rate, get_real_time_stats
from components.alerts import alert_manager, format_alert_message, get_severity_color
from utils.data_loader import load_live_traffic, generate_mock_traffic_data
from utils.model_predictor import predictor

# Page config
st.set_page_config(page_title="Live Detection", page_icon="🔴", layout="wide")

# Custom CSS
st.markdown("""
<style>
    .alert-box {
        padding: 15px;
        border-radius: 5px;
        margin: 10px 0;
        border-left: 5px solid;
    }
    .critical { border-color: #DC143C; background: rgba(220, 20, 60, 0.1); }
    .high { border-color: #FF4500; background: rgba(255, 69, 0, 0.1); }
    .medium { border-color: #FFD700; background: rgba(255, 215, 0, 0.1); }
    .low { border-color: #90EE90; background: rgba(144, 238, 144, 0.1); }
</style>
""", unsafe_allow_html=True)

# Header
st.title("🔴 Live Detection & Monitoring")
st.markdown("Real-time network traffic analysis and intrusion detection")

# Check if data is loaded
if 'df' not in st.session_state or st.session_state.df is None:
    st.warning("⚠️ No data loaded. Please load data from the main page.")
    st.stop()

# Initialize live monitoring state
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False
    st.session_state.live_data = []
    st.session_state.live_alerts = []

# Control panel
col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    st.subheader("⚙️ Monitoring Controls")

with col2:
    if st.button("▶️ Start Monitoring" if not st.session_state.monitoring else "⏸️ Pause Monitoring"):
        st.session_state.monitoring = not st.session_state.monitoring

with col3:
    if st.button("🔄 Reset Data"):
        st.session_state.live_data = []
        st.session_state.live_alerts = []
        st.rerun()

st.markdown("---")

# Main monitoring area
if st.session_state.monitoring:
    st.info("🟢 **System is actively monitoring network traffic...**")
else:
    st.warning("⏸️ **Monitoring paused**")

# Real-time metrics
st.subheader("📊 Real-time Metrics")

metrics_col1, metrics_col2, metrics_col3, metrics_col4, metrics_col5 = st.columns(5)

# Get recent data sample
recent_df = st.session_state.df.tail(100)

with metrics_col1:
    st.metric("Active Flows", len(recent_df))

with metrics_col2:
    attack_count = (recent_df['Label'] != 'BENIGN').sum()
    st.metric("Threats Detected", attack_count, delta=f"{attack_count}")

with metrics_col3:
    detection_rate = calculate_detection_rate(recent_df)
    st.metric("Detection Rate", f"{detection_rate}%")

with metrics_col4:
    unique_ips = recent_df['Source IP'].nunique()
    st.metric("Unique Sources", unique_ips)

with metrics_col5:
    if 'Flow Packets/s' in recent_df.columns:
        avg_pps = recent_df['Flow Packets/s'].mean()
        st.metric("Avg Packets/s", f"{avg_pps:.0f}")
    else:
        st.metric("Avg Packets/s", "N/A")

st.markdown("---")

# Two-column layout
col_left, col_right = st.columns([2, 1])

with col_left:
    # Traffic timeline
    st.subheader("📈 Traffic Timeline")
    
    if 'Timestamp' in recent_df.columns:
        timeline_chart = plot_traffic_timeline(
            recent_df, 
            time_column='Timestamp',
            value_column='Flow Packets/s' if 'Flow Packets/s' in recent_df.columns else 'Total Fwd Packets'
        )
        st.plotly_chart(timeline_chart, use_container_width=True)
    else:
        st.info("Timeline data not available")
    
    # Protocol distribution
    st.subheader("🔀 Protocol Distribution")
    protocol_chart = plot_protocol_breakdown(recent_df)
    st.plotly_chart(protocol_chart, use_container_width=True)
    
    # Attack distribution
    st.subheader("🎯 Attack Type Distribution")
    attack_chart = plot_attack_distribution_pie(recent_df)
    st.plotly_chart(attack_chart, use_container_width=True)

with col_right:
    # Live alerts feed
    st.subheader("🚨 Live Alerts Feed")
    
    alerts_container = st.container()
    
    with alerts_container:
        recent_alerts = alert_manager.get_recent_alerts(10)
        
        if recent_alerts:
            for alert in recent_alerts:
                severity = alert.get('severity', 'Medium')
                severity_class = severity.lower()
                
                st.markdown(f"""
                <div class='alert-box {severity_class}'>
                    <strong>{alert['attack_type']}</strong> - {severity}<br>
                    <small>🕐 {alert['timestamp']}</small><br>
                    <small>📍 {alert['source_ip']} → {alert['destination_ip']}:{alert['destination_port']}</small><br>
                    <small>🎯 Confidence: {alert['confidence']:.2f}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No alerts detected yet")
    
    # Quick statistics
    st.subheader("📊 Alert Statistics")
    
    alert_stats = alert_manager.get_alert_statistics()
    
    st.metric("Total Alerts", alert_stats['total'])
    st.metric("Blocked", alert_stats['blocked'])
    st.metric("Investigated", alert_stats['investigated'])
    
    # Severity breakdown
    if alert_stats['by_severity']:
        st.markdown("**By Severity:**")
        for severity, count in alert_stats['by_severity'].items():
            color = get_severity_color(severity)
            st.markdown(f"<span style='color:{color}'>●</span> {severity}: {count}", 
                       unsafe_allow_html=True)

st.markdown("---")

# Detailed traffic table
st.subheader("🔍 Recent Traffic Details")

# Filter options
col1, col2, col3 = st.columns(3)

with col1:
    show_only_attacks = st.checkbox("Show only attacks", value=False)

with col2:
    if 'Protocol' in recent_df.columns:
        protocol_filter = st.multiselect(
            "Filter by Protocol",
            options=recent_df['Protocol'].unique(),
            default=None
        )
    else:
        protocol_filter = None

with col3:
    max_rows = st.slider("Rows to display", 10, 100, 20)

# Apply filters
filtered_df = recent_df.copy()

if show_only_attacks:
    filtered_df = filtered_df[filtered_df['Label'] != 'BENIGN']

if protocol_filter:
    filtered_df = filtered_df[filtered_df['Protocol'].isin(protocol_filter)]

# Select columns to display
display_columns = [
    'Timestamp', 'Source IP', 'Destination IP', 'Destination Port', 
    'Protocol', 'Label', 'Flow Packets/s', 'Flow Bytes/s'
]
display_columns = [col for col in display_columns if col in filtered_df.columns]

# Display table
st.dataframe(
    filtered_df[display_columns].tail(max_rows),
    use_container_width=True,
    height=400
)

# Auto-refresh for live monitoring
if st.session_state.monitoring:
    time.sleep(2)
    st.rerun()

# Export options
st.markdown("---")
st.subheader("💾 Export Options")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("📥 Export Current Traffic"):
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label="Download CSV",
            data=csv,
            file_name=f"traffic_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

with col2:
    if st.button("📥 Export Alerts"):
        if recent_alerts:
            alerts_df = pd.DataFrame(recent_alerts)
            csv = alerts_df.to_csv(index=False)
            st.download_button(
                label="Download Alerts CSV",
                data=csv,
                file_name=f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )
        else:
            st.warning("No alerts to export")

with col3:
    st.info("💡 Tip: Use filters to narrow down specific traffic patterns")