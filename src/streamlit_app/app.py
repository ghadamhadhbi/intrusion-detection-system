"""
Intelligent Intrusion Detection System (IDS) Dashboard
Main entry point for the Streamlit application
"""

import streamlit as st
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parent))

from utils.data_loader import load_cicids2017_sample, get_data_summary
from components.metrics import calculate_detection_rate, get_real_time_stats
from components.alerts import alert_manager
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for cybersecurity theme
st.markdown("""
<style>
    /* Main theme */
    .stApp {
        background: linear-gradient(135deg, #0a0e27 0%, #1a1d3a 100%);
    }
    
    /* Metric cards */
    [data-testid="stMetricValue"] {
        font-size: 28px;
        font-weight: bold;
    }
    
    /* Headers */
    h1 {
        color: #00FF41;
        text-shadow: 0 0 10px rgba(0, 255, 65, 0.5);
    }
    
    h2, h3 {
        color: #00BFFF;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #1a1d3a 0%, #0a0e27 100%);
    }
    
    /* Alert boxes */
    .stAlert {
        background-color: rgba(255, 0, 0, 0.1);
        border-left: 4px solid #FF0000;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'data_loaded' not in st.session_state:
    st.session_state.data_loaded = False
    st.session_state.df = None

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/security-shield-green.png", width=80)
    st.title("🛡️ IDS Control")
    st.markdown("---")
    
    # System status
    st.subheader("System Status")
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Status", "🟢 Online")
    with col2:
        st.metric("Model", "⚠️ Mock")
    
    st.markdown("---")
    
    # Data loader
    st.subheader("Data Configuration")
    
    data_source = st.selectbox(
        "Data Source",
        ["Mock Data (Testing)", "Upload CSV", "Live Capture"]
    )
    
    if data_source == "Upload CSV":
        uploaded_file = st.file_uploader("Upload CICIDS2017 CSV", type=['csv'])
        if uploaded_file:
            if st.button("Load Dataset"):
                with st.spinner("Loading data..."):
                    st.session_state.df = pd.read_csv(uploaded_file, nrows=10000)
                    st.session_state.data_loaded = True
                    st.success("✅ Data loaded successfully!")
    
    elif data_source == "Mock Data (Testing)":
        sample_size = st.slider("Sample Size", 100, 5000, 1000)
        if st.button("Generate Mock Data"):
            with st.spinner("Generating mock data..."):
                st.session_state.df = load_cicids2017_sample(sample_size=sample_size)
                st.session_state.data_loaded = True
                st.success(f"✅ Generated {sample_size} flows")
    
    st.markdown("---")
    
    # Quick stats
    if st.session_state.data_loaded and st.session_state.df is not None:
        st.subheader("Quick Stats")
        summary = get_data_summary(st.session_state.df)
        st.metric("Total Flows", f"{summary['total_flows']:,}")
        st.metric("Attacks", f"{summary['attack_count']:,}")
        st.metric("Attack Rate", f"{(summary['attack_count']/summary['total_flows']*100):.1f}%")

# Main content
st.title("🛡️ Intelligent Intrusion Detection System")
st.markdown("### Real-time Network Security Monitoring Dashboard")

# Welcome section
if not st.session_state.data_loaded:
    st.info("👈 **Please load data from the sidebar to begin analysis**")
    
    # Show project overview
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        ### 📊 Analytics
        - Traffic analysis
        - Attack distribution
        - Protocol breakdown
        - Temporal patterns
        """)
    
    with col2:
        st.markdown("""
        ### 🎯 Detection
        - Real-time monitoring
        - ML-based classification
        - Alert generation
        - Threat scoring
        """)
    
    with col3:
        st.markdown("""
        ### 🔍 Investigation
        - Alert management
        - Detailed inspection
        - Incident response
        - Report generation
        """)
    
    st.markdown("---")
    
    # Project info
    st.subheader("About This Project")
    st.markdown("""
    This Intelligent Intrusion Detection System leverages **Machine Learning** to detect 
    network intrusions in real-time. The system analyzes the **CICIDS2017** dataset and 
    identifies various attack types including:
    
    - **DoS/DDoS** attacks
    - **Port Scanning**
    - **Brute Force** attempts
    - **Botnet** activity
    - **Web Attacks**
    - And more...
    
    Navigate through the pages using the sidebar to explore different aspects of the system.
    """)

else:
    # Dashboard overview with loaded data
    st.success("✅ Data loaded successfully! Explore the pages from the sidebar.")
    
    # Key metrics
    st.subheader("📊 System Overview")
    
    col1, col2, col3, col4 = st.columns(4)
    
    df = st.session_state.df
    summary = get_data_summary(df)
    
    with col1:
        st.metric(
            "Total Flows",
            f"{summary['total_flows']:,}",
            delta=None
        )
    
    with col2:
        attack_pct = (summary['attack_count']/summary['total_flows']*100)
        st.metric(
            "Attack Rate",
            f"{attack_pct:.2f}%",
            delta=f"{summary['attack_count']:,} attacks"
        )
    
    with col3:
        st.metric(
            "Unique IPs",
            f"{df['Source IP'].nunique():,}",
            delta=None
        )
    
    with col4:
        alerts = alert_manager.get_alerts_by_timeframe(24)
        st.metric(
            "Alerts (24h)",
            len(alerts),
            delta=None
        )
    
    st.markdown("---")
    
    # Attack distribution preview
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Attack Type Distribution")
        attack_dist = df[df['Label'] != 'BENIGN']['Label'].value_counts()
        st.bar_chart(attack_dist)
    
    with col2:
        st.subheader("Recent Alerts")
        recent_alerts = alert_manager.get_recent_alerts(5)
        if recent_alerts:
            for alert in recent_alerts:
                severity_color = {
                    'Critical': '🔴',
                    'High': '🟠',
                    'Medium': '🟡',
                    'Low': '🟢'
                }
                emoji = severity_color.get(alert['severity'], '⚪')
                st.markdown(f"{emoji} **{alert['attack_type']}** from {alert['source_ip']} at {alert['timestamp']}")
        else:
            st.info("No recent alerts")
    
    st.markdown("---")
    
    # Navigation guide
    st.subheader("📍 Navigation Guide")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.markdown("""
        **🔴 Live Detection**
        
        Real-time monitoring and attack detection
        """)
    
    with col2:
        st.markdown("""
        **📊 Analytics**
        
        Traffic analysis and insights
        """)
    
    with col3:
        st.markdown("""
        **🎯 Model Performance**
        
        ML model metrics and evaluation
        """)
    
    with col4:
        st.markdown("""
        **🔍 Investigation**
        
        Alert inspection and incident response
        """)

# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666;'>
    <p>Intelligent IDS Dashboard v1.0 | Powered by Machine Learning | CICIDS2017 Dataset</p>
</div>
""", unsafe_allow_html=True)