"""
Analytics Page - Deep Traffic Analysis
Comprehensive analysis of network traffic patterns and attack trends
"""

import streamlit as st
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from components.charts import (
    plot_attack_distribution_bar, plot_attack_timeline,
    plot_port_distribution, plot_protocol_breakdown
)
from components.metrics import (
    calculate_attack_type_distribution, get_top_attacked_ports,
    get_top_attacker_ips, get_hourly_attack_rate
)
from utils.feature_extractor import (
    get_protocol_distribution, calculate_attack_statistics,
    get_network_summary
)

# Page config
st.set_page_config(page_title="Analytics", page_icon="📊", layout="wide")

# Header
st.title("📊 Network Traffic Analytics")
st.markdown("Comprehensive analysis of network traffic patterns and security insights")

# Check if data is loaded
if 'df' not in st.session_state or st.session_state.df is None:
    st.warning("⚠️ No data loaded. Please load data from the main page.")
    st.stop()

df = st.session_state.df

# Tabs for different analysis sections
tab1, tab2, tab3, tab4 = st.tabs([
    "📈 Overview", 
    "🎯 Attack Analysis", 
    "🌐 Network Analysis",
    "⏰ Temporal Analysis"
])

# TAB 1: OVERVIEW
with tab1:
    st.subheader("📊 Traffic Overview")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    total_flows = len(df)
    benign_count = (df['Label'] == 'BENIGN').sum()
    attack_count = total_flows - benign_count
    attack_rate = (attack_count / total_flows * 100) if total_flows > 0 else 0
    
    with col1:
        st.metric("Total Flows", f"{total_flows:,}")
    
    with col2:
        st.metric("Benign Traffic", f"{benign_count:,}", delta=f"{(benign_count/total_flows*100):.1f}%")
    
    with col3:
        st.metric("Malicious Traffic", f"{attack_count:,}", delta=f"{attack_rate:.1f}%", delta_color="inverse")
    
    with col4:
        unique_protocols = df['Protocol'].nunique() if 'Protocol' in df.columns else 0
        st.metric("Protocols", unique_protocols)
    
    st.markdown("---")
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Attack vs Benign Distribution")
        
        # Create pie chart data
        traffic_dist = pd.Series({
            'BENIGN': benign_count,
            'ATTACKS': attack_count
        })
        
        import plotly.graph_objects as go
        fig = go.Figure(data=[go.Pie(
            labels=traffic_dist.index,
            values=traffic_dist.values,
            hole=0.4,
            marker=dict(colors=['#00FF41', '#FF0000'])
        )])
        fig.update_layout(
            template='plotly_dark',
            height=400
        )
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Protocol Distribution")
        protocol_chart = plot_protocol_breakdown(df)
        st.plotly_chart(protocol_chart, use_container_width=True)
    
    st.markdown("---")
    
    # Network summary
    st.subheader("📋 Network Summary")
    
    network_summary = get_network_summary(df)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**IP Statistics**")
        st.write(f"• Unique Source IPs: {network_summary['unique_source_ips']:,}")
        st.write(f"• Unique Destination IPs: {network_summary['unique_dest_ips']:,}")
    
    with col2:
        st.markdown("**Traffic Volume**")
        st.write(f"• Total Packets: {network_summary['total_packets']:,}")
        st.write(f"• Total Bytes: {network_summary['total_bytes']:,}")
    
    with col3:
        st.markdown("**Flow Statistics**")
        st.write(f"• Avg Flow Duration: {network_summary['avg_flow_duration']:.0f} ms")
        st.write(f"• Total Flows: {network_summary['total_flows']:,}")

# TAB 2: ATTACK ANALYSIS
with tab2:
    st.subheader("🎯 Attack Type Analysis")
    
    # Filter attacks only
    attacks_df = df[df['Label'] != 'BENIGN'].copy()
    
    if len(attacks_df) == 0:
        st.info("No attacks detected in the dataset")
    else:
        # Attack statistics
        attack_stats = calculate_attack_statistics(df)
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.markdown("### Attack Type Distribution")
            attack_bar = plot_attack_distribution_bar(df)
            st.plotly_chart(attack_bar, use_container_width=True)
        
        with col2:
            st.markdown("### Attack Statistics")
            st.metric("Total Attacks", f"{attack_stats['attack_flows']:,}")
            st.metric("Attack Types", len(attack_stats['attack_types']))
            st.metric("Attack Percentage", f"{attack_stats['attack_percentage']:.2f}%")
            
            st.markdown("---")
            
            st.markdown("**Top Attack Types:**")
            for attack_type, count in sorted(attack_stats['attack_types'].items(), 
                                            key=lambda x: x[1], reverse=True)[:5]:
                pct = (count / attack_stats['attack_flows'] * 100)
                st.write(f"• {attack_type}: {count:,} ({pct:.1f}%)")
        
        st.markdown("---")
        
        # Detailed attack breakdown
        st.subheader("📊 Detailed Attack Breakdown")
        
        attack_details = attacks_df.groupby('Label').agg({
            'Flow Duration': 'mean',
            'Total Fwd Packets': 'mean',
            'Flow Bytes/s': 'mean',
            'Destination Port': lambda x: x.mode()[0] if len(x.mode()) > 0 else 0
        }).round(2)
        
        attack_details['Count'] = attacks_df['Label'].value_counts()
        attack_details.columns = ['Avg Duration', 'Avg Packets', 'Avg Bytes/s', 'Common Port', 'Count']
        
        st.dataframe(attack_details, use_container_width=True)

# TAB 3: NETWORK ANALYSIS
with tab3:
    st.subheader("🌐 Network Behavior Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Most Targeted Ports")
        port_chart = plot_port_distribution(df, top_n=10)
        st.plotly_chart(port_chart, use_container_width=True)
        
        # Port details table
        top_ports = get_top_attacked_ports(df, n=10)
        if len(top_ports) > 0:
            port_df = pd.DataFrame(top_ports, columns=['Port', 'Count'])
            
            # Add service names
            port_services = {
                80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
                25: 'SMTP', 53: 'DNS', 3389: 'RDP', 8080: 'HTTP-ALT'
            }
            port_df['Service'] = port_df['Port'].map(port_services).fillna('Unknown')
            
            st.dataframe(port_df, use_container_width=True)
    
    with col2:
        st.markdown("### Top Attacker IPs")
        
        top_attackers = get_top_attacker_ips(df[df['Label'] != 'BENIGN'], n=10)
        
        if len(top_attackers) > 0:
            attacker_df = pd.DataFrame(top_attackers, columns=['IP Address', 'Attack Count'])
            
            import plotly.express as px
            fig = px.bar(
                attacker_df,
                x='Attack Count',
                y='IP Address',
                orientation='h',
                color='Attack Count',
                color_continuous_scale='Reds'
            )
            fig.update_layout(
                template='plotly_dark',
                showlegend=False,
                height=400
            )
            st.plotly_chart(fig, use_container_width=True)
            
            st.dataframe(attacker_df, use_container_width=True)
        else:
            st.info("No attacker IPs found")
    
    st.markdown("---")
    
    # IP Analysis
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Top Source IPs (All Traffic)")
        top_sources = df['Source IP'].value_counts().head(10)
        st.bar_chart(top_sources)
    
    with col2:
        st.markdown("### Top Destination IPs")
        top_destinations = df['Destination IP'].value_counts().head(10)
        st.bar_chart(top_destinations)

# TAB 4: TEMPORAL ANALYSIS
with tab4:
    st.subheader("⏰ Time-based Analysis")
    
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        
        # Attack timeline
        st.markdown("### Attack Timeline")
        timeline_chart = plot_attack_timeline(df, time_window='1H')
        st.plotly_chart(timeline_chart, use_container_width=True)
        
        st.markdown("---")
        
        # Hourly analysis
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Hourly Attack Distribution")
            
            hourly_attacks = get_hourly_attack_rate(df)
            
            if not hourly_attacks.empty:
                import plotly.express as px
                fig = px.bar(
                    hourly_attacks,
                    x='Hour',
                    y='Attacks',
                    color='Attack_Rate',
                    color_continuous_scale='Reds',
                    labels={'Attacks': 'Number of Attacks', 'Hour': 'Hour of Day'}
                )
                fig.update_layout(template='plotly_dark', height=400)
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.markdown("### Peak Activity Hours")
            
            if not hourly_attacks.empty:
                peak_hours = hourly_attacks.nlargest(5, 'Attacks')[['Hour', 'Attacks', 'Attack_Rate']]
                st.dataframe(peak_hours, use_container_width=True)
                
                st.markdown("---")
                
                st.markdown("**Activity Summary:**")
                st.write(f"• Busiest Hour: {hourly_attacks.loc[hourly_attacks['Attacks'].idxmax(), 'Hour']}:00")
                st.write(f"• Peak Attacks: {hourly_attacks['Attacks'].max()}")
                st.write(f"• Quietest Hour: {hourly_attacks.loc[hourly_attacks['Attacks'].idxmin(), 'Hour']}:00")
        
        st.markdown("---")
        
        # Date range analysis
        st.markdown("### Traffic Over Time")
        
        df_by_date = df.set_index('Timestamp').resample('1H').size().reset_index(name='Count')
        
        import plotly.express as px
        fig = px.area(
            df_by_date,
            x='Timestamp',
            y='Count',
            labels={'Count': 'Number of Flows', 'Timestamp': 'Time'}
        )
        fig.update_layout(template='plotly_dark', height=400)
        st.plotly_chart(fig, use_container_width=True)
        
    else:
        st.warning("Timestamp column not available for temporal analysis")

# Footer
st.markdown("---")

col1, col2, col3 = st.columns(3)

with col1:
    if st.button("📥 Export Analysis Report"):
        # Create summary report
        report = {
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_flows': total_flows,
            'attack_count': attack_count,
            'attack_rate': attack_rate,
            'protocols': list(df['Protocol'].unique()) if 'Protocol' in df.columns else []
        }
        
        import json
        report_json = json.dumps(report, indent=2)
        
        st.download_button(
            label="Download JSON Report",
            data=report_json,
            file_name=f"analytics_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

with col2:
    st.info("💡 Use filters in the sidebar to refine analysis")

with col3:
    st.success(f"✅ Analyzed {total_flows:,} network flows")