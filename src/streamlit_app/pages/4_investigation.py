"""
Investigation Page - Alert Analysis and Incident Response
Detailed alert inspection, investigation tools, and reporting
"""

import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from components.alerts import (
    alert_manager, format_alert_message, get_severity_color,
    create_alert_dataframe
)
from components.charts import plot_severity_gauge
from components.metrics import get_severity_distribution

# Page config
st.set_page_config(page_title="Investigation", page_icon="🔍", layout="wide")

# Custom CSS
st.markdown("""
<style>
    .alert-detail {
        background: rgba(0, 191, 255, 0.1);
        border: 2px solid #00BFFF;
        border-radius: 10px;
        padding: 20px;
        margin: 10px 0;
    }
    .severity-critical { color: #DC143C; font-weight: bold; }
    .severity-high { color: #FF4500; font-weight: bold; }
    .severity-medium { color: #FFD700; font-weight: bold; }
    .severity-low { color: #90EE90; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Header
st.title("🔍 Alert Investigation & Incident Response")
st.markdown("Detailed analysis and management of security alerts")

# Get all alerts
all_alerts = alert_manager.alerts
alert_stats = alert_manager.get_alert_statistics()

# Summary metrics
st.subheader("📊 Alert Overview")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("Total Alerts", alert_stats['total'])

with col2:
    st.metric("Blocked", alert_stats['blocked'], delta="Auto-blocked")

with col3:
    st.metric("Investigated", alert_stats['investigated'])

with col4:
    false_positives = alert_stats['false_positives']
    fp_rate = (false_positives / alert_stats['total'] * 100) if alert_stats['total'] > 0 else 0
    st.metric("False Positives", false_positives, delta=f"{fp_rate:.1f}%")

with col5:
    pending = alert_stats['total'] - alert_stats['investigated']
    st.metric("Pending Review", pending, delta=f"{pending} alerts")

st.markdown("---")

# Tabs for different investigation sections
tab1, tab2, tab3, tab4 = st.tabs([
    "🚨 Alert Dashboard",
    "🔎 Detailed Investigation",
    "📋 Alert Management",
    "📊 Reports & Export"
])

# TAB 1: ALERT DASHBOARD
with tab1:
    st.subheader("🚨 Alert Dashboard")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Severity distribution
        st.markdown("### Severity Distribution")
        
        severity_dist = get_severity_distribution(all_alerts)
        
        severity_gauge = plot_severity_gauge(
            severity_dist['Critical'],
            severity_dist['High'],
            severity_dist['Medium'],
            severity_dist['Low']
        )
        st.plotly_chart(severity_gauge, use_container_width=True)
    
    with col2:
        st.markdown("### Severity Breakdown")
        
        for severity, count in severity_dist.items():
            color = get_severity_color(severity)
            pct = (count / alert_stats['total'] * 100) if alert_stats['total'] > 0 else 0
            st.markdown(f"""
            <div style='padding: 10px; margin: 5px 0; background: rgba(0,0,0,0.2); border-left: 4px solid {color};'>
                <strong>{severity}</strong>: {count} alerts ({pct:.1f}%)
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # Attack type distribution
    st.subheader("Attack Type Analysis")
    
    if alert_stats['by_type']:
        import plotly.graph_objects as go
        
        attack_types = list(alert_stats['by_type'].keys())
        attack_counts = list(alert_stats['by_type'].values())
        
        fig = go.Figure(data=[go.Bar(
            x=attack_types,
            y=attack_counts,
            marker=dict(
                color=attack_counts,
                colorscale='Reds',
                showscale=True
            ),
            text=attack_counts,
            textposition='auto'
        )])
        
        fig.update_layout(
            title='Alerts by Attack Type',
            xaxis_title='Attack Type',
            yaxis_title='Number of Alerts',
            template='plotly_dark',
            height=400
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # Timeline
    st.subheader("Alert Timeline (Last 24 Hours)")
    
    alerts_24h = alert_manager.get_alerts_by_timeframe(24)
    
    if alerts_24h:
        # Convert to dataframe for timeline
        timeline_df = pd.DataFrame(alerts_24h)
        timeline_df['timestamp'] = pd.to_datetime(timeline_df['timestamp'])
        timeline_df['hour'] = timeline_df['timestamp'].dt.hour
        
        hourly_counts = timeline_df.groupby('hour').size().reindex(range(24), fill_value=0)
        
        import plotly.express as px
        fig = px.line(
            x=hourly_counts.index,
            y=hourly_counts.values,
            labels={'x': 'Hour of Day', 'y': 'Number of Alerts'},
            markers=True
        )
        fig.update_traces(line_color='#FF0000', line_width=3)
        fig.update_layout(template='plotly_dark', height=300)
        
        st.plotly_chart(fig, use_container_width=True)

# TAB 2: DETAILED INVESTIGATION
with tab2:
    st.subheader("🔎 Detailed Alert Investigation")
    
    # Filters
    st.markdown("### 🔍 Search & Filter")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        severity_filter = st.multiselect(
            "Severity",
            options=['Critical', 'High', 'Medium', 'Low'],
            default=None
        )
    
    with col2:
        if alert_stats['by_type']:
            attack_type_filter = st.multiselect(
                "Attack Type",
                options=list(alert_stats['by_type'].keys()),
                default=None
            )
        else:
            attack_type_filter = None
    
    with col3:
        timeframe = st.selectbox(
            "Time Range",
            options=['Last 1 Hour', 'Last 6 Hours', 'Last 24 Hours', 'Last 7 Days', 'All Time']
        )
    
    with col4:
        status_filter = st.selectbox(
            "Status",
            options=['All', 'Pending', 'Investigated', 'False Positives']
        )
    
    # Apply filters
    filtered_alerts = all_alerts.copy()
    
    if severity_filter:
        filtered_alerts = [a for a in filtered_alerts if a.get('severity') in severity_filter]
    
    if attack_type_filter:
        filtered_alerts = [a for a in filtered_alerts if a.get('attack_type') in attack_type_filter]
    
    # Timeframe filter
    timeframe_map = {
        'Last 1 Hour': 1,
        'Last 6 Hours': 6,
        'Last 24 Hours': 24,
        'Last 7 Days': 168,
        'All Time': None
    }
    
    if timeframe_map[timeframe]:
        filtered_alerts = alert_manager.get_alerts_by_timeframe(timeframe_map[timeframe])
    
    # Status filter
    if status_filter == 'Pending':
        filtered_alerts = [a for a in filtered_alerts if not a.get('investigated', False)]
    elif status_filter == 'Investigated':
        filtered_alerts = [a for a in filtered_alerts if a.get('investigated', False)]
    elif status_filter == 'False Positives':
        filtered_alerts = [a for a in filtered_alerts if a.get('false_positive', False)]
    
    st.markdown(f"**Found {len(filtered_alerts)} alerts**")
    
    st.markdown("---")
    
    # Display filtered alerts
    if filtered_alerts:
        # Select alert to investigate
        alert_ids = [a['id'] for a in filtered_alerts]
        selected_alert_id = st.selectbox("Select Alert to Investigate", alert_ids)
        
        # Find selected alert
        selected_alert = next((a for a in filtered_alerts if a['id'] == selected_alert_id), None)
        
        if selected_alert:
            col1, col2 = st.columns([2, 1])
            
            with col1:
                st.markdown("### Alert Details")
                
                # Format and display alert
                message = format_alert_message(selected_alert)
                st.markdown(f"""
                <div class='alert-detail'>
                {message.replace('**', '<strong>').replace('**', '</strong>')}
                </div>
                """, unsafe_allow_html=True)
                
                # Additional details
                st.markdown("### Technical Details")
                
                detail_col1, detail_col2 = st.columns(2)
                
                with detail_col1:
                    st.write(f"**Alert ID:** {selected_alert['id']}")
                    st.write(f"**Timestamp:** {selected_alert['timestamp']}")
                    st.write(f"**Attack Type:** {selected_alert['attack_type']}")
                    st.write(f"**Severity:** {selected_alert['severity']}")
                
                with detail_col2:
                    st.write(f"**Source:** {selected_alert['source_ip']}")
                    st.write(f"**Destination:** {selected_alert['destination_ip']}:{selected_alert['destination_port']}")
                    st.write(f"**Protocol:** {selected_alert.get('protocol', 'Unknown')}")
                    st.write(f"**Confidence:** {selected_alert['confidence']:.2f}")
                
                st.markdown("### Traffic Statistics")
                st.write(f"• **Packets:** {selected_alert['packets']:,}")
                st.write(f"• **Bytes:** {selected_alert['bytes']:,}")
                st.write(f"• **Flow Duration:** {selected_alert.get('flow_duration', 0):,} ms")
                
                # Notes section
                st.markdown("### Investigation Notes")
                notes = st.text_area(
                    "Add notes about this alert",
                    value=selected_alert.get('notes', ''),
                    height=100,
                    key=f"notes_{selected_alert_id}"
                )
            
            with col2:
                st.markdown("### Actions")
                
                # Action buttons
                if not selected_alert.get('investigated', False):
                    if st.button("✅ Mark as Investigated", key="mark_investigated"):
                        alert_manager.mark_as_investigated(selected_alert_id)
                        st.success("Alert marked as investigated")
                        st.rerun()
                else:
                    st.success("✅ Already Investigated")
                
                if not selected_alert.get('false_positive', False):
                    if st.button("❌ Mark as False Positive", key="mark_fp"):
                        alert_manager.mark_as_false_positive(selected_alert_id, notes)
                        st.success("Alert marked as false positive")
                        st.rerun()
                else:
                    st.info("ℹ️ Marked as False Positive")
                
                st.markdown("---")
                
                st.markdown("### Recommended Actions")
                
                severity = selected_alert['severity']
                
                if severity == 'Critical':
                    st.error("**Immediate action required!**")
                    st.write("1. Isolate affected systems")
                    st.write("2. Block source IP")
                    st.write("3. Notify security team")
                    st.write("4. Collect forensic data")
                elif severity == 'High':
                    st.warning("**Priority investigation**")
                    st.write("1. Verify attack legitimacy")
                    st.write("2. Check for lateral movement")
                    st.write("3. Review logs")
                    st.write("4. Consider blocking")
                elif severity == 'Medium':
                    st.info("**Standard investigation**")
                    st.write("1. Review traffic patterns")
                    st.write("2. Check similar alerts")
                    st.write("3. Monitor source IP")
                else:
                    st.success("**Low priority**")
                    st.write("1. Log for analysis")
                    st.write("2. Monitor trends")
                
                st.markdown("---")
                
                st.markdown("### Quick Stats")
                st.write(f"**Status:** {'🟢 Blocked' if selected_alert.get('blocked') else '🔴 Detected'}")
                st.write(f"**Investigated:** {'Yes' if selected_alert.get('investigated') else 'No'}")
                st.write(f"**False Positive:** {'Yes' if selected_alert.get('false_positive') else 'No'}")
    
    else:
        st.info("No alerts match the selected filters")

# TAB 3: ALERT MANAGEMENT
with tab3:
    st.subheader("📋 Alert Management")
    
    # Bulk operations
    st.markdown("### Bulk Operations")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("📧 Export All Alerts"):
            alert_manager.export_alerts_to_csv('all_alerts_export.csv')
            st.success("✅ Alerts exported to CSV")
    
    with col2:
        days_to_keep = st.number_input("Keep alerts for (days)", min_value=1, max_value=365, value=30)
        if st.button("🗑️ Clear Old Alerts"):
            alert_manager.clear_old_alerts(days=days_to_keep)
            st.success(f"✅ Cleared alerts older than {days_to_keep} days")
            st.rerun()
    
    with col3:
        st.info(f"💾 {alert_stats['total']} alerts in database")
    
    st.markdown("---")
    
    # Alert table with all details
    st.markdown("### All Alerts")
    
    if all_alerts:
        alerts_df = create_alert_dataframe(all_alerts)
        
        # Add color coding
        def color_severity(val):
            if val == 'Critical':
                return 'background-color: rgba(220, 20, 60, 0.3)'
            elif val == 'High':
                return 'background-color: rgba(255, 69, 0, 0.3)'
            elif val == 'Medium':
                return 'background-color: rgba(255, 215, 0, 0.3)'
            elif val == 'Low':
                return 'background-color: rgba(144, 238, 144, 0.3)'
            return ''
        
        if 'severity' in alerts_df.columns:
            styled_df = alerts_df.style.applymap(color_severity, subset=['severity'])
            st.dataframe(styled_df, use_container_width=True, height=500)
        else:
            st.dataframe(alerts_df, use_container_width=True, height=500)
    else:
        st.info("No alerts available")

# TAB 4: REPORTS & EXPORT
with tab4:
    st.subheader("📊 Reports & Export")
    
    # Summary report
    st.markdown("### Investigation Summary Report")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### Alert Statistics")
        st.write(f"• Total Alerts: {alert_stats['total']}")
        st.write(f"• Critical Alerts: {alert_stats['by_severity'].get('Critical', 0)}")
        st.write(f"• High Severity: {alert_stats['by_severity'].get('High', 0)}")
        st.write(f"• Medium Severity: {alert_stats['by_severity'].get('Medium', 0)}")
        st.write(f"• Low Severity: {alert_stats['by_severity'].get('Low', 0)}")
        st.write(f"• Blocked: {alert_stats['blocked']}")
        st.write(f"• False Positives: {alert_stats['false_positives']}")
        
        fp_rate = (alert_stats['false_positives'] / alert_stats['total'] * 100) if alert_stats['total'] > 0 else 0
        st.write(f"• False Positive Rate: {fp_rate:.2f}%")
    
    with col2:
        st.markdown("#### Top Attack Types")
        
        if alert_stats['by_type']:
            for attack_type, count in sorted(alert_stats['by_type'].items(), 
                                            key=lambda x: x[1], reverse=True)[:5]:
                pct = (count / alert_stats['total'] * 100) if alert_stats['total'] > 0 else 0
                st.write(f"• {attack_type}: {count} ({pct:.1f}%)")
    
    st.markdown("---")
    
    # Export options
    st.markdown("### Export Options")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**📥 CSV Export**")
        if st.button("Download Alerts as CSV"):
            if all_alerts:
                alerts_df = pd.DataFrame(all_alerts)
                csv = alerts_df.to_csv(index=False)
                st.download_button(
                    label="💾 Download CSV",
                    data=csv,
                    file_name=f"alerts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv"
                )
            else:
                st.warning("No alerts to export")
    
    with col2:
        st.markdown("**📊 JSON Export**")
        if st.button("Download Alerts as JSON"):
            import json
            if all_alerts:
                json_data = json.dumps(all_alerts, indent=2, default=str)
                st.download_button(
                    label="💾 Download JSON",
                    data=json_data,
                    file_name=f"alerts_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
            else:
                st.warning("No alerts to export")
    
    with col3:
        st.markdown("**📄 Summary Report**")
        if st.button("Generate Summary"):
            report = f"""
INTRUSION DETECTION SYSTEM - INVESTIGATION REPORT
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY STATISTICS
------------------
Total Alerts: {alert_stats['total']}
Critical: {alert_stats['by_severity'].get('Critical', 0)}
High: {alert_stats['by_severity'].get('High', 0)}
Medium: {alert_stats['by_severity'].get('Medium', 0)}
Low: {alert_stats['by_severity'].get('Low', 0)}

RESPONSE ACTIONS
----------------
Blocked: {alert_stats['blocked']}
Investigated: {alert_stats['investigated']}
False Positives: {alert_stats['false_positives']}
Pending Review: {alert_stats['total'] - alert_stats['investigated']}

False Positive Rate: {fp_rate:.2f}%
"""
            st.download_button(
                label="💾 Download Report",
                data=report,
                file_name=f"investigation_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    
    st.markdown("---")
    
    # Visualization export
    st.markdown("### 📊 Visual Reports")
    
    st.info("💡 Use the charts above to generate visual reports. Right-click on any chart to download as PNG.")

# Footer
st.markdown("---")
st.success("✅ Investigation tools ready. Select an alert to begin detailed analysis.")