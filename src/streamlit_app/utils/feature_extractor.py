"""
Feature Extraction Utilities for IDS Dashboard
Extract meaningful statistics and metrics from network traffic data
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def extract_traffic_metrics(df, time_window='1H'):
    """
    Calculate traffic metrics over time windows
    
    Args:
        df: DataFrame with network traffic
        time_window: Time window for aggregation ('1H', '30T', '1D', etc.)
        
    Returns:
        DataFrame with time-series metrics
    """
    if 'Timestamp' not in df.columns:
        return pd.DataFrame()
    
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df_copy = df.set_index('Timestamp')
    
    metrics = df_copy.resample(time_window).agg({
        'Flow Duration': 'mean',
        'Total Fwd Packets': 'sum',
        'Total Backward Packets': 'sum',
        'Flow Bytes/s': 'mean',
        'Flow Packets/s': 'mean'
    }).reset_index()
    
    metrics.columns = ['Timestamp', 'Avg_Flow_Duration', 'Total_Fwd_Packets', 
                       'Total_Bwd_Packets', 'Avg_Bytes_Per_Sec', 'Avg_Packets_Per_Sec']
    
    return metrics


def get_protocol_distribution(df):
    """
    Get protocol distribution (TCP, UDP, ICMP)
    
    Args:
        df: DataFrame with 'Protocol' column
        
    Returns:
        Dictionary with protocol counts
    """
    if 'Protocol' not in df.columns:
        return {}
    
    protocol_counts = df['Protocol'].value_counts().to_dict()
    return protocol_counts


def get_top_ports(df, n=10, port_column='Destination Port'):
    """
    Get most frequently targeted ports
    
    Args:
        df: DataFrame with port information
        n: Number of top ports to return
        port_column: Column name for ports
        
    Returns:
        DataFrame with top ports and their counts
    """
    if port_column not in df.columns:
        return pd.DataFrame()
    
    top_ports = df[port_column].value_counts().head(n).reset_index()
    top_ports.columns = ['Port', 'Count']
    
    # Add common service names
    port_services = {
        80: 'HTTP',
        443: 'HTTPS',
        22: 'SSH',
        21: 'FTP',
        25: 'SMTP',
        53: 'DNS',
        3389: 'RDP',
        8080: 'HTTP-ALT',
        3306: 'MySQL',
        5432: 'PostgreSQL'
    }
    
    top_ports['Service'] = top_ports['Port'].map(port_services).fillna('Unknown')
    return top_ports


def get_top_ips(df, n=10, ip_column='Source IP', direction='source'):
    """
    Get most active IP addresses
    
    Args:
        df: DataFrame with IP information
        n: Number of top IPs to return
        ip_column: Column name for IPs
        direction: 'source' or 'destination'
        
    Returns:
        DataFrame with top IPs and their counts
    """
    if ip_column not in df.columns:
        return pd.DataFrame()
    
    top_ips = df[ip_column].value_counts().head(n).reset_index()
    top_ips.columns = ['IP Address', 'Flow Count']
    top_ips['Direction'] = direction.capitalize()
    
    return top_ips


def calculate_attack_statistics(df):
    """
    Calculate statistics about detected attacks
    
    Args:
        df: DataFrame with 'Label' column
        
    Returns:
        Dictionary with attack statistics
    """
    if 'Label' not in df.columns:
        return {}
    
    total_flows = len(df)
    benign_flows = (df['Label'] == 'BENIGN').sum()
    attack_flows = total_flows - benign_flows
    
    stats = {
        'total_flows': total_flows,
        'benign_flows': benign_flows,
        'attack_flows': attack_flows,
        'attack_percentage': round((attack_flows / total_flows * 100), 2) if total_flows > 0 else 0,
        'attack_types': df[df['Label'] != 'BENIGN']['Label'].value_counts().to_dict()
    }
    
    return stats


def get_attack_timeline(df, time_window='1H'):
    """
    Get attack timeline showing when attacks occurred
    
    Args:
        df: DataFrame with 'Timestamp' and 'Label' columns
        time_window: Time window for aggregation
        
    Returns:
        DataFrame with attack counts over time
    """
    if 'Timestamp' not in df.columns or 'Label' not in df.columns:
        return pd.DataFrame()
    
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df_copy = df.copy()
    df_copy['Is_Attack'] = (df_copy['Label'] != 'BENIGN').astype(int)
    
    timeline = df_copy.set_index('Timestamp').resample(time_window).agg({
        'Is_Attack': 'sum',
        'Label': 'count'
    }).reset_index()
    
    timeline.columns = ['Timestamp', 'Attack_Count', 'Total_Flows']
    timeline['Attack_Rate'] = (timeline['Attack_Count'] / timeline['Total_Flows'] * 100).round(2)
    
    return timeline


def create_attack_heatmap_data(df):
    """
    Create data for attack heatmap (hour vs day)
    
    Args:
        df: DataFrame with 'Timestamp' and 'Label' columns
        
    Returns:
        DataFrame suitable for heatmap visualization
    """
    if 'Timestamp' not in df.columns or 'Label' not in df.columns:
        return pd.DataFrame()
    
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df_attacks = df[df['Label'] != 'BENIGN'].copy()
    
    df_attacks['Hour'] = df_attacks['Timestamp'].dt.hour
    df_attacks['DayOfWeek'] = df_attacks['Timestamp'].dt.day_name()
    
    heatmap = df_attacks.groupby(['DayOfWeek', 'Hour']).size().reset_index(name='Count')
    
    # Ensure all hours and days are present
    days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    hours = list(range(24))
    
    # Create complete grid
    complete_grid = pd.DataFrame(
        [(day, hour) for day in days for hour in hours],
        columns=['DayOfWeek', 'Hour']
    )
    
    heatmap = complete_grid.merge(heatmap, on=['DayOfWeek', 'Hour'], how='left')
    heatmap['Count'] = heatmap['Count'].fillna(0).astype(int)
    
    return heatmap


def calculate_flow_statistics(df):
    """
    Calculate statistical features of flows
    
    Args:
        df: DataFrame with flow features
        
    Returns:
        Dictionary with statistical summaries
    """
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    stats = {}
    for col in numeric_cols[:10]:  # Limit to avoid overload
        if col in df.columns:
            stats[col] = {
                'mean': round(df[col].mean(), 2),
                'median': round(df[col].median(), 2),
                'std': round(df[col].std(), 2),
                'min': round(df[col].min(), 2),
                'max': round(df[col].max(), 2)
            }
    
    return stats


def detect_anomaly_patterns(df):
    """
    Simple rule-based anomaly detection
    This is a basic version - your friend's ML model will be much better
    
    Args:
        df: DataFrame with flow features
        
    Returns:
        Series with anomaly scores (0-1)
    """
    scores = np.zeros(len(df))
    
    # Rule 1: Very high packet rate
    if 'Flow Packets/s' in df.columns:
        high_packet_rate = df['Flow Packets/s'] > df['Flow Packets/s'].quantile(0.95)
        scores += high_packet_rate.astype(int) * 0.3
    
    # Rule 2: Unusual SYN flag count (potential SYN flood)
    if 'SYN Flag Count' in df.columns:
        high_syn = df['SYN Flag Count'] > 10
        scores += high_syn.astype(int) * 0.4
    
    # Rule 3: Very short flow duration with many packets (suspicious)
    if 'Flow Duration' in df.columns and 'Total Fwd Packets' in df.columns:
        fast_flow = (df['Flow Duration'] < 1000) & (df['Total Fwd Packets'] > 100)
        scores += fast_flow.astype(int) * 0.3
    
    # Normalize scores to 0-1
    scores = np.clip(scores, 0, 1)
    
    return pd.Series(scores, index=df.index)


def get_network_summary(df):
    """
    Get overall network summary for dashboard KPIs
    
    Args:
        df: DataFrame with network traffic
        
    Returns:
        Dictionary with summary metrics
    """
    summary = {
        'total_flows': len(df),
        'unique_source_ips': df['Source IP'].nunique() if 'Source IP' in df.columns else 0,
        'unique_dest_ips': df['Destination IP'].nunique() if 'Destination IP' in df.columns else 0,
        'total_bytes': df['Total Length of Fwd Packets'].sum() if 'Total Length of Fwd Packets' in df.columns else 0,
        'total_packets': df['Total Fwd Packets'].sum() if 'Total Fwd Packets' in df.columns else 0,
        'avg_flow_duration': df['Flow Duration'].mean() if 'Flow Duration' in df.columns else 0,
        'protocols': get_protocol_distribution(df),
        'time_span': {
            'start': df['Timestamp'].min() if 'Timestamp' in df.columns else None,
            'end': df['Timestamp'].max() if 'Timestamp' in df.columns else None
        }
    }
    
    return summary


# Test function
if __name__ == "__main__":
    print("Testing feature_extractor.py...")
    
    # Generate sample data for testing
    from data_loader import generate_mock_traffic_data
    df = generate_mock_traffic_data(1000)
    
    # Test protocol distribution
    protocols = get_protocol_distribution(df)
    print(f"\n✅ Protocol distribution: {protocols}")
    
    # Test top ports
    top_ports = get_top_ports(df, n=5)
    print(f"\n✅ Top 5 ports:\n{top_ports}")
    
    # Test attack statistics
    attack_stats = calculate_attack_statistics(df)
    print(f"\n✅ Attack statistics: {attack_stats['attack_percentage']}% attacks")
    
    # Test network summary
    summary = get_network_summary(df)
    print(f"\n✅ Network summary: {summary['total_flows']} flows analyzed")
    
    print("\n✅ All tests passed!")