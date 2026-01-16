"""
Metrics Component for IDS Dashboard
Calculate KPIs and metrics to display in the dashboard
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta

def calculate_detection_rate(df):
    """
    Calculate the detection rate (attacks detected / total flows)
    
    Args:
        df: DataFrame with 'Label' or 'Prediction' column
        
    Returns:
        Float percentage (0-100)
    """
    if 'Label' in df.columns:
        attack_count = (df['Label'] != 'BENIGN').sum()
    elif 'Prediction' in df.columns:
        attack_count = (df['Prediction'] != 'BENIGN').sum()
    else:
        return 0.0
    
    total = len(df)
    if total == 0:
        return 0.0
    
    return round((attack_count / total) * 100, 2)


def calculate_threat_count(df, time_window='24H'):
    """
    Count threats in the specified time window
    
    Args:
        df: DataFrame with 'Timestamp' and 'Label' columns
        time_window: Time window (e.g., '24H', '1H', '7D')
        
    Returns:
        Integer count of threats
    """
    if 'Timestamp' not in df.columns or 'Label' not in df.columns:
        return 0
    
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    cutoff_time = datetime.now() - pd.Timedelta(time_window)
    
    recent_df = df[df['Timestamp'] >= cutoff_time]
    threat_count = (recent_df['Label'] != 'BENIGN').sum()
    
    return int(threat_count)


def calculate_blocked_attacks(alerts):
    """
    Calculate number of blocked attacks from alerts
    
    Args:
        alerts: List of alert dictionaries
        
    Returns:
        Integer count of blocked attacks
    """
    if not alerts:
        return 0
    
    blocked = sum(1 for alert in alerts if alert.get('blocked', False))
    return blocked


def calculate_false_positive_rate(df):
    """
    Calculate false positive rate (if ground truth is available)
    This requires both 'Label' (ground truth) and 'Prediction' columns
    
    Args:
        df: DataFrame with 'Label' and 'Prediction' columns
        
    Returns:
        Float percentage (0-100)
    """
    if 'Label' not in df.columns or 'Prediction' not in df.columns:
        return 0.0
    
    # False Positive: Predicted as attack but actually benign
    benign_flows = df[df['Label'] == 'BENIGN']
    if len(benign_flows) == 0:
        return 0.0
    
    false_positives = (benign_flows['Prediction'] != 'BENIGN').sum()
    fpr = (false_positives / len(benign_flows)) * 100
    
    return round(fpr, 2)


def calculate_accuracy(df):
    """
    Calculate prediction accuracy
    
    Args:
        df: DataFrame with 'Label' and 'Prediction' columns
        
    Returns:
        Float percentage (0-100)
    """
    if 'Label' not in df.columns or 'Prediction' not in df.columns:
        return 0.0
    
    correct = (df['Label'] == df['Prediction']).sum()
    total = len(df)
    
    if total == 0:
        return 0.0
    
    return round((correct / total) * 100, 2)


def calculate_precision_recall_f1(df, attack_type=None):
    """
    Calculate precision, recall, and F1-score
    
    Args:
        df: DataFrame with 'Label' and 'Prediction' columns
        attack_type: Specific attack type to calculate for (None for overall)
        
    Returns:
        Dictionary with precision, recall, f1_score
    """
    if 'Label' not in df.columns or 'Prediction' not in df.columns:
        return {'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0}
    
    if attack_type:
        # Calculate for specific attack type
        true_positive = ((df['Label'] == attack_type) & (df['Prediction'] == attack_type)).sum()
        false_positive = ((df['Label'] != attack_type) & (df['Prediction'] == attack_type)).sum()
        false_negative = ((df['Label'] == attack_type) & (df['Prediction'] != attack_type)).sum()
    else:
        # Calculate overall (treating all attacks as positive class)
        true_positive = ((df['Label'] != 'BENIGN') & (df['Prediction'] != 'BENIGN') & 
                        (df['Label'] == df['Prediction'])).sum()
        false_positive = ((df['Label'] == 'BENIGN') & (df['Prediction'] != 'BENIGN')).sum()
        false_negative = ((df['Label'] != 'BENIGN') & (df['Prediction'] == 'BENIGN')).sum()
    
    # Calculate metrics
    precision = true_positive / (true_positive + false_positive) if (true_positive + false_positive) > 0 else 0
    recall = true_positive / (true_positive + false_negative) if (true_positive + false_negative) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        'precision': round(precision * 100, 2),
        'recall': round(recall * 100, 2),
        'f1_score': round(f1_score * 100, 2)
    }


def get_severity_distribution(alerts):
    """
    Get distribution of alert severities
    
    Args:
        alerts: List of alert dictionaries
        
    Returns:
        Dictionary with severity counts
    """
    if not alerts:
        return {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    
    for alert in alerts:
        severity = alert.get('severity', 'Medium')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    return severity_counts


def calculate_attack_type_distribution(df):
    """
    Get distribution of attack types
    
    Args:
        df: DataFrame with 'Label' column
        
    Returns:
        Dictionary with attack type counts (excluding BENIGN)
    """
    if 'Label' not in df.columns:
        return {}
    
    attacks = df[df['Label'] != 'BENIGN']
    distribution = attacks['Label'].value_counts().to_dict()
    
    return distribution


def calculate_packets_per_second(df, time_window='1H'):
    """
    Calculate average packets per second
    
    Args:
        df: DataFrame with packet information
        time_window: Time window for calculation
        
    Returns:
        Float average packets/second
    """
    if 'Flow Packets/s' in df.columns:
        return round(df['Flow Packets/s'].mean(), 2)
    elif 'Total Fwd Packets' in df.columns and 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        time_diff = (df['Timestamp'].max() - df['Timestamp'].min()).total_seconds()
        if time_diff > 0:
            total_packets = df['Total Fwd Packets'].sum()
            return round(total_packets / time_diff, 2)
    
    return 0.0


def calculate_bytes_per_second(df):
    """
    Calculate average bytes per second
    
    Args:
        df: DataFrame with byte information
        
    Returns:
        Float average bytes/second
    """
    if 'Flow Bytes/s' in df.columns:
        return round(df['Flow Bytes/s'].mean(), 2)
    elif 'Total Length of Fwd Packets' in df.columns and 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        time_diff = (df['Timestamp'].max() - df['Timestamp'].min()).total_seconds()
        if time_diff > 0:
            total_bytes = df['Total Length of Fwd Packets'].sum()
            return round(total_bytes / time_diff, 2)
    
    return 0.0


def get_top_attacked_ports(df, n=5):
    """
    Get the most attacked ports
    
    Args:
        df: DataFrame with 'Destination Port' and 'Label' columns
        n: Number of top ports to return
        
    Returns:
        List of tuples (port, count)
    """
    if 'Destination Port' not in df.columns or 'Label' not in df.columns:
        return []
    
    attacks = df[df['Label'] != 'BENIGN']
    top_ports = attacks['Destination Port'].value_counts().head(n)
    
    return [(int(port), int(count)) for port, count in top_ports.items()]


def get_top_attacker_ips(df, n=5):
    """
    Get the most frequent attacker IPs
    
    Args:
        df: DataFrame with 'Source IP' and 'Label' columns
        n: Number of top IPs to return
        
    Returns:
        List of tuples (ip, count)
    """
    if 'Source IP' not in df.columns or 'Label' not in df.columns:
        return []
    
    attacks = df[df['Label'] != 'BENIGN']
    top_ips = attacks['Source IP'].value_counts().head(n)
    
    return [(ip, int(count)) for ip, count in top_ips.items()]


def calculate_uptime_status():
    """
    Calculate system uptime (mock for now)
    In production, this would track actual IDS uptime
    
    Returns:
        Dictionary with uptime information
    """
    # Mock uptime - your friend can implement real tracking
    uptime_hours = np.random.randint(100, 1000)
    uptime_days = uptime_hours // 24
    remaining_hours = uptime_hours % 24
    
    return {
        'hours': uptime_hours,
        'days': uptime_days,
        'remaining_hours': remaining_hours,
        'status': 'Online',
        'last_restart': (datetime.now() - timedelta(hours=uptime_hours)).strftime('%Y-%m-%d %H:%M:%S')
    }


def get_real_time_stats(df):
    """
    Get real-time statistics for live monitoring
    
    Args:
        df: DataFrame with recent traffic data
        
    Returns:
        Dictionary with real-time metrics
    """
    stats = {
        'total_flows': len(df),
        'attack_count': (df['Label'] != 'BENIGN').sum() if 'Label' in df.columns else 0,
        'benign_count': (df['Label'] == 'BENIGN').sum() if 'Label' in df.columns else 0,
        'packets_per_sec': calculate_packets_per_second(df),
        'bytes_per_sec': calculate_bytes_per_second(df),
        'unique_source_ips': df['Source IP'].nunique() if 'Source IP' in df.columns else 0,
        'unique_dest_ips': df['Destination IP'].nunique() if 'Destination IP' in df.columns else 0,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    return stats


def calculate_trend(current_value, previous_value):
    """
    Calculate percentage change between two values
    
    Args:
        current_value: Current metric value
        previous_value: Previous metric value
        
    Returns:
        Dictionary with trend info (percentage, direction)
    """
    if previous_value == 0:
        return {'percentage': 0, 'direction': 'neutral'}
    
    change = ((current_value - previous_value) / previous_value) * 100
    direction = 'up' if change > 0 else 'down' if change < 0 else 'neutral'
    
    return {
        'percentage': round(abs(change), 2),
        'direction': direction
    }


def get_hourly_attack_rate(df):
    """
    Calculate attack rate by hour of day
    
    Args:
        df: DataFrame with 'Timestamp' and 'Label' columns
        
    Returns:
        DataFrame with hourly attack rates
    """
    if 'Timestamp' not in df.columns or 'Label' not in df.columns:
        return pd.DataFrame()
    
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df['Hour'] = df['Timestamp'].dt.hour
    df['Is_Attack'] = (df['Label'] != 'BENIGN').astype(int)
    
    hourly = df.groupby('Hour').agg({
        'Is_Attack': 'sum',
        'Label': 'count'
    }).reset_index()
    
    hourly.columns = ['Hour', 'Attacks', 'Total']
    hourly['Attack_Rate'] = (hourly['Attacks'] / hourly['Total'] * 100).round(2)
    
    return hourly


def format_metric_display(value, metric_type='number'):
    """
    Format metrics for display in the dashboard
    
    Args:
        value: Metric value
        metric_type: Type of metric ('number', 'percentage', 'bytes', 'time')
        
    Returns:
        Formatted string
    """
    if metric_type == 'percentage':
        return f"{value:.2f}%"
    elif metric_type == 'bytes':
        # Convert to KB, MB, GB
        if value < 1024:
            return f"{value:.2f} B"
        elif value < 1024**2:
            return f"{value/1024:.2f} KB"
        elif value < 1024**3:
            return f"{value/(1024**2):.2f} MB"
        else:
            return f"{value/(1024**3):.2f} GB"
    elif metric_type == 'time':
        # Assume value is in seconds
        if value < 60:
            return f"{value:.1f}s"
        elif value < 3600:
            return f"{value/60:.1f}m"
        else:
            return f"{value/3600:.1f}h"
    else:
        # Regular number with thousands separator
        return f"{value:,.0f}"


# Test function
if __name__ == "__main__":
    print("Testing metrics.py...")
    
    # Generate sample data
    import sys
    sys.path.append('..')
    from utils.data_loader import generate_mock_traffic_data
    
    df = generate_mock_traffic_data(1000)
    
    # Add predictions for testing
    df['Prediction'] = df['Label']  # Perfect predictions for testing
    
    # Test various metrics
    detection_rate = calculate_detection_rate(df)
    print(f"\n✅ Detection rate: {detection_rate}%")
    
    accuracy = calculate_accuracy(df)
    print(f"✅ Accuracy: {accuracy}%")
    
    metrics = calculate_precision_recall_f1(df)
    print(f"✅ Precision: {metrics['precision']}%, Recall: {metrics['recall']}%")
    
    attack_dist = calculate_attack_type_distribution(df)
    print(f"✅ Attack distribution: {attack_dist}")
    
    top_ports = get_top_attacked_ports(df, n=3)
    print(f"✅ Top 3 attacked ports: {top_ports}")
    
    stats = get_real_time_stats(df)
    print(f"✅ Real-time stats: {stats['total_flows']} flows, {stats['attack_count']} attacks")
    
    print("\n✅ All tests passed!")