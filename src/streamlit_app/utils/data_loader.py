"""
Data Loading Utilities for IDS Dashboard
This module handles loading data from various sources
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import os
import json

def load_cicids2017_sample(file_path=None, sample_size=10000):
    """
    Load a sample of CICIDS2017 dataset
    
    Args:
        file_path: Path to the CSV file (your friend will provide this)
        sample_size: Number of rows to load for performance
        
    Returns:
        DataFrame with network traffic data
    """
    # TODO: Replace this with actual CICIDS2017 loading when available
    # For now, create mock data that matches CICIDS2017 structure
    
    if file_path and os.path.exists(file_path):
        # Load real data
        df = pd.read_csv(file_path, nrows=sample_size)
        return df
    else:
        # Generate mock data for testing
        print("⚠️ No dataset found. Generating mock data for testing...")
        return generate_mock_traffic_data(sample_size)


def generate_mock_traffic_data(n_rows=1000):
    """
    Generate mock network traffic data that looks like CICIDS2017
    This is ONLY for testing until your friend provides the real dataset
    
    Returns:
        DataFrame with mock traffic data
    """
    np.random.seed(42)
    
    # Attack types from CICIDS2017
    attack_types = ['BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot', 
                    'FTP-Patator', 'SSH-Patator', 'Web Attack']
    
    # Generate timestamps (last 24 hours)
    end_time = datetime.now()
    start_time = end_time - timedelta(hours=24)
    timestamps = [start_time + timedelta(seconds=i*86400/n_rows) 
                  for i in range(n_rows)]
    
    data = {
        'Timestamp': timestamps,
        'Flow Duration': np.random.randint(0, 10000000, n_rows),
        'Total Fwd Packets': np.random.randint(1, 1000, n_rows),
        'Total Backward Packets': np.random.randint(0, 500, n_rows),
        'Total Length of Fwd Packets': np.random.randint(0, 50000, n_rows),
        'Total Length of Bwd Packets': np.random.randint(0, 30000, n_rows),
        'Flow Bytes/s': np.random.uniform(0, 1000000, n_rows),
        'Flow Packets/s': np.random.uniform(0, 10000, n_rows),
        'Flow IAT Mean': np.random.uniform(0, 100000, n_rows),
        'Flow IAT Max': np.random.uniform(0, 500000, n_rows),
        'Fwd IAT Mean': np.random.uniform(0, 100000, n_rows),
        'Bwd IAT Mean': np.random.uniform(0, 100000, n_rows),
        'Fwd PSH Flags': np.random.randint(0, 10, n_rows),
        'Bwd PSH Flags': np.random.randint(0, 10, n_rows),
        'Fwd URG Flags': np.random.randint(0, 3, n_rows),
        'Bwd URG Flags': np.random.randint(0, 3, n_rows),
        'FIN Flag Count': np.random.randint(0, 5, n_rows),
        'SYN Flag Count': np.random.randint(0, 5, n_rows),
        'RST Flag Count': np.random.randint(0, 5, n_rows),
        'PSH Flag Count': np.random.randint(0, 5, n_rows),
        'ACK Flag Count': np.random.randint(0, 20, n_rows),
        'URG Flag Count': np.random.randint(0, 3, n_rows),
        'Down/Up Ratio': np.random.uniform(0, 10, n_rows),
        'Average Packet Size': np.random.uniform(0, 1500, n_rows),
        'Avg Fwd Segment Size': np.random.uniform(0, 1500, n_rows),
        'Avg Bwd Segment Size': np.random.uniform(0, 1500, n_rows),
        'Subflow Fwd Packets': np.random.randint(1, 100, n_rows),
        'Subflow Bwd Packets': np.random.randint(0, 50, n_rows),
        'Init_Win_bytes_forward': np.random.randint(0, 65535, n_rows),
        'Init_Win_bytes_backward': np.random.randint(0, 65535, n_rows),
        'Protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], n_rows, p=[0.7, 0.25, 0.05]),
        'Destination Port': np.random.choice([80, 443, 22, 21, 53, 3389, 8080, 25], n_rows),
        'Source IP': [f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}" 
                      for _ in range(n_rows)],
        'Destination IP': [f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}" 
                           for _ in range(n_rows)],
        # Label column - 70% benign, 30% attacks
        'Label': np.random.choice(attack_types, n_rows, 
                                 p=[0.70, 0.08, 0.07, 0.05, 0.04, 0.02, 0.02, 0.02])
    }
    
    df = pd.DataFrame(data)
    return df


def load_live_traffic(file_path='data/live_traffic.csv'):
    """
    Load live traffic data buffer
    This will be updated by your friend's model in real-time
    
    Returns:
        DataFrame with recent traffic
    """
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        # Ensure Timestamp is datetime
        if 'Timestamp' in df.columns:
            df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        return df
    else:
        # Create empty file with correct structure
        df = generate_mock_traffic_data(100)
        os.makedirs('data', exist_ok=True)
        df.to_csv(file_path, index=False)
        return df


def load_historical_alerts(file_path='data/historical_alerts.json'):
    """
    Load historical alerts from JSON file
    
    Returns:
        List of alert dictionaries
    """
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            alerts = json.load(f)
        return alerts
    else:
        # Generate sample alerts
        alerts = generate_sample_alerts()
        save_alerts(alerts, file_path)
        return alerts


def save_alerts(alerts, file_path='data/historical_alerts.json'):
    """
    Save alerts to JSON file
    
    Args:
        alerts: List of alert dictionaries
        file_path: Path to save file
    """
    os.makedirs('data', exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(alerts, f, indent=2, default=str)


def generate_sample_alerts(n_alerts=50):
    """
    Generate sample alerts for testing
    This simulates what your friend's model will detect
    
    Returns:
        List of alert dictionaries
    """
    attack_types = ['DoS', 'DDoS', 'PortScan', 'Bot', 'Brute Force', 'Web Attack']
    severities = ['Critical', 'High', 'Medium', 'Low']
    
    alerts = []
    end_time = datetime.now()
    
    for i in range(n_alerts):
        alert_time = end_time - timedelta(hours=np.random.randint(0, 168))  # Last week
        
        alert = {
            'id': f'ALERT-{i+1:04d}',
            'timestamp': alert_time.strftime('%Y-%m-%d %H:%M:%S'),
            'attack_type': np.random.choice(attack_types),
            'severity': np.random.choice(severities, p=[0.15, 0.25, 0.35, 0.25]),
            'source_ip': f"192.168.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
            'destination_ip': f"10.0.{np.random.randint(1,255)}.{np.random.randint(1,255)}",
            'destination_port': np.random.choice([80, 443, 22, 21, 3389, 8080]),
            'confidence': round(np.random.uniform(0.75, 0.99), 2),
            'packets': np.random.randint(10, 10000),
            'bytes': np.random.randint(1000, 1000000),
            'blocked': np.random.choice([True, False], p=[0.7, 0.3])
        }
        alerts.append(alert)
    
    # Sort by timestamp (newest first)
    alerts.sort(key=lambda x: x['timestamp'], reverse=True)
    return alerts


def filter_data_by_date(df, start_date, end_date):
    """
    Filter dataframe by date range
    
    Args:
        df: DataFrame with 'Timestamp' column
        start_date: Start date (datetime or string)
        end_date: End date (datetime or string)
        
    Returns:
        Filtered DataFrame
    """
    if 'Timestamp' not in df.columns:
        return df
    
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    mask = (df['Timestamp'] >= pd.to_datetime(start_date)) & \
           (df['Timestamp'] <= pd.to_datetime(end_date))
    return df[mask]


def get_attack_types(df):
    """
    Get unique attack types from dataset
    
    Args:
        df: DataFrame with 'Label' column
        
    Returns:
        List of unique attack types
    """
    if 'Label' in df.columns:
        return sorted(df['Label'].unique().tolist())
    return []


def get_data_summary(df):
    """
    Get summary statistics of the dataset
    
    Args:
        df: DataFrame
        
    Returns:
        Dictionary with summary stats
    """
    summary = {
        'total_flows': len(df),
        'date_range': {
            'start': df['Timestamp'].min() if 'Timestamp' in df.columns else None,
            'end': df['Timestamp'].max() if 'Timestamp' in df.columns else None
        },
        'attack_distribution': df['Label'].value_counts().to_dict() if 'Label' in df.columns else {},
        'protocol_distribution': df['Protocol'].value_counts().to_dict() if 'Protocol' in df.columns else {},
        'benign_count': (df['Label'] == 'BENIGN').sum() if 'Label' in df.columns else 0,
        'attack_count': (df['Label'] != 'BENIGN').sum() if 'Label' in df.columns else 0
    }
    return summary


# Test function
if __name__ == "__main__":
    print("Testing data_loader.py...")
    
    # Test mock data generation
    df = load_cicids2017_sample()
    print(f"\n✅ Generated {len(df)} mock traffic flows")
    print(f"Columns: {df.columns.tolist()[:5]}...")
    print(f"\nAttack distribution:\n{df['Label'].value_counts()}")
    
    # Test alerts
    alerts = load_historical_alerts()
    print(f"\n✅ Generated {len(alerts)} sample alerts")
    print(f"First alert: {alerts[0]}")
    
    print("\n✅ All tests passed!")