"""
Chart Components for IDS Dashboard
Reusable chart functions using Plotly for interactive visualizations
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from datetime import datetime

# Color scheme for cybersecurity theme
COLORS = {
    'benign': '#00FF41',      # Matrix green
    'attack': '#FF0000',      # Red
    'warning': '#FFA500',     # Orange
    'info': '#00BFFF',        # Blue
    'critical': '#DC143C',    # Crimson
    'high': '#FF4500',        # Orange-red
    'medium': '#FFD700',      # Gold
    'low': '#90EE90',         # Light green
    'background': '#0a0e27',  # Dark blue
    'grid': '#1e2139'         # Darker blue-grey
}


def plot_traffic_timeline(df, time_column='Timestamp', value_column='Flow Packets/s', title='Network Traffic Over Time'):
    """
    Create a line chart showing traffic over time
    
    Args:
        df: DataFrame with time-series data
        time_column: Column name for timestamps
        value_column: Column name for values to plot
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    if time_column not in df.columns or value_column not in df.columns:
        # Return empty figure
        fig = go.Figure()
        fig.add_annotation(text="No data available", showarrow=False, 
                          font=dict(size=20, color='gray'))
        return fig
    
    df_sorted = df.sort_values(time_column)
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=df_sorted[time_column],
        y=df_sorted[value_column],
        mode='lines',
        name='Traffic',
        line=dict(color=COLORS['info'], width=2),
        fill='tozeroy',
        fillcolor='rgba(0, 191, 255, 0.1)'
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title='Time',
        yaxis_title=value_column,
        template='plotly_dark',
        hovermode='x unified',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background']
    )
    
    return fig


def plot_attack_distribution_pie(df, label_column='Label', title='Attack Type Distribution'):
    """
    Create a pie chart showing distribution of attack types
    
    Args:
        df: DataFrame with labels
        label_column: Column name for attack labels
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    if label_column not in df.columns:
        fig = go.Figure()
        fig.add_annotation(text="No data available", showarrow=False)
        return fig
    
    # Count attack types
    attack_counts = df[label_column].value_counts()
    
    # Define colors for each attack type
    color_map = {
        'BENIGN': COLORS['benign'],
        'DoS': COLORS['critical'],
        'DDoS': COLORS['critical'],
        'PortScan': COLORS['medium'],
        'Bot': COLORS['high'],
        'FTP-Patator': COLORS['warning'],
        'SSH-Patator': COLORS['warning'],
        'Web Attack': COLORS['high']
    }
    
    colors = [color_map.get(label, COLORS['info']) for label in attack_counts.index]
    
    fig = go.Figure(data=[go.Pie(
        labels=attack_counts.index,
        values=attack_counts.values,
        hole=0.4,
        marker=dict(colors=colors),
        textinfo='label+percent',
        textfont=dict(size=12)
    )])
    
    fig.update_layout(
        title=title,
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        showlegend=True
    )
    
    return fig


def plot_attack_distribution_bar(df, label_column='Label', title='Attack Type Counts'):
    """
    Create a bar chart showing attack type counts
    
    Args:
        df: DataFrame with labels
        label_column: Column name for attack labels
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    if label_column not in df.columns:
        fig = go.Figure()
        return fig
    
    # Get attacks only (exclude BENIGN)
    attacks = df[df[label_column] != 'BENIGN']
    attack_counts = attacks[label_column].value_counts().sort_values(ascending=True)
    
    fig = go.Figure(data=[go.Bar(
        x=attack_counts.values,
        y=attack_counts.index,
        orientation='h',
        marker=dict(
            color=attack_counts.values,
            colorscale='Reds',
            showscale=False
        ),
        text=attack_counts.values,
        textposition='auto'
    )])
    
    fig.update_layout(
        title=title,
        xaxis_title='Count',
        yaxis_title='Attack Type',
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        height=400
    )
    
    return fig


def plot_protocol_breakdown(df, protocol_column='Protocol', title='Protocol Distribution'):
    """
    Create a bar chart showing protocol distribution
    
    Args:
        df: DataFrame with protocol information
        protocol_column: Column name for protocols
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    if protocol_column not in df.columns:
        fig = go.Figure()
        return fig
    
    protocol_counts = df[protocol_column].value_counts()
    
    colors_list = [COLORS['info'], COLORS['warning'], COLORS['benign']]
    
    fig = go.Figure(data=[go.Bar(
        x=protocol_counts.index,
        y=protocol_counts.values,
        marker=dict(color=colors_list[:len(protocol_counts)]),
        text=protocol_counts.values,
        textposition='auto'
    )])
    
    fig.update_layout(
        title=title,
        xaxis_title='Protocol',
        yaxis_title='Count',
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background']
    )
    
    return fig


def plot_attack_timeline(df, time_column='Timestamp', label_column='Label', 
                         time_window='1H', title='Attack Timeline'):
    """
    Create a timeline showing when attacks occurred
    
    Args:
        df: DataFrame with timestamps and labels
        time_column: Column name for timestamps
        label_column: Column name for labels
        time_window: Aggregation window
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    if time_column not in df.columns or label_column not in df.columns:
        fig = go.Figure()
        return fig
    
    df[time_column] = pd.to_datetime(df[time_column])
    df_copy = df.copy()
    df_copy['Is_Attack'] = (df_copy[label_column] != 'BENIGN').astype(int)
    
    # Resample by time window
    timeline = df_copy.set_index(time_column).resample(time_window).agg({
        'Is_Attack': 'sum',
        label_column: 'count'
    }).reset_index()
    
    timeline.columns = [time_column, 'Attacks', 'Total']
    
    fig = go.Figure()
    
    # Total traffic (area)
    fig.add_trace(go.Scatter(
        x=timeline[time_column],
        y=timeline['Total'],
        mode='lines',
        name='Total Traffic',
        line=dict(color=COLORS['info'], width=1),
        fill='tozeroy',
        fillcolor='rgba(0, 191, 255, 0.1)'
    ))
    
    # Attacks (bars)
    fig.add_trace(go.Bar(
        x=timeline[time_column],
        y=timeline['Attacks'],
        name='Attacks',
        marker=dict(color=COLORS['attack']),
        opacity=0.7
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title='Time',
        yaxis_title='Count',
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        hovermode='x unified',
        barmode='overlay'
    )
    
    return fig


def plot_confusion_matrix(confusion_matrix, class_names, title='Confusion Matrix'):
    """
    Create a heatmap visualization of confusion matrix
    
    Args:
        confusion_matrix: 2D array or list of lists
        class_names: List of class names
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    cm_array = np.array(confusion_matrix)
    
    # Normalize for color scale
    cm_normalized = cm_array.astype('float') / cm_array.sum(axis=1)[:, np.newaxis]
    
    fig = go.Figure(data=go.Heatmap(
        z=cm_array,
        x=class_names,
        y=class_names,
        colorscale='RdYlGn_r',
        text=cm_array,
        texttemplate='%{text}',
        textfont={"size": 12},
        hovertemplate='True: %{y}<br>Predicted: %{x}<br>Count: %{z}<extra></extra>'
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title='Predicted Label',
        yaxis_title='True Label',
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        height=500,
        width=600
    )
    
    return fig


def plot_roc_curve(fpr, tpr, auc_score, title='ROC Curve'):
    """
    Plot ROC curve
    
    Args:
        fpr: False positive rates (list)
        tpr: True positive rates (list)
        auc_score: AUC score (float)
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    fig = go.Figure()
    
    # ROC curve
    fig.add_trace(go.Scatter(
        x=fpr,
        y=tpr,
        mode='lines',
        name=f'ROC Curve (AUC = {auc_score:.3f})',
        line=dict(color=COLORS['info'], width=3)
    ))
    
    # Diagonal line (random classifier)
    fig.add_trace(go.Scatter(
        x=[0, 1],
        y=[0, 1],
        mode='lines',
        name='Random Classifier',
        line=dict(color='gray', width=2, dash='dash')
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title='False Positive Rate',
        yaxis_title='True Positive Rate',
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        xaxis=dict(range=[0, 1]),
        yaxis=dict(range=[0, 1])
    )
    
    return fig


def plot_feature_importance(feature_dict, title='Feature Importance', top_n=15):
    """
    Plot feature importance from model
    
    Args:
        feature_dict: Dictionary {feature_name: importance_score}
        title: Chart title
        top_n: Number of top features to show
        
    Returns:
        Plotly figure object
    """
    # Sort by importance
    sorted_features = sorted(feature_dict.items(), key=lambda x: x[1], reverse=True)[:top_n]
    features, importance = zip(*sorted_features)
    
    fig = go.Figure(data=[go.Bar(
        x=list(importance),
        y=list(features),
        orientation='h',
        marker=dict(
            color=list(importance),
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title='Importance')
        ),
        text=[f'{imp:.3f}' for imp in importance],
        textposition='auto'
    )])
    
    fig.update_layout(
        title=title,
        xaxis_title='Importance Score',
        yaxis_title='Feature',
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        height=500
    )
    
    return fig


def plot_port_distribution(df, port_column='Destination Port', label_column='Label', 
                           top_n=10, title='Most Targeted Ports'):
    """
    Plot distribution of targeted ports
    
    Args:
        df: DataFrame with port and label data
        port_column: Column name for ports
        label_column: Column name for labels
        top_n: Number of top ports to show
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    if port_column not in df.columns or label_column not in df.columns:
        fig = go.Figure()
        return fig
    
    attacks = df[df[label_column] != 'BENIGN']
    port_counts = attacks[port_column].value_counts().head(top_n)
    
    # Map common port numbers to services
    port_services = {
        80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
        25: 'SMTP', 53: 'DNS', 3389: 'RDP', 8080: 'HTTP-ALT',
        3306: 'MySQL', 5432: 'PostgreSQL'
    }
    
    labels = [f"{port} ({port_services.get(port, 'Unknown')})" for port in port_counts.index]
    
    fig = go.Figure(data=[go.Bar(
        x=labels,
        y=port_counts.values,
        marker=dict(color=COLORS['high']),
        text=port_counts.values,
        textposition='auto'
    )])
    
    fig.update_layout(
        title=title,
        xaxis_title='Port (Service)',
        yaxis_title='Attack Count',
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        xaxis_tickangle=-45
    )
    
    return fig


def plot_severity_gauge(critical_count, high_count, medium_count, low_count, 
                        title='Alert Severity Distribution'):
    """
    Create a gauge chart for alert severity
    
    Args:
        critical_count: Number of critical alerts
        high_count: Number of high severity alerts
        medium_count: Number of medium severity alerts
        low_count: Number of low severity alerts
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    total = critical_count + high_count + medium_count + low_count
    
    if total == 0:
        severity_score = 0
    else:
        # Weight: Critical=4, High=3, Medium=2, Low=1
        weighted_sum = (critical_count * 4 + high_count * 3 + 
                       medium_count * 2 + low_count * 1)
        severity_score = (weighted_sum / (total * 4)) * 100
    
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=severity_score,
        title={'text': title},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkred"},
            'steps': [
                {'range': [0, 25], 'color': COLORS['low']},
                {'range': [25, 50], 'color': COLORS['medium']},
                {'range': [50, 75], 'color': COLORS['high']},
                {'range': [75, 100], 'color': COLORS['critical']}
            ],
            'threshold': {
                'line': {'color': "white", 'width': 4},
                'thickness': 0.75,
                'value': severity_score
            }
        }
    ))
    
    fig.update_layout(
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        height=300
    )
    
    return fig


def plot_live_metrics_line(data_list, metric_name='Packets/s', title='Live Metrics'):
    """
    Create a real-time updating line chart
    
    Args:
        data_list: List of (timestamp, value) tuples
        metric_name: Name of the metric
        title: Chart title
        
    Returns:
        Plotly figure object
    """
    if not data_list:
        fig = go.Figure()
        return fig
    
    timestamps, values = zip(*data_list)
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatter(
        x=list(timestamps),
        y=list(values),
        mode='lines+markers',
        name=metric_name,
        line=dict(color=COLORS['benign'], width=2),
        marker=dict(size=4)
    ))
    
    fig.update_layout(
        title=title,
        xaxis_title='Time',
        yaxis_title=metric_name,
        template='plotly_dark',
        plot_bgcolor=COLORS['background'],
        paper_bgcolor=COLORS['background'],
        hovermode='x unified',
        height=300
    )
    
    return fig


# Test function
if __name__ == "__main__":
    print("Testing charts.py...")
    
    # Generate sample data
    import sys
    sys.path.append('..')
    from utils.data_loader import generate_mock_traffic_data
    
    df = generate_mock_traffic_data(500)
    
    # Test charts
    print("\n✅ Testing traffic timeline...")
    fig1 = plot_traffic_timeline(df)
    
    print("✅ Testing attack distribution pie...")
    fig2 = plot_attack_distribution_pie(df)
    
    print("✅ Testing protocol breakdown...")
    fig3 = plot_protocol_breakdown(df)
    
    print("✅ Testing attack timeline...")
    fig4 = plot_attack_timeline(df)
    
    print("✅ Testing confusion matrix...")
    cm = [[950, 20, 15, 10, 5],
          [10, 480, 5, 3, 2],
          [8, 6, 470, 12, 4],
          [5, 4, 8, 475, 8],
          [3, 2, 4, 6, 485]]
    classes = ['BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot']
    fig5 = plot_confusion_matrix(cm, classes)
    
    print("\n✅ All chart tests passed!")
    print("Charts created successfully - ready for Streamlit integration!")