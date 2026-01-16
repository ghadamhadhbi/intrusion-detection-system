"""
Alert Management Component for IDS Dashboard
Generate, save, and manage security alerts
"""

import json
import os
from datetime import datetime
import pandas as pd

class AlertManager:
    """
    Manage security alerts for the IDS system
    """
    
    def __init__(self, alerts_file='data/historical_alerts.json'):
        """
        Initialize the alert manager
        
        Args:
            alerts_file: Path to store alerts
        """
        self.alerts_file = alerts_file
        self.alerts = self.load_alerts()
    
    
    def generate_alert(self, flow_data, prediction_result):
        """
        Generate a security alert from a detected attack
        
        Args:
            flow_data: Dictionary or Series with network flow data
            prediction_result: Dictionary with prediction info from model
            
        Returns:
            Dictionary with alert information
        """
        # Only create alert if it's an attack
        if not prediction_result.get('is_attack', False):
            return None
        
        alert = {
            'id': self._generate_alert_id(),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'attack_type': prediction_result.get('prediction', 'Unknown'),
            'severity': prediction_result.get('severity', 'Medium'),
            'confidence': prediction_result.get('confidence', 0.0),
            'source_ip': flow_data.get('Source IP', 'Unknown'),
            'destination_ip': flow_data.get('Destination IP', 'Unknown'),
            'destination_port': int(flow_data.get('Destination Port', 0)),
            'protocol': flow_data.get('Protocol', 'Unknown'),
            'packets': int(flow_data.get('Total Fwd Packets', 0)),
            'bytes': int(flow_data.get('Total Length of Fwd Packets', 0)),
            'flow_duration': int(flow_data.get('Flow Duration', 0)),
            'blocked': self._should_block(prediction_result),
            'investigated': False,
            'false_positive': False,
            'notes': ''
        }
        
        return alert
    
    
    def _generate_alert_id(self):
        """
        Generate a unique alert ID
        
        Returns:
            String alert ID
        """
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        count = len(self.alerts) + 1
        return f"ALERT-{timestamp}-{count:04d}"
    
    
    def _should_block(self, prediction_result):
        """
        Determine if an attack should be blocked automatically
        
        Args:
            prediction_result: Dictionary with prediction info
            
        Returns:
            Boolean whether to block
        """
        severity = prediction_result.get('severity', 'Medium')
        confidence = prediction_result.get('confidence', 0.0)
        
        # Block if Critical or High severity with high confidence
        if severity == 'Critical' and confidence >= 0.85:
            return True
        elif severity == 'High' and confidence >= 0.90:
            return True
        else:
            return False
    
    
    def add_alert(self, alert):
        """
        Add a new alert to the list
        
        Args:
            alert: Alert dictionary
        """
        if alert:
            self.alerts.insert(0, alert)  # Add to beginning (newest first)
            self.save_alerts()
    
    
    def save_alerts(self):
        """
        Save alerts to JSON file
        """
        os.makedirs(os.path.dirname(self.alerts_file), exist_ok=True)
        with open(self.alerts_file, 'w') as f:
            json.dump(self.alerts, f, indent=2, default=str)
    
    
    def load_alerts(self):
        """
        Load alerts from JSON file
        
        Returns:
            List of alert dictionaries
        """
        if os.path.exists(self.alerts_file):
            try:
                with open(self.alerts_file, 'r') as f:
                    alerts = json.load(f)
                return alerts
            except Exception as e:
                print(f"Error loading alerts: {e}")
                return []
        return []
    
    
    def get_recent_alerts(self, n=10):
        """
        Get the most recent alerts
        
        Args:
            n: Number of alerts to return
            
        Returns:
            List of recent alert dictionaries
        """
        return self.alerts[:n]
    
    
    def get_alerts_by_severity(self, severity):
        """
        Get alerts filtered by severity level
        
        Args:
            severity: 'Critical', 'High', 'Medium', or 'Low'
            
        Returns:
            List of alerts with matching severity
        """
        return [alert for alert in self.alerts if alert.get('severity') == severity]
    
    
    def get_alerts_by_type(self, attack_type):
        """
        Get alerts filtered by attack type
        
        Args:
            attack_type: Attack type string (e.g., 'DoS', 'DDoS')
            
        Returns:
            List of alerts with matching attack type
        """
        return [alert for alert in self.alerts if alert.get('attack_type') == attack_type]
    
    
    def get_alerts_by_timeframe(self, hours=24):
        """
        Get alerts from the last N hours
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of alerts within timeframe
        """
        cutoff = datetime.now().timestamp() - (hours * 3600)
        
        filtered_alerts = []
        for alert in self.alerts:
            alert_time = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()
            if alert_time >= cutoff:
                filtered_alerts.append(alert)
        
        return filtered_alerts
    
    
    def mark_as_investigated(self, alert_id):
        """
        Mark an alert as investigated
        
        Args:
            alert_id: Alert ID to update
        """
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['investigated'] = True
                self.save_alerts()
                break
    
    
    def mark_as_false_positive(self, alert_id, notes=''):
        """
        Mark an alert as false positive
        
        Args:
            alert_id: Alert ID to update
            notes: Optional notes about why it's false positive
        """
        for alert in self.alerts:
            if alert['id'] == alert_id:
                alert['false_positive'] = True
                alert['investigated'] = True
                alert['notes'] = notes
                self.save_alerts()
                break
    
    
    def get_alert_statistics(self):
        """
        Get statistics about alerts
        
        Returns:
            Dictionary with alert statistics
        """
        if not self.alerts:
            return {
                'total': 0,
                'by_severity': {},
                'by_type': {},
                'blocked': 0,
                'investigated': 0,
                'false_positives': 0
            }
        
        stats = {
            'total': len(self.alerts),
            'by_severity': {},
            'by_type': {},
            'blocked': sum(1 for a in self.alerts if a.get('blocked', False)),
            'investigated': sum(1 for a in self.alerts if a.get('investigated', False)),
            'false_positives': sum(1 for a in self.alerts if a.get('false_positive', False))
        }
        
        # Count by severity
        for alert in self.alerts:
            severity = alert.get('severity', 'Unknown')
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
        
        # Count by type
        for alert in self.alerts:
            attack_type = alert.get('attack_type', 'Unknown')
            stats['by_type'][attack_type] = stats['by_type'].get(attack_type, 0) + 1
        
        return stats
    
    
    def export_alerts_to_csv(self, output_file='alerts_export.csv'):
        """
        Export alerts to CSV file
        
        Args:
            output_file: Path to output CSV file
        """
        if not self.alerts:
            print("No alerts to export")
            return
        
        df = pd.DataFrame(self.alerts)
        df.to_csv(output_file, index=False)
        print(f"✅ Exported {len(self.alerts)} alerts to {output_file}")
    
    
    def clear_old_alerts(self, days=30):
        """
        Clear alerts older than specified days
        
        Args:
            days: Number of days to keep
        """
        cutoff = datetime.now().timestamp() - (days * 24 * 3600)
        
        filtered_alerts = []
        removed_count = 0
        
        for alert in self.alerts:
            alert_time = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S').timestamp()
            if alert_time >= cutoff:
                filtered_alerts.append(alert)
            else:
                removed_count += 1
        
        self.alerts = filtered_alerts
        self.save_alerts()
        
        print(f"✅ Removed {removed_count} alerts older than {days} days")


def format_alert_message(alert):
    """
    Format an alert into a human-readable message
    
    Args:
        alert: Alert dictionary
        
    Returns:
        Formatted string message
    """
    severity_emoji = {
        'Critical': '🔴',
        'High': '🟠',
        'Medium': '🟡',
        'Low': '🟢'
    }
    
    emoji = severity_emoji.get(alert.get('severity', 'Medium'), '⚪')
    
    message = f"""
{emoji} **{alert.get('severity', 'Unknown')} Severity Alert**

**Attack Type:** {alert.get('attack_type', 'Unknown')}
**Confidence:** {alert.get('confidence', 0):.2f}
**Time:** {alert.get('timestamp', 'Unknown')}

**Source IP:** {alert.get('source_ip', 'Unknown')}
**Destination IP:** {alert.get('destination_ip', 'Unknown')}
**Port:** {alert.get('destination_port', 0)}
**Protocol:** {alert.get('protocol', 'Unknown')}

**Traffic:** {alert.get('packets', 0)} packets, {alert.get('bytes', 0)} bytes
**Status:** {'🛡️ BLOCKED' if alert.get('blocked', False) else '⚠️ DETECTED'}
"""
    
    return message.strip()


def get_severity_color(severity):
    """
    Get color code for severity level
    
    Args:
        severity: Severity string
        
    Returns:
        Hex color code
    """
    colors = {
        'Critical': '#DC143C',
        'High': '#FF4500',
        'Medium': '#FFD700',
        'Low': '#90EE90'
    }
    return colors.get(severity, '#808080')


def create_alert_dataframe(alerts):
    """
    Convert alerts list to pandas DataFrame for display
    
    Args:
        alerts: List of alert dictionaries
        
    Returns:
        pandas DataFrame
    """
    if not alerts:
        return pd.DataFrame()
    
    df = pd.DataFrame(alerts)
    
    # Select important columns for display
    display_cols = ['id', 'timestamp', 'attack_type', 'severity', 'confidence',
                   'source_ip', 'destination_ip', 'destination_port', 
                   'blocked', 'investigated']
    
    # Only include columns that exist
    display_cols = [col for col in display_cols if col in df.columns]
    
    return df[display_cols]


# Global alert manager instance
alert_manager = AlertManager()


# Test function
if __name__ == "__main__":
    print("Testing alerts.py...")
    
    # Create test alert manager
    test_manager = AlertManager('data/test_alerts.json')
    
    # Generate test alert
    flow_data = {
        'Source IP': '192.168.1.100',
        'Destination IP': '10.0.0.50',
        'Destination Port': 80,
        'Protocol': 'TCP',
        'Total Fwd Packets': 1500,
        'Total Length of Fwd Packets': 50000,
        'Flow Duration': 10000
    }
    
    prediction = {
        'prediction': 'DoS',
        'confidence': 0.95,
        'is_attack': True,
        'severity': 'Critical'
    }
    
    alert = test_manager.generate_alert(flow_data, prediction)
    print(f"\n✅ Generated alert: {alert['id']}")
    
    test_manager.add_alert(alert)
    print(f"✅ Alert saved to {test_manager.alerts_file}")
    
    # Test retrieval
    recent = test_manager.get_recent_alerts(5)
    print(f"✅ Retrieved {len(recent)} recent alerts")
    
    # Test statistics
    stats = test_manager.get_alert_statistics()
    print(f"✅ Alert statistics: {stats['total']} total alerts")
    
    # Test formatting
    message = format_alert_message(alert)
    print(f"\n✅ Formatted alert message:\n{message}")
    
    print("\n✅ All alert tests passed!")