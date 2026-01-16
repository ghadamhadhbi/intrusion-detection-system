"""
Feature Extraction Module for Network Traffic Analysis
Extracts relevant features from network flow data
"""

import pandas as pd
import numpy as np
import logging
from typing import List, Dict
import yaml

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkFeatureExtractor:
    """
    Extract features from network traffic data
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize feature extractor
        
        Args:
            config_path: Path to configuration file
        """
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
    
    def extract_basic_flow_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract basic flow-level features
        
        Args:
            df: Input DataFrame with raw network data
            
        Returns:
            DataFrame with extracted features
        """
        logger.info("Extracting basic flow features...")
        
        features = pd.DataFrame(index=df.index)
        
        # Flow duration features
        if 'Flow Duration' in df.columns:
            features['flow_duration'] = df['Flow Duration']
            features['flow_duration_log'] = np.log1p(df['Flow Duration'])
        
        # Packet count features
        if 'Total Fwd Packets' in df.columns and 'Total Backward Packets' in df.columns:
            features['total_packets'] = df['Total Fwd Packets'] + df['Total Backward Packets']
            features['fwd_packets'] = df['Total Fwd Packets']
            features['bwd_packets'] = df['Total Backward Packets']
            features['packet_ratio'] = df['Total Fwd Packets'] / (df['Total Backward Packets'] + 1)
        
        # Byte count features
        if 'Total Length of Fwd Packets' in df.columns and 'Total Length of Bwd Packets' in df.columns:
            features['total_bytes'] = df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']
            features['fwd_bytes'] = df['Total Length of Fwd Packets']
            features['bwd_bytes'] = df['Total Length of Bwd Packets']
            features['byte_ratio'] = df['Total Length of Fwd Packets'] / (df['Total Length of Bwd Packets'] + 1)
        
        # Packet length statistics
        if 'Fwd Packet Length Mean' in df.columns:
            features['fwd_pkt_len_mean'] = df['Fwd Packet Length Mean']
            features['fwd_pkt_len_std'] = df['Fwd Packet Length Std']
            features['fwd_pkt_len_max'] = df['Fwd Packet Length Max']
            features['fwd_pkt_len_min'] = df['Fwd Packet Length Min']
        
        if 'Bwd Packet Length Mean' in df.columns:
            features['bwd_pkt_len_mean'] = df['Bwd Packet Length Mean']
            features['bwd_pkt_len_std'] = df['Bwd Packet Length Std']
            features['bwd_pkt_len_max'] = df['Bwd Packet Length Max']
            features['bwd_pkt_len_min'] = df['Bwd Packet Length Min']
        
        logger.info(f"Extracted {len(features.columns)} basic flow features")
        return features
    
    def extract_statistical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract statistical features from flow data
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with statistical features
        """
        logger.info("Extracting statistical features...")
        
        features = pd.DataFrame(index=df.index)
        
        # Flow rate features
        if 'Flow Duration' in df.columns and 'Total Fwd Packets' in df.columns:
            flow_duration_sec = df['Flow Duration'] / 1000000  # Convert to seconds
            features['flow_packets_per_sec'] = (
                (df['Total Fwd Packets'] + df['Total Backward Packets']) / 
                (flow_duration_sec + 1)
            )
            features['flow_bytes_per_sec'] = (
                (df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']) / 
                (flow_duration_sec + 1)
            )
        
        # Inter-arrival time features
        if 'Flow IAT Mean' in df.columns:
            features['flow_iat_mean'] = df['Flow IAT Mean']
            features['flow_iat_std'] = df['Flow IAT Std']
            features['flow_iat_max'] = df['Flow IAT Max']
            features['flow_iat_min'] = df['Flow IAT Min']
        
        if 'Fwd IAT Mean' in df.columns:
            features['fwd_iat_mean'] = df['Fwd IAT Mean']
            features['fwd_iat_std'] = df['Fwd IAT Std']
            features['fwd_iat_max'] = df['Fwd IAT Max']
            features['fwd_iat_min'] = df['Fwd IAT Min']
            features['fwd_iat_total'] = df['Fwd IAT Total']
        
        if 'Bwd IAT Mean' in df.columns:
            features['bwd_iat_mean'] = df['Bwd IAT Mean']
            features['bwd_iat_std'] = df['Bwd IAT Std']
            features['bwd_iat_max'] = df['Bwd IAT Max']
            features['bwd_iat_min'] = df['Bwd IAT Min']
            features['bwd_iat_total'] = df['Bwd IAT Total']
        
        # Active and Idle time features
        if 'Active Mean' in df.columns:
            features['active_mean'] = df['Active Mean']
            features['active_std'] = df['Active Std']
            features['active_max'] = df['Active Max']
            features['active_min'] = df['Active Min']
        
        if 'Idle Mean' in df.columns:
            features['idle_mean'] = df['Idle Mean']
            features['idle_std'] = df['Idle Std']
            features['idle_max'] = df['Idle Max']
            features['idle_min'] = df['Idle Min']
        
        logger.info(f"Extracted {len(features.columns)} statistical features")
        return features
    
    def extract_flag_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract TCP flag-based features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with flag features
        """
        logger.info("Extracting TCP flag features...")
        
        features = pd.DataFrame(index=df.index)
        
        # Flag counts
        flag_columns = [
            'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
            'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count',
            'CWE Flag Count', 'ECE Flag Count'
        ]
        
        for col in flag_columns:
            if col in df.columns:
                feature_name = col.lower().replace(' ', '_')
                features[feature_name] = df[col]
        
        # Flag ratios
        if 'Fwd PSH Flags' in df.columns:
            features['fwd_psh_flags'] = df['Fwd PSH Flags']
        if 'Bwd PSH Flags' in df.columns:
            features['bwd_psh_flags'] = df['Bwd PSH Flags']
        if 'Fwd URG Flags' in df.columns:
            features['fwd_urg_flags'] = df['Fwd URG Flags']
        if 'Bwd URG Flags' in df.columns:
            features['bwd_urg_flags'] = df['Bwd URG Flags']
        
        logger.info(f"Extracted {len(features.columns)} flag features")
        return features
    
    def extract_header_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract header length features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with header features
        """
        logger.info("Extracting header features...")
        
        features = pd.DataFrame(index=df.index)
        
        if 'Fwd Header Length' in df.columns:
            features['fwd_header_length'] = df['Fwd Header Length']
        
        if 'Bwd Header Length' in df.columns:
            features['bwd_header_length'] = df['Bwd Header Length']
        
        # Header length ratios
        if 'Fwd Header Length' in df.columns and 'Total Fwd Packets' in df.columns:
            features['fwd_header_length_mean'] = df['Fwd Header Length'] / (df['Total Fwd Packets'] + 1)
        
        if 'Bwd Header Length' in df.columns and 'Total Backward Packets' in df.columns:
            features['bwd_header_length_mean'] = df['Bwd Header Length'] / (df['Total Backward Packets'] + 1)
        
        logger.info(f"Extracted {len(features.columns)} header features")
        return features
    
    def extract_protocol_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract protocol-based features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with protocol features
        """
        logger.info("Extracting protocol features...")
        
        features = pd.DataFrame(index=df.index)
        
        # Protocol type (if available)
        if 'Protocol' in df.columns:
            # One-hot encode protocol
            protocol_dummies = pd.get_dummies(df['Protocol'], prefix='protocol')
            features = pd.concat([features, protocol_dummies], axis=1)
        
        # Destination port (common ports)
        if 'Destination Port' in df.columns:
            features['dst_port'] = df['Destination Port']
            
            # Common port indicators
            features['is_http_port'] = (df['Destination Port'].isin([80, 8080])).astype(int)
            features['is_https_port'] = (df['Destination Port'] == 443).astype(int)
            features['is_ssh_port'] = (df['Destination Port'] == 22).astype(int)
            features['is_ftp_port'] = (df['Destination Port'].isin([20, 21])).astype(int)
            features['is_smtp_port'] = (df['Destination Port'] == 25).astype(int)
            features['is_dns_port'] = (df['Destination Port'] == 53).astype(int)
        
        logger.info(f"Extracted {len(features.columns)} protocol features")
        return features
    
    def extract_window_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract window size features
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with window features
        """
        logger.info("Extracting window features...")
        
        features = pd.DataFrame(index=df.index)
        
        if 'Init_Win_bytes_forward' in df.columns:
            features['init_win_bytes_forward'] = df['Init_Win_bytes_forward']
        
        if 'Init_Win_bytes_backward' in df.columns:
            features['init_win_bytes_backward'] = df['Init_Win_bytes_backward']
        
        if 'act_data_pkt_fwd' in df.columns:
            features['act_data_pkt_fwd'] = df['act_data_pkt_fwd']
        
        if 'min_seg_size_forward' in df.columns:
            features['min_seg_size_forward'] = df['min_seg_size_forward']
        
        logger.info(f"Extracted {len(features.columns)} window features")
        return features
    
    def extract_all_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract all available features from the dataset
        
        Args:
            df: Input DataFrame
            
        Returns:
            DataFrame with all extracted features
        """
        logger.info("Starting comprehensive feature extraction...")
        
        # Extract different feature groups
        basic_features = self.extract_basic_flow_features(df)
        statistical_features = self.extract_statistical_features(df)
        flag_features = self.extract_flag_features(df)
        header_features = self.extract_header_features(df)
        protocol_features = self.extract_protocol_features(df)
        window_features = self.extract_window_features(df)
        
        # Combine all features
        all_features = pd.concat([
            basic_features,
            statistical_features,
            flag_features,
            header_features,
            protocol_features,
            window_features
        ], axis=1)
        
        # Remove duplicate columns
        all_features = all_features.loc[:, ~all_features.columns.duplicated()]
        
        logger.info(f"Total features extracted: {len(all_features.columns)}")
        logger.info(f"Final feature shape: {all_features.shape}")
        
        return all_features
    
    def select_important_features(self, 
                                  X: pd.DataFrame, 
                                  y: pd.Series,
                                  n_features: int = 50) -> List[str]:
        """
        Select most important features using feature importance
        
        Args:
            X: Feature DataFrame
            y: Target labels
            n_features: Number of features to select
            
        Returns:
            List of selected feature names
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.feature_selection import SelectKBest, f_classif
        
        logger.info(f"Selecting top {n_features} features...")
        
        # Method 1: Random Forest feature importance
        rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
        rf.fit(X, y)
        
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': rf.feature_importances_
        }).sort_values('importance', ascending=False)
        
        top_features_rf = feature_importance.head(n_features)['feature'].tolist()
        
        logger.info(f"Selected {len(top_features_rf)} features using Random Forest")
        logger.info(f"Top 10 features: {top_features_rf[:10]}")
        
        return top_features_rf
    
    def create_feature_summary(self, features_df: pd.DataFrame) -> Dict:
        """
        Create a summary of extracted features
        
        Args:
            features_df: DataFrame with extracted features
            
        Returns:
            Dictionary with feature summary
        """
        summary = {
            'total_features': len(features_df.columns),
            'feature_names': features_df.columns.tolist(),
            'numeric_features': len(features_df.select_dtypes(include=[np.number]).columns),
            'categorical_features': len(features_df.select_dtypes(include=['object']).columns),
            'missing_values': features_df.isnull().sum().sum(),
            'memory_usage_mb': features_df.memory_usage(deep=True).sum() / (1024**2)
        }
        
        return summary


if __name__ == "__main__":
    # Example usage
    extractor = NetworkFeatureExtractor()
    print("Feature extraction module loaded successfully!")