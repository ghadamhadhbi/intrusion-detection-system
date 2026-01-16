"""
Data Processing Module for IDS
Handles loading, cleaning, and preprocessing of network traffic data
"""

import pandas as pd
import numpy as np
import yaml
import os
import logging
from pathlib import Path
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import SMOTE, ADASYN, RandomOverSampler
from imblearn.under_sampling import RandomUnderSampler
import joblib
from typing import Tuple, List, Dict, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DataProcessor:
    """
    Main class for processing IDS datasets
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        """
        Initialize DataProcessor with configuration
        
        Args:
            config_path: Path to configuration YAML file
        """
        self.config = self._load_config(config_path)
        self.scaler = None
        self.label_encoder = LabelEncoder()
        
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(config_path, "r", encoding="utf-8") as f:

                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {config_path}")
            return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            raise
    
    def load_dataset(self, file_path: Optional[str] = None, 
                     sample_frac: float = 1.0) -> pd.DataFrame:
        """
        Load dataset from CSV file
        
        Args:
            file_path: Path to CSV file (if None, loads all files from config)
            sample_frac: Fraction of data to sample (for testing)
        
        Returns:
            DataFrame with loaded data
        """
        import glob

        logger.info("Loading dataset...")
        
        if file_path:
            # Load single file
            df = pd.read_csv(file_path, encoding='utf-8', low_memory=False)
            logger.info(f"Loaded {len(df)} records from {file_path}")
        else:
            # Load all files from config
            raw_path = self.config['paths']['data_raw']
            files = glob.glob(os.path.join(raw_path, "**", "*.csv"), recursive=True)
            print("Files found by glob:", files) 

            
            dfs = []
            for file_full_path in files:
                if os.path.exists(file_full_path):
                    df_temp = pd.read_csv(file_full_path, encoding='utf-8', low_memory=False)
                    dfs.append(df_temp)
                    logger.info(f"Loaded {len(df_temp)} records from {os.path.basename(file_full_path)}")
                else:
                    logger.warning(f"File not found: {file_full_path}")
            if not dfs:
                raise ValueError(f"No CSV files were loaded from {raw_path}!")
            df = pd.concat(dfs, ignore_index=True)
            logger.info(f"Total records loaded: {len(df)}")
        
        # Sample data if needed (for testing)
        if sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=42)
            logger.info(f"Sampled {len(df)} records ({sample_frac*100}%)")
        
        return df
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Clean the dataset by handling missing values, duplicates, and infinite values
        
        Args:
            df: Input DataFrame
        
        Returns:
            Cleaned DataFrame
        """
        logger.info("Cleaning data...")
        initial_rows = len(df)
        
        # Display initial info
        logger.info(f"Initial shape: {df.shape}")
        logger.info(f"Missing values: {df.isnull().sum().sum()}")
        logger.info(f"Duplicate rows: {df.duplicated().sum()}")
        
        # Remove duplicates
        if self.config['preprocessing']['remove_duplicates']:
            df = df.drop_duplicates()
            logger.info(f"Removed {initial_rows - len(df)} duplicate rows")
        
        # Handle missing values
        missing_strategy = self.config['preprocessing']['missing_strategy']
        if missing_strategy == 'drop':
            df = df.dropna()
            logger.info(f"Dropped rows with missing values. Remaining: {len(df)}")
        elif missing_strategy == 'mean':
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].mean())
        elif missing_strategy == 'median':
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
        
        # Handle infinite values
        if self.config['preprocessing']['handle_infinity']:
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
            df = df.dropna()
            logger.info(f"Handled infinite values. Remaining: {len(df)}")
        
        # Clean column names (remove spaces)
        df.columns = df.columns.str.strip()
        
        logger.info(f"Final shape after cleaning: {df.shape}")
        
        return df
    
    def prepare_features(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
        """
        Prepare features by dropping non-predictive columns and separating labels
        
        Args:
            df: Input DataFrame
        
        Returns:
            Tuple of (features DataFrame, labels Series)
        """
        logger.info("Preparing features...")
        
        # Get label column
        label_col = self.config['dataset']['label_column']
        
        if label_col not in df.columns:
            raise ValueError(f"Label column '{label_col}' not found in dataset")
        
        # Separate features and labels
        y = df[label_col].copy()
        X = df.drop(columns=[label_col])
        
        # Drop non-predictive features
        drop_features = self.config['features']['drop_features']
        existing_drop_features = [col for col in drop_features if col in X.columns]
        X = X.drop(columns=existing_drop_features, errors='ignore')
        logger.info(f"Dropped {len(existing_drop_features)} non-predictive features")
        
        # Keep only numeric features
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X = X[numeric_cols]
        logger.info(f"Selected {len(numeric_cols)} numeric features")
        
        # Display label distribution
        logger.info(f"\nLabel distribution:\n{y.value_counts()}")
        
        return X, y
    
    def encode_labels(self, y: pd.Series, binary: bool = False) -> np.ndarray:
        """
        Encode labels (multi-class or binary)
        
        Args:
            y: Label Series
            binary: If True, convert to binary (BENIGN vs ATTACK)
        
        Returns:
            Encoded labels
        """
        logger.info("Encoding labels...")
        
        if binary:
            # Binary classification: BENIGN (0) vs ATTACK (1)
            y_encoded = (y != 'BENIGN').astype(int)
            logger.info("Binary encoding: BENIGN=0, ATTACK=1")
        else:
            # Multi-class classification
            y_encoded = self.label_encoder.fit_transform(y)
            logger.info(f"Multi-class encoding: {len(self.label_encoder.classes_)} classes")
            logger.info(f"Classes: {self.label_encoder.classes_}")
        
        return y_encoded
    
    def normalize_features(self, X_train: pd.DataFrame, 
                          X_test: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Normalize features using specified method
        
        Args:
            X_train: Training features
            X_test: Test features
        
        Returns:
            Tuple of normalized (X_train, X_test)
        """
        logger.info("Normalizing features...")
        
        method = self.config['preprocessing']['normalization']
        
        if method == 'standard':
            self.scaler = StandardScaler()
        elif method == 'minmax':
            self.scaler = MinMaxScaler()
        elif method == 'robust':
            self.scaler = RobustScaler()
        else:
            logger.warning(f"Unknown normalization method: {method}. Using StandardScaler.")
            self.scaler = StandardScaler()
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        logger.info(f"Normalization completed using {method} scaling")
        
        return X_train_scaled, X_test_scaled
    
    def split_data(self, X: pd.DataFrame, y: np.ndarray) -> Tuple:
        """
        Split data into train, validation, and test sets
        
        Args:
            X: Features
            y: Labels
        
        Returns:
            Tuple of (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        logger.info("Splitting data...")
        
        test_size = self.config['preprocessing']['test_size']
        val_size = self.config['preprocessing']['validation_size']
        random_state = self.config['preprocessing']['random_state']
        
        # First split: train+val and test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Second split: train and validation
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=random_state, stratify=y_temp
        )
        
        logger.info(f"Train set: {len(X_train)} samples")
        logger.info(f"Validation set: {len(X_val)} samples")
        logger.info(f"Test set: {len(X_test)} samples")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def handle_imbalance(self, X_train: np.ndarray, 
                        y_train: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Handle class imbalance using sampling techniques
        
        Args:
            X_train: Training features
            y_train: Training labels
        
        Returns:
            Tuple of resampled (X_train, y_train)
        """
        if not self.config['preprocessing']['sampling']['enabled']:
            return X_train, y_train
        
        logger.info("Handling class imbalance...")
        logger.info(f"Original distribution: {np.bincount(y_train)}")
        
        method = self.config['preprocessing']['sampling']['method']
        strategy = self.config['preprocessing']['sampling']['strategy']
        
        if method == 'SMOTE':
            sampler = SMOTE(sampling_strategy=strategy, random_state=42)
        elif method == 'ADASYN':
            sampler = ADASYN(sampling_strategy=strategy, random_state=42)
        elif method == 'RandomOverSampler':
            sampler = RandomOverSampler(sampling_strategy=strategy, random_state=42)
        elif method == 'RandomUnderSampler':
            sampler = RandomUnderSampler(sampling_strategy=strategy, random_state=42)
        else:
            logger.warning(f"Unknown sampling method: {method}. Skipping.")
            return X_train, y_train
        
        X_resampled, y_resampled = sampler.fit_resample(X_train, y_train)
        logger.info(f"Resampled distribution: {np.bincount(y_resampled)}")
        logger.info(f"New training size: {len(X_resampled)}")
        
        return X_resampled, y_resampled
    
    def save_processed_data(self, X_train, X_val, X_test, 
                           y_train, y_val, y_test, 
                           feature_names: List[str]):
        """
        Save processed data and scaler
        
        Args:
            X_train, X_val, X_test: Feature sets
            y_train, y_val, y_test: Label sets
            feature_names: List of feature names
        """
        logger.info("Saving processed data...")
        
        processed_path = self.config['paths']['data_processed']
        os.makedirs(processed_path, exist_ok=True)
        
        # Save data
        np.save(os.path.join(processed_path, 'X_train.npy'), X_train)
        np.save(os.path.join(processed_path, 'X_val.npy'), X_val)
        np.save(os.path.join(processed_path, 'X_test.npy'), X_test)
        np.save(os.path.join(processed_path, 'y_train.npy'), y_train)
        np.save(os.path.join(processed_path, 'y_val.npy'), y_val)
        np.save(os.path.join(processed_path, 'y_test.npy'), y_test)
        
        # Save scaler
        joblib.dump(self.scaler, os.path.join(processed_path, 'scaler.pkl'))
        
        # Save label encoder
        joblib.dump(self.label_encoder, os.path.join(processed_path, 'label_encoder.pkl'))
        
        # Save feature names
        joblib.dump(feature_names, os.path.join(processed_path, 'feature_names.pkl'))
        
        logger.info(f"Data saved to {processed_path}")
    
    def load_processed_data(self) -> Tuple:
        """
        Load previously processed data
        
        Returns:
            Tuple of (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        logger.info("Loading processed data...")
        
        processed_path = self.config['paths']['data_processed']
        
        X_train = np.load(os.path.join(processed_path, 'X_train.npy'))
        X_val = np.load(os.path.join(processed_path, 'X_val.npy'))
        X_test = np.load(os.path.join(processed_path, 'X_test.npy'))
        y_train = np.load(os.path.join(processed_path, 'y_train.npy'))
        y_val = np.load(os.path.join(processed_path, 'y_val.npy'))
        y_test = np.load(os.path.join(processed_path, 'y_test.npy'))
        
        self.scaler = joblib.load(os.path.join(processed_path, 'scaler.pkl'))
        self.label_encoder = joblib.load(os.path.join(processed_path, 'label_encoder.pkl'))
        
        logger.info("Data loaded successfully")
        
        return X_train, X_val, X_test, y_train, y_val, y_test
    
    def process_pipeline(self, file_path: Optional[str] = None, 
                        binary_classification: bool = False,
                        sample_frac: float = 1.0) -> Tuple:
        """
        Complete data processing pipeline
        
        Args:
            file_path: Path to CSV file (optional)
            binary_classification: Binary vs multi-class
            sample_frac: Fraction of data to use
        
        Returns:
            Tuple of processed data (X_train, X_val, X_test, y_train, y_val, y_test)
        """
        logger.info("="*60)
        logger.info("STARTING DATA PROCESSING PIPELINE")
        logger.info("="*60)
        
        # 1. Load dataset
        df = self.load_dataset(file_path, sample_frac)
        
        # 2. Clean data
        df = self.clean_data(df)
        
        # 3. Prepare features
        X, y = self.prepare_features(df)
        feature_names = X.columns.tolist()
        
        # 4. Encode labels
        y_encoded = self.encode_labels(y, binary=binary_classification)
        
        # 5. Split data
        X_train, X_val, X_test, y_train, y_val, y_test = self.split_data(X, y_encoded)
        
        # 6. Normalize features
        X_train_scaled, X_val_scaled = self.normalize_features(
            X_train, X_val
        )
        _, X_test_scaled = self.normalize_features(
            X_train, X_test  # Use train scaler for test
        )
        
        # 7. Handle class imbalance (only on training data)
        X_train_resampled, y_train_resampled = self.handle_imbalance(
            X_train_scaled, y_train
        )
        
        # 8. Save processed data
        self.save_processed_data(
            X_train_resampled, X_val_scaled, X_test_scaled,
            y_train_resampled, y_val, y_test,
            feature_names
        )
        
        logger.info("="*60)
        logger.info("DATA PROCESSING PIPELINE COMPLETED")
        logger.info("="*60)
        
        return X_train_resampled, X_val_scaled, X_test_scaled, y_train_resampled, y_val, y_test


if __name__ == "__main__":
    # Example usage
    processor = DataProcessor()
    
    # Process data (use sample_frac=0.1 for testing with 10% of data)
    X_train, X_val, X_test, y_train, y_val, y_test = processor.process_pipeline(
        binary_classification=False,  # Set to True for binary classification
        sample_frac=0.1  # Use 10% of data for testing
    )
    
    print(f"\nFinal shapes:")
    print(f"X_train: {X_train.shape}")
    print(f"X_val: {X_val.shape}")
    print(f"X_test: {X_test.shape}")
    print(f"y_train: {y_train.shape}")
    print(f"y_val: {y_val.shape}")
    print(f"y_test: {y_test.shape}")