"""
Model Prediction Utilities for IDS Dashboard
This is a PLACEHOLDER that your friend will replace with the real ML model
"""

import numpy as np
import pandas as pd
import pickle
import os

class IDSPredictor:
    """
    Wrapper class for the IDS machine learning model
    Your friend will implement the actual model loading and prediction
    """
    
    def __init__(self, model_path='models/trained_model.pkl'):
        """
        Initialize the predictor
        
        Args:
            model_path: Path to the trained model file (.pkl or .h5)
        """
        self.model_path = model_path
        self.model = None
        self.is_loaded = False
        self.attack_types = ['BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot', 
                             'FTP-Patator', 'SSH-Patator', 'Web Attack']
        
        # Try to load model if it exists
        if os.path.exists(model_path):
            self.load_model()
        else:
            print("⚠️ Model not found. Using mock predictions for testing.")
    
    
    def load_model(self):
        """
        Load the trained ML model from disk
        
        TODO: Your friend will implement this properly
        For now, it's just a placeholder
        """
        try:
            # TODO: Replace with actual model loading
            # Example for scikit-learn:
            # with open(self.model_path, 'rb') as f:
            #     self.model = pickle.load(f)
            
            # Example for TensorFlow/Keras:
            # from tensorflow import keras
            # self.model = keras.models.load_model(self.model_path)
            
            print(f"✅ Model loaded from {self.model_path}")
            self.is_loaded = True
            
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self.is_loaded = False
    
    
    def predict_single(self, flow_features):
        """
        Predict attack type for a single network flow
        
        Args:
            flow_features: Dictionary or Series with network flow features
            
        Returns:
            Dictionary with prediction results
        """
        if self.is_loaded and self.model is not None:
            # TODO: Your friend will implement actual prediction
            # Example:
            # features_array = self.preprocess_features(flow_features)
            # prediction = self.model.predict(features_array)
            # confidence = self.model.predict_proba(features_array)
            pass
        
        # Mock prediction for testing
        return self._mock_predict()
    
    
    def predict_batch(self, df):
        """
        Predict attack types for multiple flows at once
        
        Args:
            df: DataFrame with network flow features
            
        Returns:
            DataFrame with added 'Prediction' and 'Confidence' columns
        """
        if self.is_loaded and self.model is not None:
            # TODO: Your friend will implement batch prediction
            # Example:
            # features = self.preprocess_features(df)
            # predictions = self.model.predict(features)
            # confidences = self.model.predict_proba(features).max(axis=1)
            # df['Prediction'] = predictions
            # df['Confidence'] = confidences
            pass
        
        # Mock predictions for testing
        df['Prediction'] = [self._mock_predict()['prediction'] for _ in range(len(df))]
        df['Confidence'] = [self._mock_predict()['confidence'] for _ in range(len(df))]
        
        return df
    
    
    def _mock_predict(self):
        """
        Generate mock predictions for testing
        This will be removed when the real model is ready
        
        Returns:
            Dictionary with mock prediction
        """
        # 70% benign, 30% attacks
        is_attack = np.random.random() > 0.7
        
        if is_attack:
            attack_type = np.random.choice(['DoS', 'DDoS', 'PortScan', 'Bot', 
                                           'FTP-Patator', 'SSH-Patator', 'Web Attack'])
            confidence = np.random.uniform(0.75, 0.99)
        else:
            attack_type = 'BENIGN'
            confidence = np.random.uniform(0.85, 0.99)
        
        return {
            'prediction': attack_type,
            'confidence': round(confidence, 2),
            'is_attack': is_attack,
            'severity': self._get_severity(attack_type)
        }
    
    
    def _get_severity(self, attack_type):
        """
        Map attack type to severity level
        
        Args:
            attack_type: String attack type
            
        Returns:
            Severity level (Critical/High/Medium/Low)
        """
        severity_map = {
            'BENIGN': 'Low',
            'PortScan': 'Medium',
            'Bot': 'High',
            'FTP-Patator': 'Medium',
            'SSH-Patator': 'Medium',
            'Web Attack': 'High',
            'DoS': 'Critical',
            'DDoS': 'Critical'
        }
        return severity_map.get(attack_type, 'Medium')
    
    
    def get_feature_importance(self):
        """
        Get feature importance from the model
        Useful for the Model Performance page
        
        Returns:
            Dictionary with feature names and importance scores
        """
        if self.is_loaded and self.model is not None:
            # TODO: Your friend will implement this
            # For Random Forest:
            # return dict(zip(feature_names, self.model.feature_importances_))
            pass
        
        # Mock feature importance
        features = [
            'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
            'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
            'Fwd PSH Flags', 'Bwd PSH Flags', 'SYN Flag Count',
            'ACK Flag Count', 'Average Packet Size', 'Protocol'
        ]
        importance = np.random.random(len(features))
        importance = importance / importance.sum()  # Normalize
        
        return dict(zip(features, sorted(importance, reverse=True)))
    
    
    def get_model_metrics(self):
        """
        Get model performance metrics
        These should come from your friend's evaluation phase
        
        Returns:
            Dictionary with accuracy, precision, recall, f1-score
        """
        # TODO: Your friend will provide real metrics from their evaluation
        # These should be loaded from a saved JSON file or similar
        
        # Mock metrics for testing
        return {
            'accuracy': 0.9834,
            'precision': 0.9756,
            'recall': 0.9821,
            'f1_score': 0.9788,
            'confusion_matrix': self._generate_mock_confusion_matrix(),
            'per_class_metrics': {
                'BENIGN': {'precision': 0.99, 'recall': 0.98, 'f1': 0.985},
                'DoS': {'precision': 0.97, 'recall': 0.99, 'f1': 0.98},
                'DDoS': {'precision': 0.98, 'recall': 0.97, 'f1': 0.975},
                'PortScan': {'precision': 0.95, 'recall': 0.96, 'f1': 0.955},
                'Bot': {'precision': 0.94, 'recall': 0.98, 'f1': 0.96},
            }
        }
    
    
    def _generate_mock_confusion_matrix(self):
        """
        Generate a mock confusion matrix for visualization
        Real data will come from your friend's model evaluation
        """
        classes = ['BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot']
        n = len(classes)
        
        # Create a diagonal-heavy matrix (good predictions)
        cm = np.zeros((n, n), dtype=int)
        for i in range(n):
            cm[i, i] = np.random.randint(800, 1000)  # True predictions
            for j in range(n):
                if i != j:
                    cm[i, j] = np.random.randint(0, 50)  # False predictions
        
        return cm.tolist()
    
    
    def preprocess_features(self, features):
        """
        Preprocess features before prediction
        Your friend will implement the same preprocessing used during training
        
        Args:
            features: Raw features (DataFrame or dict)
            
        Returns:
            Preprocessed features ready for model
        """
        # TODO: Your friend implements this
        # Examples:
        # - Normalization/Standardization
        # - Feature selection
        # - Encoding categorical variables
        # - Handling missing values
        
        return features


# Singleton instance for easy access throughout the app
predictor = IDSPredictor()


def predict_flow(flow_data):
    """
    Convenience function to predict a single flow
    
    Args:
        flow_data: Dictionary or Series with flow features
        
    Returns:
        Prediction dictionary
    """
    return predictor.predict_single(flow_data)


def predict_dataframe(df):
    """
    Convenience function to predict multiple flows
    
    Args:
        df: DataFrame with flow features
        
    Returns:
        DataFrame with predictions added
    """
    return predictor.predict_batch(df)


# Test function
if __name__ == "__main__":
    print("Testing model_predictor.py...")
    
    # Test single prediction
    result = predictor.predict_single({})
    print(f"\n✅ Single prediction: {result}")
    
    # Test batch prediction
    import pandas as pd
    df = pd.DataFrame({'flow_id': range(10)})
    df_pred = predictor.predict_batch(df)
    print(f"\n✅ Batch predictions:\n{df_pred[['Prediction', 'Confidence']].head()}")
    
    # Test metrics
    metrics = predictor.get_model_metrics()
    print(f"\n✅ Model accuracy: {metrics['accuracy']}")
    
    # Test feature importance
    importance = predictor.get_feature_importance()
    print(f"\n✅ Top 3 features: {list(importance.items())[:3]}")
    
    print("\n✅ All tests passed!")