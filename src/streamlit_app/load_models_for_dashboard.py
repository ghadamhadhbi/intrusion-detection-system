"""
Load Models for Streamlit Dashboard
This script prepares trained models and metrics for the dashboard
"""

import os
import numpy as np
import joblib
from pathlib import Path
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

def load_and_prepare_models():
    """
    Load trained models and generate metrics for dashboard
    """
    print("="*70)
    print("PREPARING MODELS FOR STREAMLIT DASHBOARD")
    print("="*70)
    
    # Paths
    models_path = Path("C:/Users/ghada/intrusion-detection-system/data/models")
    processed_path = Path("C:/Users/ghada/intrusion-detection-system/data/processed")
    
    # Check if directories exist
    if not models_path.exists():
        print(f"❌ Models directory not found: {models_path}")
        print("Please run model training first")
        return False
    
    if not processed_path.exists():
        print(f"❌ Processed data directory not found: {processed_path}")
        print("Please run data processing first")
        return False
    
    print(f"\n✅ Models directory: {models_path}")
    print(f"✅ Processed data directory: {processed_path}")
    
    # Load test data
    try:
        X_test = np.load(processed_path / 'X_test.npy')
        y_test = np.load(processed_path / 'y_test.npy')
        print(f"\n✅ Test data loaded: {X_test.shape}")
    except Exception as e:
        print(f"❌ Error loading test data: {e}")
        return False
    
    # Load label encoder
    try:
        label_encoder = joblib.load(processed_path / 'label_encoder.pkl')
        class_names = label_encoder.classes_
        print(f"✅ Label encoder loaded: {len(class_names)} classes")
        print(f"   Classes: {list(class_names)}")
    except Exception as e:
        print(f"⚠️ Warning: Could not load label encoder: {e}")
        label_encoder = None
        class_names = None
    
    # Find all model files
    model_files = list(models_path.glob("*.pkl"))
    
    if not model_files:
        print(f"\n❌ No model files found in {models_path}")
        print("Please train models first")
        return False
    
    print(f"\n📦 Found {len(model_files)} model file(s):")
    for f in model_files:
        print(f"   - {f.name}")
    
    # Evaluate each model
    all_metrics = {}
    
    for model_file in model_files:
        model_name = model_file.stem.replace('_model', '')
        
        # Skip non-model files
        if model_name in ['scaler', 'label_encoder', 'feature_names', 'model_metrics']:
            continue
        
        print(f"\n{'='*70}")
        print(f"Evaluating: {model_name}")
        print('='*70)
        
        try:
            # Load model
            model = joblib.load(model_file)
            print(f"✅ Model loaded: {type(model).__name__}")
            
            # Make predictions
            y_pred = model.predict(X_test)
            print(f"✅ Predictions generated")
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
            recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
            f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
            
            print(f"\n📊 Performance Metrics:")
            print(f"   Accuracy:  {accuracy*100:.2f}%")
            print(f"   Precision: {precision*100:.2f}%")
            print(f"   Recall:    {recall*100:.2f}%")
            print(f"   F1-Score:  {f1*100:.2f}%")
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            # Per-class metrics
            if class_names is not None:
                report = classification_report(
                    y_test, y_pred,
                    target_names=class_names,
                    output_dict=True,
                    zero_division=0
                )
                per_class = {k: v for k, v in report.items() 
                           if k not in ['accuracy', 'macro avg', 'weighted avg']}
            else:
                per_class = {}
            
            # Store metrics
            all_metrics[model_name] = {
                'accuracy': float(accuracy),
                'precision': float(precision),
                'recall': float(recall),
                'f1_score': float(f1),
                'confusion_matrix': cm.tolist(),
                'class_names': list(class_names) if class_names is not None else None,
                'per_class_metrics': per_class
            }
            
            print(f"✅ Metrics calculated and stored")
            
        except Exception as e:
            print(f"❌ Error evaluating {model_name}: {e}")
            continue
    
    # Save all metrics
    if all_metrics:
        metrics_file = models_path / 'model_metrics.pkl'
        try:
            joblib.dump(all_metrics, metrics_file)
            print(f"\n{'='*70}")
            print(f"✅ All metrics saved to: {metrics_file}")
            print(f"✅ Total models evaluated: {len(all_metrics)}")
            print('='*70)
            
            # Print summary
            print("\n📊 EVALUATION SUMMARY:")
            print("-" * 70)
            print(f"{'Model':<20} {'Accuracy':<12} {'Precision':<12} {'Recall':<12} {'F1-Score':<12}")
            print("-" * 70)
            
            for model_name, metrics in all_metrics.items():
                print(f"{model_name:<20} "
                      f"{metrics['accuracy']*100:>10.2f}%  "
                      f"{metrics['precision']*100:>10.2f}%  "
                      f"{metrics['recall']*100:>10.2f}%  "
                      f"{metrics['f1_score']*100:>10.2f}%")
            
            print("-" * 70)
            
            # Find best model
            best_model = max(all_metrics.items(), key=lambda x: x[1]['f1_score'])
            print(f"\n🏆 BEST MODEL: {best_model[0]}")
            print(f"   F1-Score: {best_model[1]['f1_score']*100:.2f}%")
            
            # Save best model reference
            all_metrics['best'] = best_model[1].copy()
            joblib.dump(all_metrics, metrics_file)
            
            print(f"\n✅ Dashboard preparation complete!")
            print(f"✅ You can now run: streamlit run src/streamlit_app/app.py")
            
            return True
            
        except Exception as e:
            print(f"❌ Error saving metrics: {e}")
            return False
    else:
        print("\n❌ No models were successfully evaluated")
        return False


if __name__ == "__main__":
    success = load_and_prepare_models()
    
    if success:
        print("\n" + "="*70)
        print("SUCCESS! Models are ready for the Streamlit dashboard")
        print("="*70)
    else:
        print("\n" + "="*70)
        print("FAILED! Please check the errors above")
        print("="*70)