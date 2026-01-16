"""
Model Performance Page - ML Model Evaluation
Display model metrics, confusion matrix, and feature importance
"""

import streamlit as st
import pandas as pd
import numpy as np
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent))

from components.charts import (
    plot_confusion_matrix, plot_roc_curve, plot_feature_importance
)
from components.metrics import (
    calculate_accuracy, calculate_precision_recall_f1,
    calculate_false_positive_rate
)
from utils.model_predictor import predictor

# Page config
st.set_page_config(page_title="Model Performance", page_icon="🎯", layout="wide")

# Header
st.title("🎯 Model Performance Evaluation")
st.markdown("Machine Learning model metrics and evaluation results")

# Model status indicator
col1, col2, col3 = st.columns([2, 1, 1])

with col1:
    st.subheader("Model Information")

with col2:
    if predictor.is_loaded:
        st.success("✅ Model Loaded")
    else:
        st.warning("⚠️ Using Mock Model")

with col3:
    st.info("Version 1.0")

st.markdown("---")

# Get model metrics
metrics = predictor.get_model_metrics()

# Tabs for different evaluation aspects
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Overall Metrics",
    "🎯 Confusion Matrix",
    "📈 Performance Curves",
    "🔍 Feature Importance"
])

# TAB 1: OVERALL METRICS
with tab1:
    st.subheader("📊 Model Performance Metrics")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        accuracy = metrics.get('accuracy', 0) * 100
        st.metric(
            "Accuracy",
            f"{accuracy:.2f}%",
            delta="High" if accuracy > 95 else "Medium"
        )
    
    with col2:
        precision = metrics.get('precision', 0) * 100
        st.metric(
            "Precision",
            f"{precision:.2f}%",
            delta="Good" if precision > 95 else "Fair"
        )
    
    with col3:
        recall = metrics.get('recall', 0) * 100
        st.metric(
            "Recall",
            f"{recall:.2f}%",
            delta="High" if recall > 95 else "Medium"
        )
    
    with col4:
        f1 = metrics.get('f1_score', 0) * 100
        st.metric(
            "F1-Score",
            f"{f1:.2f}%",
            delta="Excellent" if f1 > 95 else "Good"
        )
    
    st.markdown("---")
    
    # Performance visualization
    st.subheader("Performance Score Visualization")
    
    # Create gauge charts
    col1, col2 = st.columns(2)
    
    with col1:
        import plotly.graph_objects as go
        
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=accuracy,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Overall Accuracy"},
            delta={'reference': 95},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#00FF41"},
                'steps': [
                    {'range': [0, 70], 'color': "#DC143C"},
                    {'range': [70, 85], 'color': "#FFD700"},
                    {'range': [85, 100], 'color': "#90EE90"}
                ],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': 95
                }
            }
        ))
        fig.update_layout(template='plotly_dark', height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=f1,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "F1-Score"},
            delta={'reference': 90},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "#00BFFF"},
                'steps': [
                    {'range': [0, 70], 'color': "#DC143C"},
                    {'range': [70, 85], 'color': "#FFD700"},
                    {'range': [85, 100], 'color': "#90EE90"}
                ],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(template='plotly_dark', height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # Per-class metrics
    st.subheader("📋 Per-Class Performance")
    
    if 'per_class_metrics' in metrics:
        per_class = metrics['per_class_metrics']
        
        # Convert to dataframe
        per_class_df = pd.DataFrame(per_class).T
        per_class_df.columns = ['Precision', 'Recall', 'F1-Score']
        per_class_df = (per_class_df * 100).round(2)
        
        # Style the dataframe
        def highlight_cells(val):
            if val >= 95:
                color = '#90EE90'
            elif val >= 85:
                color = '#FFD700'
            else:
                color = '#FF6B6B'
            return f'background-color: {color}; color: black'
        
        styled_df = per_class_df.style.applymap(highlight_cells)
        st.dataframe(styled_df, use_container_width=True)
        
        # Best and worst performing classes
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("**🏆 Best Performing Class:**")
            best_class = per_class_df['F1-Score'].idxmax()
            best_score = per_class_df['F1-Score'].max()
            st.success(f"{best_class}: {best_score:.2f}% F1-Score")
        
        with col2:
            st.markdown("**⚠️ Needs Improvement:**")
            worst_class = per_class_df['F1-Score'].idxmin()
            worst_score = per_class_df['F1-Score'].min()
            st.warning(f"{worst_class}: {worst_score:.2f}% F1-Score")
    
    # Model comparison (mock data for now)
    st.markdown("---")
    st.subheader("🔄 Model Comparison")
    
    comparison_data = {
        'Model': ['Random Forest', 'XGBoost', 'Neural Network', 'SVM', 'Current Model'],
        'Accuracy': [96.5, 97.2, 98.1, 94.3, accuracy],
        'Precision': [95.8, 96.9, 97.5, 93.8, precision],
        'Recall': [96.2, 97.0, 98.0, 94.1, recall],
        'F1-Score': [96.0, 96.9, 97.8, 94.0, f1],
        'Training Time (min)': [12, 18, 45, 8, 15]
    }
    
    comparison_df = pd.DataFrame(comparison_data)
    
    # Highlight current model
    def highlight_current(row):
        if row['Model'] == 'Current Model':
            return ['background-color: #00BFFF; color: black'] * len(row)
        return [''] * len(row)
    
    styled_comparison = comparison_df.style.apply(highlight_current, axis=1)
    st.dataframe(styled_comparison, use_container_width=True)

# TAB 2: CONFUSION MATRIX
with tab2:
    st.subheader("🎯 Confusion Matrix")
    
    st.markdown("""
    The confusion matrix shows how well the model classifies each attack type.
    Diagonal values represent correct predictions, while off-diagonal values show misclassifications.
    """)
    
    cm = metrics.get('confusion_matrix', [])
    class_names = ['BENIGN', 'DoS', 'DDoS', 'PortScan', 'Bot']
    
    if cm:
        cm_chart = plot_confusion_matrix(cm, class_names)
        st.plotly_chart(cm_chart, use_container_width=True)
        
        st.markdown("---")
        
        # Confusion matrix statistics
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Key Observations")
            
            cm_array = np.array(cm)
            
            # Calculate misclassification rate
            total_predictions = cm_array.sum()
            correct_predictions = np.trace(cm_array)
            misclassification_rate = ((total_predictions - correct_predictions) / total_predictions * 100)
            
            st.write(f"• Total Predictions: {total_predictions:,}")
            st.write(f"• Correct Predictions: {correct_predictions:,}")
            st.write(f"• Misclassification Rate: {misclassification_rate:.2f}%")
            
            # Most confused pairs
            st.markdown("### Most Confused Pairs")
            
            confused_pairs = []
            for i in range(len(cm_array)):
                for j in range(len(cm_array)):
                    if i != j and cm_array[i][j] > 0:
                        confused_pairs.append({
                            'True': class_names[i],
                            'Predicted': class_names[j],
                            'Count': int(cm_array[i][j])
                        })
            
            if confused_pairs:
                confused_df = pd.DataFrame(confused_pairs).sort_values('Count', ascending=False).head(5)
                st.dataframe(confused_df, use_container_width=True)
        
        with col2:
            st.markdown("### Class-wise Accuracy")
            
            class_accuracies = []
            for i, class_name in enumerate(class_names):
                correct = cm_array[i][i]
                total = cm_array[i].sum()
                accuracy = (correct / total * 100) if total > 0 else 0
                class_accuracies.append({
                    'Class': class_name,
                    'Accuracy': f"{accuracy:.2f}%",
                    'Samples': int(total)
                })
            
            acc_df = pd.DataFrame(class_accuracies)
            st.dataframe(acc_df, use_container_width=True)
    else:
        st.info("Confusion matrix not available. Train your model first.")

# TAB 3: PERFORMANCE CURVES
with tab3:
    st.subheader("📈 ROC Curve & Performance Metrics")
    
    # Generate mock ROC curve data (your friend will provide real data)
    fpr = np.linspace(0, 1, 100)
    tpr = 1 - (1 - fpr) ** 2  # Mock curve
    auc_score = 0.985
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        roc_chart = plot_roc_curve(fpr, tpr, auc_score)
        st.plotly_chart(roc_chart, use_container_width=True)
    
    with col2:
        st.markdown("### ROC Analysis")
        st.metric("AUC Score", f"{auc_score:.3f}")
        
        st.markdown("---")
        
        st.markdown("**Interpretation:**")
        if auc_score > 0.95:
            st.success("✅ Excellent discrimination ability")
        elif auc_score > 0.85:
            st.info("✅ Good discrimination ability")
        else:
            st.warning("⚠️ Fair discrimination ability")
        
        st.markdown("---")
        
        st.markdown("**ROC Curve Guide:**")
        st.write("• AUC = 1.0: Perfect classifier")
        st.write("• AUC = 0.5: Random classifier")
        st.write("• Higher AUC = Better performance")
    
    st.markdown("---")
    
    # Precision-Recall curve
    st.subheader("Precision-Recall Trade-off")
    
    # Mock P-R curve
    recall_values = np.linspace(0, 1, 100)
    precision_values = 1 - 0.5 * recall_values + 0.3 * np.random.random(100)
    precision_values = np.clip(precision_values, 0, 1)
    
    import plotly.graph_objects as go
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=recall_values,
        y=precision_values,
        mode='lines',
        name='Precision-Recall',
        line=dict(color='#00FF41', width=3)
    ))
    
    fig.update_layout(
        title='Precision-Recall Curve',
        xaxis_title='Recall',
        yaxis_title='Precision',
        template='plotly_dark',
        xaxis=dict(range=[0, 1]),
        yaxis=dict(range=[0, 1])
    )
    
    st.plotly_chart(fig, use_container_width=True)

# TAB 4: FEATURE IMPORTANCE
with tab4:
    st.subheader("🔍 Feature Importance Analysis")
    
    st.markdown("""
    Feature importance shows which network traffic features contribute most to the model's predictions.
    Higher importance means the feature has more influence on detecting attacks.
    """)
    
    feature_importance = predictor.get_feature_importance()
    
    if feature_importance:
        # Plot feature importance
        importance_chart = plot_feature_importance(feature_importance, top_n=15)
        st.plotly_chart(importance_chart, use_container_width=True)
        
        st.markdown("---")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Top 10 Features")
            
            top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:10]
            
            for i, (feature, importance) in enumerate(top_features, 1):
                st.write(f"{i}. **{feature}**: {importance:.4f}")
        
        with col2:
            st.markdown("### Feature Categories")
            
            # Categorize features
            flow_features = [f for f in feature_importance.keys() if 'Flow' in f or 'Duration' in f]
            packet_features = [f for f in feature_importance.keys() if 'Packet' in f]
            flag_features = [f for f in feature_importance.keys() if 'Flag' in f]
            
            st.write(f"• Flow Features: {len(flow_features)}")
            st.write(f"• Packet Features: {len(packet_features)}")
            st.write(f"• Flag Features: {len(flag_features)}")
            st.write(f"• Other Features: {len(feature_importance) - len(flow_features) - len(packet_features) - len(flag_features)}")
        
        st.markdown("---")
        
        # Feature importance table
        st.markdown("### Complete Feature Rankings")
        
        importance_df = pd.DataFrame(
            [(k, v) for k, v in sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)],
            columns=['Feature', 'Importance']
        )
        importance_df['Rank'] = range(1, len(importance_df) + 1)
        importance_df = importance_df[['Rank', 'Feature', 'Importance']]
        
        st.dataframe(importance_df, use_container_width=True, height=400)
    else:
        st.info("Feature importance not available. Train your model first.")

# Footer with recommendations
st.markdown("---")
st.subheader("💡 Model Improvement Recommendations")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**Data Quality**")
    st.write("• Ensure balanced dataset")
    st.write("• Remove outliers carefully")
    st.write("• Add more training samples")

with col2:
    st.markdown("**Model Tuning**")
    st.write("• Optimize hyperparameters")
    st.write("• Try ensemble methods")
    st.write("• Cross-validation")

with col3:
    st.markdown("**Feature Engineering**")
    st.write("• Create new features")
    st.write("• Feature selection")
    st.write("• Dimensionality reduction")