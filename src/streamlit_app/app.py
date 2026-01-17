import streamlit as st
import pandas as pd
import numpy as np
import json
import pickle
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import os
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="IDS - Détection d'Intrusions",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 0rem 1rem;
    }
    .stAlert {
        margin-top: 1rem;
    }
    h1 {
        color: #1f77b4;
        padding-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    </style>
""", unsafe_allow_html=True)

# Title
st.title("🛡️ Système de Détection d'Intrusions Intelligente")
st.markdown("---")

# Sidebar
with st.sidebar:
    st.header("⚙️ Configuration")
    
    # Page selection
    page = st.radio(
        "Navigation",
        ["📊 Dashboard", "📈 Comparaison des Modèles"]
    )
    
    st.markdown("---")
    st.info("**Projet Cybersécurité** - Détection d'intrusions basée sur le Machine Learning")

# Load metrics
@st.cache_data
def load_metrics():
    metrics_path = "data/models/metrics.json"
    if os.path.exists(metrics_path):
        with open(metrics_path, 'r') as f:
            return json.load(f)
    return {}

# Load sample data
@st.cache_data
def load_sample_data():
    # Try to load processed data
    processed_path = "data/processed"
    if os.path.exists(processed_path):
        files = [f for f in os.listdir(processed_path) if f.endswith('.csv')]
        if files:
            return pd.read_csv(os.path.join(processed_path, files[0]))
    return None

# Page: Dashboard
if page == "📊 Dashboard":
    st.header("📊 Vue d'Ensemble du Système IDS")
    
    metrics = load_metrics()
    
    if metrics:
        # Display overall statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Modèles Entraînés", len(metrics))
        
        with col2:
            if metrics:
                best_accuracy = max([m.get('accuracy', 0) for m in metrics.values()])
                st.metric("Meilleure Précision", f"{best_accuracy*100:.2f}%")
        
        with col3:
            st.metric("Types d'Attaques", "6+")
        
        with col4:
            st.metric("Statut", "✅ Opérationnel", delta="Actif")
        
        st.markdown("---")
        
        # Performance summary
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🎯 Performance des Modèles")
            
            # Create performance comparison chart
            model_names = []
            accuracies = []
            f1_scores = []
            
            for model_name, model_metrics in metrics.items():
                model_names.append(model_name.replace('_best', '').upper())
                accuracies.append(model_metrics.get('accuracy', 0) * 100)
                f1_scores.append(model_metrics.get('f1_score', 0) * 100)
            
            fig = go.Figure()
            fig.add_trace(go.Bar(
                name='Accuracy',
                x=model_names,
                y=accuracies,
                marker_color='lightblue'
            ))
            fig.add_trace(go.Bar(
                name='F1-Score',
                x=model_names,
                y=f1_scores,
                marker_color='lightcoral'
            ))
            
            fig.update_layout(
                barmode='group',
                title="Comparaison des Métriques",
                xaxis_title="Modèles",
                yaxis_title="Score (%)",
                height=400
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📋 Détails des Modèles")
            
            for model_name, model_metrics in metrics.items():
                with st.expander(f"🤖 {model_name.replace('_best', '').upper()}"):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.metric("Accuracy", f"{model_metrics.get('accuracy', 0)*100:.2f}%")
                        st.metric("Precision", f"{model_metrics.get('precision', 0)*100:.2f}%")
                    with col_b:
                        st.metric("Recall", f"{model_metrics.get('recall', 0)*100:.2f}%")
                        st.metric("F1-Score", f"{model_metrics.get('f1_score', 0)*100:.2f}%")
    else:
        st.warning("⚠️ Aucune métrique trouvée. Assurez-vous que le fichier metrics.json existe.")

# Page: Model Comparison
elif page == "📈 Comparaison des Modèles":
    st.header("📈 Comparaison Détaillée des Modèles")
    
    metrics = load_metrics()
    
    if metrics:
        # Radar chart for model comparison
        st.subheader("🕸️ Comparaison Multi-critères")
        
        # Select models to compare
        model_list = list(metrics.keys())
        selected_models = st.multiselect(
            "Sélectionnez les modèles à comparer",
            model_list,
            default=model_list[:3] if len(model_list) >= 3 else model_list
        )
        
        if selected_models:
            fig = go.Figure()
            
            categories = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
            
            for model_name in selected_models:
                model_metrics = metrics[model_name]
                values = [
                    model_metrics.get('accuracy', 0) * 100,
                    model_metrics.get('precision', 0) * 100,
                    model_metrics.get('recall', 0) * 100,
                    model_metrics.get('f1_score', 0) * 100
                ]
                
                fig.add_trace(go.Scatterpolar(
                    r=values,
                    theta=categories,
                    fill='toself',
                    name=model_name.replace('_best', '').upper()
                ))
            
            fig.update_layout(
                polar=dict(
                    radialaxis=dict(
                        visible=True,
                        range=[0, 100]
                    )
                ),
                showlegend=True,
                height=500
            )
            
            st.plotly_chart(fig, use_container_width=True)
        
        # Detailed metrics table
        st.subheader("📊 Tableau Comparatif")
        
        metrics_df = pd.DataFrame([
            {
                'Modèle': name.replace('_best', '').upper(),
                'Accuracy (%)': f"{m.get('accuracy', 0)*100:.2f}",
                'Precision (%)': f"{m.get('precision', 0)*100:.2f}",
                'Recall (%)': f"{m.get('recall', 0)*100:.2f}",
                'F1-Score (%)': f"{m.get('f1_score', 0)*100:.2f}"
            }
            for name, m in metrics.items()
        ])
        
        st.dataframe(metrics_df, use_container_width=True)
    else:
        st.warning("⚠️ Aucune métrique disponible.")


# Footer
st.markdown("---")
st.markdown("""
    <div style='text-align: center; color: #666;'>
        <p>🛡️ Système de Détection d'Intrusions Intelligente | Cybersecurity Project 2026</p>
    </div>
""", unsafe_allow_html=True)