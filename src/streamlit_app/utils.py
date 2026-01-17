import json
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
import streamlit as st

def load_model(model_path):
    """
    Charge un modèle depuis un fichier pickle ou keras
    
    Args:
        model_path (str): Chemin vers le fichier du modèle
        
    Returns:
        model: Le modèle chargé
    """
    try:
        if model_path.endswith('.pkl'):
            with open(model_path, 'rb') as f:
                return pickle.load(f)
        elif model_path.endswith('.keras') or model_path.endswith('.h5'):
            from tensorflow import keras
            return keras.models.load_model(model_path)
        else:
            raise ValueError(f"Format de modèle non supporté: {model_path}")
    except Exception as e:
        st.error(f"Erreur lors du chargement du modèle: {str(e)}")
        return None

def load_metrics(metrics_path="C:/Users/ghada/intrusion-detection-system/data/models/metrics.json"):
    """
    Charge les métriques depuis un fichier JSON
    
    Args:
        metrics_path (str): Chemin vers le fichier de métriques
        
    Returns:
        dict: Dictionnaire contenant les métriques
    """
    try:
        with open(metrics_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        st.warning(f"Fichier de métriques non trouvé: {metrics_path}")
        return {}
    except json.JSONDecodeError:
        st.error(f"Erreur de lecture du fichier JSON: {metrics_path}")
        return {}

def save_metrics(metrics, metrics_path="data/models/metrics.json"):
    """
    Sauvegarde les métriques dans un fichier JSON
    
    Args:
        metrics (dict): Dictionnaire contenant les métriques
        metrics_path (str): Chemin vers le fichier de métriques
    """
    try:
        with open(metrics_path, 'w') as f:
            json.dump(metrics, f, indent=4)
        st.success(f"Métriques sauvegardées dans {metrics_path}")
    except Exception as e:
        st.error(f"Erreur lors de la sauvegarde des métriques: {str(e)}")

def load_data(data_path, nrows=None):
    """
    Charge des données depuis un fichier CSV
    
    Args:
        data_path (str): Chemin vers le fichier CSV
        nrows (int, optional): Nombre de lignes à charger
        
    Returns:
        DataFrame: Les données chargées
    """
    try:
        if data_path.endswith('.csv'):
            return pd.read_csv(data_path, nrows=nrows)
        elif data_path.endswith('.parquet'):
            return pd.read_parquet(data_path)
        else:
            raise ValueError(f"Format de données non supporté: {data_path}")
    except Exception as e:
        st.error(f"Erreur lors du chargement des données: {str(e)}")
        return None

def get_available_models(models_path="data/models"):
    """
    Liste tous les modèles disponibles dans le répertoire
    
    Args:
        models_path (str): Chemin vers le répertoire des modèles
        
    Returns:
        list: Liste des noms de fichiers de modèles
    """
    try:
        path = Path(models_path)
        models = []
        
        # Chercher les fichiers .pkl et .keras
        for ext in ['*.pkl', '*.keras', '*.h5']:
            models.extend([f.name for f in path.glob(ext)])
        
        return sorted(models)
    except Exception as e:
        st.error(f"Erreur lors de la liste des modèles: {str(e)}")
        return []

def get_available_datasets(data_path="data/processed"):
    """
    Liste tous les datasets disponibles
    
    Args:
        data_path (str): Chemin vers le répertoire des données
        
    Returns:
        list: Liste des noms de fichiers de données
    """
    try:
        path = Path(data_path)
        datasets = []
        
        # Chercher les fichiers .csv et .parquet
        for ext in ['*.csv', '*.parquet']:
            datasets.extend([f.name for f in path.glob(ext)])
        
        return sorted(datasets)
    except Exception as e:
        st.error(f"Erreur lors de la liste des datasets: {str(e)}")
        return []

def calculate_metrics(y_true, y_pred):
    """
    Calcule les métriques de performance
    
    Args:
        y_true: Vraies étiquettes
        y_pred: Prédictions
        
    Returns:
        dict: Dictionnaire contenant les métriques
    """
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    
    return {
        'accuracy': accuracy_score(y_true, y_pred),
        'precision': precision_score(y_true, y_pred, average='weighted', zero_division=0),
        'recall': recall_score(y_true, y_pred, average='weighted', zero_division=0),
        'f1_score': f1_score(y_true, y_pred, average='weighted', zero_division=0)
    }

def preprocess_features(data, feature_columns=None):
    """
    Prétraitement des features pour la prédiction
    
    Args:
        data (DataFrame): Données à prétraiter
        feature_columns (list): Liste des colonnes de features
        
    Returns:
        array: Features prétraitées
    """
    try:
        if feature_columns:
            data = data[feature_columns]
        
        # Suppression des valeurs manquantes
        data = data.fillna(0)
        
        # Conversion en numpy array
        return data.values
    except Exception as e:
        st.error(f"Erreur lors du prétraitement: {str(e)}")
        return None

def format_metric(value, metric_type='percentage'):
    """
    Formate une métrique pour l'affichage
    
    Args:
        value (float): Valeur de la métrique
        metric_type (str): Type de métrique ('percentage', 'number', 'decimal')
        
    Returns:
        str: Métrique formatée
    """
    if metric_type == 'percentage':
        return f"{value * 100:.2f}%"
    elif metric_type == 'number':
        return f"{value:,}"
    elif metric_type == 'decimal':
        return f"{value:.4f}"
    else:
        return str(value)

def generate_alert(attack_type, severity, source_ip, timestamp):
    """
    Génère une alerte formatée
    
    Args:
        attack_type (str): Type d'attaque détectée
        severity (str): Sévérité de l'attaque
        source_ip (str): Adresse IP source
        timestamp (str): Horodatage
        
    Returns:
        dict: Alerte formatée
    """
    severity_icons = {
        'Critique': '🔴',
        'Haute': '🟠',
        'Moyenne': '🟡',
        'Faible': '🟢'
    }
    
    return {
        'icon': severity_icons.get(severity, '⚪'),
        'attack_type': attack_type,
        'severity': severity,
        'source_ip': source_ip,
        'timestamp': timestamp
    }

def get_attack_description(attack_type):
    """
    Retourne une description de l'attaque
    
    Args:
        attack_type (str): Type d'attaque
        
    Returns:
        str: Description de l'attaque
    """
    descriptions = {
        'DoS/DDoS': 'Attaque par déni de service visant à rendre un service indisponible',
        'Port Scan': 'Balayage des ports pour identifier les services vulnérables',
        'Brute Force': 'Tentatives répétées pour deviner des mots de passe',
        'SQL Injection': 'Injection de code SQL malveillant dans les requêtes',
        'Botnet': 'Activité coordonnée de machines infectées',
        'Data Exfiltration': 'Tentative de vol de données sensibles'
    }
    
    return descriptions.get(attack_type, 'Type d\'attaque inconnu')

def create_confusion_matrix_plot(y_true, y_pred, labels=None):
    """
    Crée un graphique de matrice de confusion
    
    Args:
        y_true: Vraies étiquettes
        y_pred: Prédictions
        labels: Noms des classes
        
    Returns:
        plotly figure: Graphique de la matrice de confusion
    """
    from sklearn.metrics import confusion_matrix
    import plotly.figure_factory as ff
    
    cm = confusion_matrix(y_true, y_pred)
    
    if labels is None:
        labels = [str(i) for i in range(len(cm))]
    
    fig = ff.create_annotated_heatmap(
        z=cm,
        x=labels,
        y=labels,
        colorscale='Blues',
        showscale=True
    )
    
    fig.update_layout(
        title='Matrice de Confusion',
        xaxis_title='Prédictions',
        yaxis_title='Vraies Étiquettes'
    )
    
    return fig