"""
Script pour générer un fichier de métriques exemple
Utilisez ce script si vous n'avez pas encore de metrics.json
"""

import json
import os

def generate_sample_metrics():
    """
    Génère un fichier metrics.json avec des valeurs exemple
    """
    
    # Métriques exemple pour chaque modèle
    metrics = {
        "random_forest": {
            "accuracy": 0.9524,
            "precision": 0.9489,
            "recall": 0.9524,
            "f1_score": 0.9503
        },
        "xgboost": {
            "accuracy": 0.9687,
            "precision": 0.9645,
            "recall": 0.9687,
            "f1_score": 0.9665
        },
        "lightgbm": {
            "accuracy": 0.9612,
            "precision": 0.9578,
            "recall": 0.9612,
            "f1_score": 0.9594
        },
        "svm": {
            "accuracy": 0.9234,
            "precision": 0.9189,
            "recall": 0.9234,
            "f1_score": 0.9210
        },
        "cnn_best": {
            "accuracy": 0.9756,
            "precision": 0.9723,
            "recall": 0.9756,
            "f1_score": 0.9739
        },
        "mlp_best": {
            "accuracy": 0.9534,
            "precision": 0.9501,
            "recall": 0.9534,
            "f1_score": 0.9517
        },
        "decision_tree": {
            "accuracy": 0.9156,
            "precision": 0.9123,
            "recall": 0.9156,
            "f1_score": 0.9139
        }
    }
    
    # Créer le dossier data/models s'il n'existe pas
    os.makedirs("data/models", exist_ok=True)
    
    # Sauvegarder les métriques
    metrics_path = "data/models/metrics.json"
    with open(metrics_path, 'w') as f:
        json.dump(metrics, f, indent=4)
    
    print(f"✅ Fichier de métriques créé : {metrics_path}")
    print("\nContenu :")
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    generate_sample_metrics()