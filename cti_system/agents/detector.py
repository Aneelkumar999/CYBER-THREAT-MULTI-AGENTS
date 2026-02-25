from typing import Dict, Any, List
from sklearn.ensemble import IsolationForest
import numpy as np
import os
import joblib

class AnomalyDetectionAgent:
    """Agent responsible for detecting anomalies using Isolation Forest."""
    
    def __init__(self, model_path: str = "cti_system/models/iforest_model.pkl"):
        self.model_path = model_path
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False
        
        # Try to load existing model
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_trained = True
                print("Loaded existing Anomaly Detection model.")
            except Exception as e:
                print(f"Error loading model: {e}")
                
    def train(self, X: List[List[float]]):
        """Trains the Isolation Forest model on normal/mixed data."""
        if not X:
            return
        X_array = np.array(X)
        self.model.fit(X_array)
        self.is_trained = True
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print("Trained and saved Anomaly Detection model.")
        
    def detect(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Detects an anomaly given a preprocessed feature vector.
        Expects state to have 'features'.
        """
        features = state.get("features")
        if not features or not self.is_trained:
            return {"anomaly_score": 0.0, "is_anomaly": False, "status": "skipped"}
            
        try:
            X = np.array([features])
            # iforest returns 1 for normal, -1 for anomaly
            prediction = self.model.predict(X)[0]
            # score_samples returns negative anomaly score. Lower means more anomalous.
            score = self.model.score_samples(X)[0] 
            
            # Convert to a 0-1 probability-like anomaly score (higher = more anomalous)
            # This is a heuristic translation for the dashboard
            normalized_score = float(max(0, min(1, 0.5 - (score / 2))))
            
            is_anomaly = bool(prediction == -1)
            
            return {
                "anomaly_score": normalized_score,
                "is_anomaly": is_anomaly,
                "status": "success"
            }
        except Exception as e:
            return {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "status": "error",
                "error": str(e)
            }
