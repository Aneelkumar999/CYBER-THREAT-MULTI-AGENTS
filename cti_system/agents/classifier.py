from typing import Dict, Any, List
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import os
import joblib

class ThreatClassificationAgent:
    """Agent responsible for classifying anomalous events into specific threat types."""
    
    # Mapping for UNSW-NB15 dataset categories
    CLASSES = ["Normal", "Generic", "Exploits", "Fuzzers", "DoS", "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms", "Unknown"]
    
    def __init__(self, model_path: str = "cti_system/models/rf_classifier.pkl"):
        self.model_path = model_path
        self.model = RandomForestClassifier(n_estimators=50, random_state=42)
        self.is_trained = False
        self.trained_classes = self.CLASSES
        
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.is_trained = True
                print("Loaded existing Threat Classification model.")
            except Exception as e:
                print(f"Error loading model: {e}")
                
    def train(self, X: List[List[float]], y: List[int]):
        """Trains the Random Forest model on labeled data."""
        if not X or not y:
            return
        X_array = np.array(X)
        y_array = np.array(y)
        self.model.fit(X_array, y_array)
        self.is_trained = True
        
        # Save model
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        print("Trained and saved Threat Classification model.")
        
    def classify(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies the threat if it's marked as an anomaly.
        """
        features = state.get("features")
        is_anomaly = state.get("is_anomaly", False)
        
        # If it's not an anomaly or model not trained, mark as Normal
        if not features or not is_anomaly or not self.is_trained:
            return {
                "threat_type": "Normal",
                "confidence": 1.0,
                "status": "success"
            }
            
        try:
            X = np.array([features])
            prediction_idx = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            # self.model.classes_ contains the actual string labels we fit with
            threat_type = str(prediction_idx)
            confidence = float(np.max(probabilities))
            
            return {
                "threat_type": threat_type,
                "confidence": confidence,
                "status": "success"
            }
        except Exception as e:
            return {
                "threat_type": "Unknown",
                "confidence": 0.0,
                "status": "error",
                "error": str(e)
            }
