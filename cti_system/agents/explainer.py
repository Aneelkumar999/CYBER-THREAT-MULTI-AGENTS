from typing import Dict, Any

class ExplainabilityAgent:
    """Agent responsible for generating human-readable explanations for anomalies."""
    
    def __init__(self):
        pass
        
    def generate_explanation(self, state: Dict[str, Any]) -> str:
        """
        Looks at the original log, features, and model outputs to explain 
        why a threat was detected.
        """
        is_anomaly = state.get("is_anomaly", False)
        
        if not is_anomaly:
            return "Activity is normal. No significant deviations detected."
            
        original_log = state.get("original_log", {})
        threat_type = state.get("threat_type", "Unknown")
        anomaly_score = state.get("anomaly_score", 0.0)
        
        explanation_parts = []
        explanation_parts.append(f"Threat '{threat_type}' detected with anomaly score {anomaly_score:.2f}.")
        
        # Rule-based explainability heuristics for real UNSW-NB15 data
        sttl = int(original_log.get("sttl", 0))
        rate = float(original_log.get("rate", 0.0))
        sbytes = int(original_log.get("sbytes", 0))
        
        if sttl > 100:
            explanation_parts.append(f"Unusually high source Time-To-Live (sttl={sttl}).")
            
        if rate > 10000:
            explanation_parts.append(f"Extremely high packet transmission rate ({rate:.1f} pkts/sec).")
            
        if sbytes > 5000:
            explanation_parts.append(f"Large payload detected from source ({sbytes} bytes).")
            
        if not explanation_parts[1:]:
            explanation_parts.append("ML model identified complex non-linear deviations from baseline in network rates/durations.")
            
        return " ".join(explanation_parts)

    def explain(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Wrapper for State object"""
        explanation = self.generate_explanation(state)
        return {"explanation": explanation, "status": "success"}
