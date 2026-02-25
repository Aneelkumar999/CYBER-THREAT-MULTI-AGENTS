from typing import Dict, Any

class RiskAssessmentAgent:
    """Agent responsible for evaluating severity level based on anomaly and threat class."""
    
    def __init__(self):
        # Base severity for different threat classes
        self.severity_map = {
            "Normal": 0,
            "Phishing": 2,
            "Malware": 3,
            "DDoS": 3,
            "DoS Hulk": 2,
            "PortScan": 2,
            "Bot": 3,
            "Infiltration": 3,
            "Web Attack": 2,
            "FTP-Patator": 2,
            "SSH-Patator": 2,
            "DoS slowloris": 2,
            "DoS Slowhttptest": 2,
            "DoS GoldenEye": 2,
            "Heartbleed": 3,
            # UNSW-NB15 Labels
            "Fuzzers": 2,
            "Exploits": 3,
            "Backdoor": 3,
            "Shellcode": 3,
            "Analysis": 2,
            "Reconnaissance": 2,
            "DoS": 2,
            "Worms": 3,
            "Intrusion": 3,
            "Generic": 1
        }
        
    def assess(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Calculates final risk score and categorization."""
        is_anomaly = state.get("is_anomaly", False)
        threat_type = state.get("threat_type", "Normal")
        anomaly_score = state.get("anomaly_score", 0.0)  # 0 to 1
        
        if not is_anomaly:
            return {
                "risk_level": "Low",
                "risk_score": 0.0,
                "status": "success"
            }
            
        base_severity = self.severity_map.get(threat_type, 1)
        
        # Combine base severity of threat with the mathematical anomaly score
        # Max score is 3 (severity) + 1 (anomaly_score) = 4
        total_score = base_severity + anomaly_score
        
        if total_score >= 3.5:
            risk_level = "Critical"
        elif total_score >= 2.5:
            risk_level = "High"
        elif total_score >= 1.5:
            risk_level = "Medium"
        else:
            risk_level = "Low"
            
        # Normalize continuous risk score to 1-100 scale for UI
        normalized_score = min(100.0, max(0.0, (total_score / 4.0) * 100))
        
        return {
            "risk_level": risk_level,
            "risk_score": normalized_score,
            "status": "success"
        }
