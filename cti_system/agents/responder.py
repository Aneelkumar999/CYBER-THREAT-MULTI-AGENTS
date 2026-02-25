from typing import Dict, Any

class ResponseAgent:
    """Agent responsible for generating actionable response recommendations."""
    
    def __init__(self):
        pass
        
    def respond(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Generates a response plan based on the threat."""
        risk_level = state.get("risk_level", "Low")
        threat_type = state.get("threat_type", "Normal")
        original_log = state.get("original_log", {})
        
        src_ip = original_log.get("src_ip", "Unknown")
        dst_port = original_log.get("dst_port", "Unknown")
        
        action_plan = []
        
        if risk_level == "Low" or threat_type == "Normal":
            action_plan.append("No immediate action required. Continue monitoring.")
        else:
            if threat_type == "DDoS":
                action_plan.append(f"Automatically rate-limit or block source IP {src_ip}.")
                action_plan.append("Alert network team for potential volumetric attack.")
            elif threat_type == "Malware":
                action_plan.append(f"Block outbound traffic to port {dst_port}.")
                action_plan.append(f"Isolate host machine (if internal) communicating with {src_ip}.")
            elif threat_type == "Phishing":
                action_plan.append(f"Flag emails/traffic from {src_ip} in proxy configuration.")
            
            if risk_level == "Critical":
                action_plan.append("TRIGGER EMERGENCY AUTOMATED FIREWALL RULE.")
                
        return {
            "response_recommendation": "\n".join(action_plan),
            "status": "success"
        }
