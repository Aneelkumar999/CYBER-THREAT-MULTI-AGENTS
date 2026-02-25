from typing import Dict, Any
import numpy as np

class PreprocessingAgent:
    """Agent responsible for cleaning and normalizing log data for ML models."""
    
    PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP"]
    ACTIONS = ["ALLOW", "DENY", "DROP"]
    MAX_PORT = 65535.0
    MAX_PACKET_SIZE = 65535.0
    
    def __init__(self):
        pass
        
    def _one_hot_encode(self, value: str, categories: list) -> list:
        """Simple one-hot encoding."""
        encoded = [0.0] * len(categories)
        if value in categories:
            encoded[categories.index(value)] = 1.0
        return encoded
        
    def process(self, state_or_log: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes a single log entry.
        Returns the original log and its feature vector representation.
        """
        try:
            # Check if this is a LangGraph state or a direct log
            if "original_log" in state_or_log:
                log = state_or_log["original_log"]
            else:
                log = state_or_log
                
            # Define universal feature space translating mapping both UNSW and CICIDS schema equivalents
            # Using 10 consistent numerical features covering flow basics for baseline normalization
            
            features = []
            
            # 1. Flow Duration (UNSW: dur, CICIDS: Flow Duration)
            f_dur = float(log.get("dur", log.get("Flow Duration", 0.0)))
            features.append(np.log1p(f_dur))
            
            # 2. Source Packets (UNSW: spkts, CICIDS: Total Fwd Packets)
            f_spkts = float(log.get("spkts", log.get("Total Fwd Packets", log.get("Total Fwd Packets        ", 0.0))))
            features.append(np.log1p(f_spkts))
            
            # 3. Destination Packets (UNSW: dpkts, CICIDS: Total Backward Packets)
            f_dpkts = float(log.get("dpkts", log.get("Total Backward Packets", log.get("Total Backward Packets   ", 0.0))))
            features.append(np.log1p(f_dpkts))
            
            # 4. Source Bytes (UNSW: sbytes, CICIDS: Total Length of Fwd Packets, Cybersecurity: Packet Length)
            f_sbytes = float(log.get("sbytes", log.get("Total Length of Fwd Packets", log.get("Packet Length", 0.0))))
            features.append(np.log1p(f_sbytes))
            
            # 5. Destination Bytes (UNSW: dbytes, CICIDS: Total Length of Bwd Packets)
            # Sometimes CICIDS abbreviates or has weird spacing, doing safe fallbacks
            f_dbytes = float(log.get("dbytes", log.get("Total Length of Bwd Packets", log.get("Total Length of Bwd Packe", 0.0))))
            features.append(np.log1p(f_dbytes))
            
            # 6. Source TTL / Header Length Forward (UNSW: sttl, CICIDS: Fwd Header Length)
            f_sttl = float(log.get("sttl", log.get("Fwd Header Length", log.get("Fwd Header Length        ", 0.0))))
            features.append(np.log1p(f_sttl))
            
            # 7. Mean Packet Length (UNSW: smean, CICIDS: Packet Length Mean, Cybersecurity: Anomaly Scores)
            f_mean = float(log.get("smean", log.get("Packet Length Mean", log.get("Anomaly Scores", 0.0))))
            features.append(np.log1p(f_mean))
            
            # 8. Rate / Flow Packets per Second (UNSW: rate, CICIDS: Flow Packets/s)
            
            # CICIDS stores some infinities as strings, let's catch it
            rate_raw_str = str(log.get("rate", log.get("Flow Packets/s", "0.0"))).strip().lower()
            if "inf" in rate_raw_str or "infinity" in rate_raw_str:
                f_rate = 1e6
            else:
                try: 
                    f_rate = float(rate_raw_str)
                except ValueError:
                    f_rate = 0.0
            features.append(np.log1p(f_rate))
            
            # 9. Source mean load / Flow Bytes/s (UNSW: sload, CICIDS: Flow Bytes/s)
            sload_raw_str = str(log.get("sload", log.get("Flow Bytes/s", "0.0"))).strip().lower()
            if "inf" in sload_raw_str or "infinity" in sload_raw_str:
                f_sload = 1e8
            else:
                try: 
                    f_sload = float(sload_raw_str)
                except ValueError:
                    f_sload = 0.0
            features.append(np.log1p(f_sload))
            
            # 10. Idle max or similar idle baseline metric (UNSW: ct_dst_ltm, CICIDS: Idle Max)
            f_idle = float(log.get("ct_dst_ltm", log.get("Idle Max", 0.0)))
            features.append(np.log1p(f_idle))

            return {
                "original_log": log,
                "features": features,
                "status": "success",
                "error": None
            }
        except Exception as e:
            import traceback
            traceback.print_exc()
            return {
                "original_log": log,
                "features": None,
                "status": "error",
                "error": str(e)
            }
