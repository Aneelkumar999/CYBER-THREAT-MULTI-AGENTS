import json
import random
import time
import pandas as pd
from datetime import datetime, timedelta

def generate_logs(num_logs=100, output_file="synthetic_high_risk.csv"):
    """Generates strictly 100 synthetic network logs overloaded with High-Risk threat tags."""
    logs = []
    base_time = datetime.now()
    
    protocols = ["TCP", "UDP", "ICMP", "HTTP"]
    actions = ["ALLOW", "DENY", "DROP"]
    
    # We use explicitly mapped tags inside RiskAssessor so the dashboard sees Level 2 & 3 risks immediately
    threat_labels = ["DDoS", "Exploits", "Backdoor", "PortScan", "Bot", "DoS Hulk"]
    
    for i in range(num_logs):
        log_time = base_time + timedelta(seconds=i*2) # simulate 2 seconds apart
        
        # Inject anomalies (~80% chance) to forcefully demonstrate High/Medium on dashboard
        is_anomaly = random.random() < 0.8
        
        if is_anomaly:
            # Anomalous log mapping directly to severe label types
            pkt_size = random.randint(10000, 50000)
            dst_port = random.choice([4444, 1337, 6667, 23])
            protocol = "TCP"
            action = random.choice(["ALLOW", "DENY"])
            label = random.choice(threat_labels)
        else:
            # Normal log
            pkt_size = random.randint(64, 1500)
            dst_port = random.choice([80, 443, 22, 53])
            protocol = random.choice(protocols)
            action = "ALLOW"
            label = "BENIGN"

        log_entry = {
            "timestamp": log_time.isoformat(),
            "Source IP": f"192.168.1.{random.randint(2, 254)}",
            "Destination IP": f"{random.randint(1, 220)}.{random.randint(0,255)}.1.1",
            "Source Port": random.randint(1024, 65535),
            "Destination Port": dst_port,
            "Protocol": protocol,
            "Total Length of Fwd Packets": pkt_size,
            "action": action,
            " Label": label
        }
        logs.append(log_entry)
        
    df = pd.DataFrame(logs)
    df.to_csv(output_file, index=False)
    print(f"Generated {num_logs} Explicit High-Risk logs to {output_file}")

if __name__ == "__main__":
    generate_logs(num_logs=100)
