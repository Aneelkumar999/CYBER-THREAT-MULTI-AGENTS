import json
import os
import pandas as pd
from typing import List, Dict

class DataCollectionAgent:
    """Agent responsible for reading and parsing log data."""
    def __init__(self, log_source_path: str):
        self.log_source_path = log_source_path
        
    def collect_logs(self, max_records=5000, shuffle=False) -> List[Dict]:
        """Reads logs from JSON or CSV file (or directory) and returns a list of dictionaries."""
        if not os.path.exists(self.log_source_path):
            raise FileNotFoundError(f"Log source not found at {self.log_source_path}")
            
        try:
            # Check if directory
            files_to_process = []
            if os.path.isdir(self.log_source_path):
                for root, _, files in os.walk(self.log_source_path):
                    for file in files:
                        if file.endswith('.csv') or file.endswith('.json'):
                            files_to_process.append(os.path.join(root, file))
            else:
                files_to_process = [self.log_source_path]

            all_logs = []
            for file_path in files_to_process:
                if len(all_logs) >= max_records:
                    break
                    
                limit = max_records - len(all_logs)
                
                if file_path.endswith('.csv'):
                    if shuffle:
                        # Load everything, randomize mathematically, and slice the ceiling to prevent bias gaps
                        # This avoids strictly grabbing the top contiguous block
                        df = pd.read_csv(file_path).sample(frac=1, random_state=42).reset_index(drop=True).head(limit)
                    else:
                        # Load capped contiguous rows instantly into memory
                        df = pd.read_csv(file_path, nrows=limit)
                    
                    # Map some CSV columns to the unified format expected by the system
                    if 'srcip' in df.columns:
                        df['src_ip'] = df['srcip']
                    elif 'Source IP' in df.columns:
                        df['src_ip'] = df['Source IP']
                    else:
                        df['src_ip'] = '192.168.1.' + df.index.astype(str) # Mock IP if not present
                        
                    if 'dstip' in df.columns:
                        df['dst_ip'] = df['dstip']
                    elif 'Destination IP' in df.columns:
                        df['dst_ip'] = df['Destination IP']
                    else:
                        df['dst_ip'] = '10.0.0.' + df.index.astype(str) # Mock IP if not present
                        
                    if 'sport' in df.columns:
                        df['src_port'] = df['sport']
                    elif 'Source Port' in df.columns:
                        df['src_port'] = df['Source Port']
                    else:
                        df['src_port'] = 12345
                        
                    if 'dsport' in df.columns:
                        df['dst_port'] = df['dsport']
                    elif 'Destination Port' in df.columns:
                        df['dst_port'] = df['Destination Port']
                    else:
                        df['dst_port'] = 80
                        
                    if 'proto' in df.columns:
                        df['protocol'] = df['proto']
                    elif 'Protocol' in df.columns:
                        df['protocol'] = df['Protocol'].str.lower()
                    else:
                        df['protocol'] = 'TCP'

                    # Map custom packet length structures 
                    if 'Packet Length' in df.columns:
                        df['packet_size'] = df['Packet Length']
                        
                    # Maintain correct attack category labels if possible
                    if 'Attack Type' in df.columns:
                        df = pd.read_csv("data/cybersecurity_attacks.csv") # direct injection
                        df['attack_cat'] = df['Attack Type'].fillna('Normal')
                    elif 'attack_cat' in df.columns:
                        df['attack_cat'] = df['attack_cat'].fillna('Normal')
                    elif ' Label' in df.columns or 'Label' in df.columns:
                        col_target = ' Label' if ' Label' in df.columns else 'Label'
                        
                        # Apply explicit attack categories rather than just grouping everything to "Malware"
                        # This enables RiskAssessor to actually identify DDoS/Bot outputs
                        def label_mapper(x):
                            x_str = str(x).strip()
                            if x_str == 'BENIGN':
                                return 'Normal'
                            return x_str # Pass specific label (e.g. "DDoS", "PortScan", "DoS Hulk") string directly to the model
                            
                        df['attack_cat'] = df[col_target].apply(label_mapper)
                        
                    # We need a timestamp for the dashboard
                    from datetime import datetime, timedelta
                    base_time = datetime.now()
                    df['timestamp'] = [ (base_time + timedelta(seconds=i)).isoformat() for i in range(len(df)) ]
                    
                    all_logs.extend(df.to_dict(orient='records'))
                else:
                    with open(file_path, 'r') as f:
                        logs = json.load(f)
                        all_logs.extend(logs[:limit])
                        
            return all_logs
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error reading logs: {e}")
            return []
            
    def stream_logs(self):
        """Simulates real-time streaming of logs."""
        logs = self.collect_logs(max_records=2000)
        for log in logs:
            yield log
