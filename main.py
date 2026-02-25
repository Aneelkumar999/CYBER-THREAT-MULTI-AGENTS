import os
import sys

# Add current directory to path so imports work
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from cti_system.orchestrator.workflow import CTIWorkflow
from cti_system.agents.collector import DataCollectionAgent
from cti_system.data_generator import generate_logs

def train_dummy_models(workflow: CTIWorkflow, logs_path: str):
    """Trains the models with the provided dataset."""
    print("Training ML agents heavily on isolated dataset...")
    # 1. Load baseline UNSW-NB15 Training Data
    collector_train = DataCollectionAgent(logs_path)
    # Enforce dataset randomizing structural mix properly injecting Attack metrics explicitly
    logs_train = collector_train.collect_logs(max_records=15000, shuffle=True)
    
    preprocessed_data = []
    labels = []
    
    for log in logs_train:
        res = workflow.preprocessor.process(log)
        if res["features"]:
            if sum(res["features"]) == 0:
                continue
                
            preprocessed_data.append(res["features"])
            
            if "attack_cat" in log:
                labels.append(log["attack_cat"])
            else:
                if log.get("action") in ["DENY", "DROP"] or log.get("dst_port") in [4444, 1337, 6667, 23]:
                    labels.append("Malware") 
                else:
                    labels.append("Normal") 
                
    workflow.detector.train(preprocessed_data)
    workflow.classifier.train(preprocessed_data, labels)
    print("Training complete.")

def run_batch():
    """Runs a batch process for non-interactive execution."""
    # Use real dataset instead of synthetic
    logs_path = "data/cybersecurity_attacks.csv"
    
    # Fallback if real dataset is missing
    if not os.path.exists(logs_path):
        logs_path = "cti_system/data/sample_logs.json"
        if not os.path.exists(logs_path):
            print("Generating sample logs...")
            generate_logs(100, logs_path)
        
    workflow = CTIWorkflow()
    
    # Train if not trained
    if not workflow.detector.is_trained or not workflow.classifier.is_trained:
        train_dummy_models(workflow, logs_path)
        
    print("\n--- Running Pipeline on a few logs ---")
    collector = DataCollectionAgent(logs_path)
    # Stream first 5 logs
    for i, log in enumerate(collector.stream_logs()):
        if i >= 5:
            break
        print(f"\nProcessing Log {i+1}: {log['src_ip']} -> {log['dst_ip']}:{log['dst_port']}")
        result = workflow.process_log(log)
        print(f"Is Anomaly: {result['is_anomaly']}")
        if result['is_anomaly']:
            print(f"Threat Type: {result['threat_type']} (Conf: {result['confidence']:.2f})")
            print(f"Explanation: {result['explanation']}")
            print(f"Risk Level: {result['risk_level']}")
            print(f"Response: {result['response_recommendation']}")

if __name__ == "__main__":
    run_batch()
