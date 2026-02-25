import streamlit as st
import sys
import os
import time
import pandas as pd

# Add root to python path to resolve cti_system imports
# app.py is in root/cti_system/dashboard/app.py, so we need 3 dirnames to get to root
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cti_system.orchestrator.workflow import CTIWorkflow
from cti_system.agents.collector import DataCollectionAgent
from cti_system.data_generator import generate_logs

st.set_page_config(page_title="Multi-Agent CTI Dashboard", layout="wide", page_icon="🛡️")

@st.cache_resource
def get_workflow():
    workflow = CTIWorkflow()
    
    logs_path = "data/cybersecurity_attacks.csv"
    if not os.path.exists(logs_path):
        logs_path = "cti_system/data/sample_logs.json"
        
    if not os.path.exists(logs_path):
        generate_logs(100, logs_path)
        
    if not workflow.detector.is_trained or not workflow.classifier.is_trained:
        # Avoid circular imports or bad paths, just load the models via train stub
        import main
        main.train_dummy_models(workflow, logs_path)
    return workflow

workflow = get_workflow()
# Swap testing stream to actual new target dataset
logs_path = "data/cybersecurity_attacks.csv"
if not os.path.exists(logs_path):
    logs_path = "cti_system/data/sample_logs.json"

st.title("🛡️ Multi-Agent Cyber Threat Intelligence System")
st.markdown("Real-time network anomaly detection, classification, and response orchestration using LangGraph.")

# Initialize session state for real-time tracking
if 'processed_events' not in st.session_state:
    st.session_state['processed_events'] = []
if 'anomaly_count' not in st.session_state:
    st.session_state['anomaly_count'] = 0
if 'is_running' not in st.session_state:
    st.session_state['is_running'] = False

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Total Events Processed", len(st.session_state['processed_events']))
with col2:
    st.metric("Threats Detected", st.session_state['anomaly_count'])
with col3:
    if st.button("Start/Stop Simulation"):
        st.session_state['is_running'] = not st.session_state['is_running']
        
    fast_forward_mode = st.toggle("Fast-Forward to Next Threat", help="Skip thousands of rows of Normal traffic to find the next DDoS/PortScan attack natively.")

log_container = st.empty()

def render_event_history(events):
    df = pd.DataFrame(events[::-1])
    
    st.subheader("Recent Network Events")
    
    # Highlight anomalies
    def color_anomalies(val):
        if val == True:
            return 'background-color: #ffcccc'
        return ''
        
    try:
        styled_df = df.style.map(color_anomalies, subset=['is_anomaly'])
    except AttributeError:
        styled_df = df.style.applymap(color_anomalies, subset=['is_anomaly'])
        
    st.dataframe(
        styled_df, 
        use_container_width=True,
        height=300
    )
    
    anomalies = [e for e in events[::-1] if e["is_anomaly"]]
    if anomalies:
        st.subheader(f"🚨 Detailed Threat Reports ({len(anomalies)})")
        for a in anomalies:
            status = "✅ RESOLVED" if a.get("resolved") else "🚨 ACTIVE"
            with st.expander(f"[{status}] Threat: {a['threat_type']} from {a['src_ip']} | Risk: {a['risk_level']} | Time: {a['timestamp']}"):
                st.write(f"**Source:** `{a['src_ip']}` -> **Target:** `{a['dst_ip']}:{a['dst_port']}`")
                st.write(f"**Classification:** {a['threat_type']} (Confidence: {a['confidence']:.2f})")
                st.write(f"**Explainability (Reasoning):** {a['explanation']}")
                st.write(f"**Risk Assessment:** {a['risk_level']} (Score: {a['risk_score']:.1f}/100)")
                st.warning(f"**Automated Response Recommendation:**\n{a['response_recommendation']}")
                
                if not a.get("resolved"):
                    if st.button("Resolve Threat", key=f"resolve_{a['id']}"):
                        for event in st.session_state['processed_events']:
                            if event.get("id") == a["id"]:
                                event["resolved"] = True
                        st.rerun()

# Real-time simulation
if st.session_state['is_running']:
    collector = DataCollectionAgent(logs_path)
    # We load a massive chunk of data so Fast-Forward can traverse down thousands of lines realistically
    logs = collector.collect_logs(max_records=50000)
    
    for i in range(len(st.session_state['processed_events']), len(logs)):
        if not st.session_state['is_running']:
            break
            
        log = logs[i]
        
        # If fast forward is enabled, check if the raw log label is a Threat. 
        # If it is just Normal or BENIGN, instantaneously skip it until we hit an attack.
        if fast_forward_mode:
            raw_label = str(log.get("attack_cat", log.get("Label", "Normal"))).strip().upper()
            if raw_label in ["NORMAL", "BENIGN", "NONE", ""]:
                # Simply skip this iteration
                # We append a dummy event if you want accurate numbering, but usually skipping entirely is cleaner
                st.session_state['processed_events'].append({
                    "id": f"evt_{i}_skipped", "is_anomaly": False, "threat_type": "Normal", "status": "skipped"
                })
                continue
        
        result = workflow.process_log(log)
        
        # Save to state
        # Only saving non-skipped events to UI
        if result.get("status") != "skipped":
            event_record = {
                "id": f"evt_{i}_{log['timestamp']}_{log['src_ip']}",
                "timestamp": log["timestamp"],
                "src_ip": log["src_ip"],
                "dst_port": log["dst_port"],
                "protocol": log["protocol"],
                "is_anomaly": result["is_anomaly"],
                "threat_type": result["threat_type"],
                "risk_level": result["risk_level"],
                "confidence": result.get("confidence", 0.0),
                "explanation": result.get("explanation", ""),
                "risk_score": result.get("risk_score", 0.0),
                "response_recommendation": result.get("response_recommendation", ""),
                "dst_ip": result.get("original_log", {}).get("dst_ip", ""),
                "resolved": False
            }
            st.session_state['processed_events'].append(event_record)
            
            if result["is_anomaly"]:
                st.session_state['anomaly_count'] += 1
                st.toast(f"🚨 Threat Detected! {result['threat_type']} from {log['src_ip']}", icon="🚨")
                
            # Update UI every 0.1 seconds for effect (only sleep if we actually process one)
            with log_container.container():
                
                # Render only real events, not the fast-forward placeholders
                display_events = [e for e in st.session_state['processed_events'] if e.get("status") != "skipped"]
                render_event_history(display_events)
                    
            time.sleep(0.1)
            st.rerun()

else:
    # Render static view when not running
    if st.session_state['processed_events']:
        render_event_history(st.session_state['processed_events'])
    else:
        st.info("Click 'Start/Stop Simulation' to begin streaming network logs.")
