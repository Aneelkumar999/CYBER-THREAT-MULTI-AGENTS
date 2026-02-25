import streamlit as st
from datetime import datetime

st.set_page_config(page_title="Agent Responses", layout="wide", page_icon="📡")

st.title("📡 Live Agent Interrogation & Communication")
st.markdown("Monitor what each specialized Multi-Agent is actively concluding about detected network threats during the simulation.")

if 'processed_events' not in st.session_state or not st.session_state['processed_events']:
    st.info("No events have been processed yet. Please start the network simulation on the main dashboard.")
else:
    # Filter only anomalies with Medium or High Risk
    anomalies = [e for e in st.session_state['processed_events'] if e.get('is_anomaly') and e.get('risk_level') in ['Medium', 'High', 'Critical']]
    
    if not anomalies:
        st.success("No Medium or High-level threats have been detected yet! All network traffic is currently normal or low-risk.")
    else:
        st.subheader(f"Interrogating {len(anomalies)} Detected Threat(s) (Medium/High Risk Only)")
        
        # Display each anomaly with the detailed agent voices
        for i, a in enumerate(reversed(anomalies)):
            status_icon = "🛡️ [RESOLVED]" if a.get("resolved") else "🚨 [ACTIVE]"
            dst_ip = a.get("dst_ip") or "target network"
            
            with st.expander(f"{status_icon} Intelligence Snapshot: {a['threat_type']} originating from {a['src_ip']} at {a['timestamp']} (Risk: {a['risk_level']})", expanded=(i==0)):
                
                st.info(f"**📥 Data Collection Agent:** I have intercepted and am routing an active session streaming from `{a['src_ip']}` attempting to connect to `{dst_ip}:{a['dst_port']}` via `{a['protocol']}`.")
                
                st.info("**🔧 Preprocessing Agent:** I have received the stream. I standardizing the packet size formats, executing one-hot feature encoding, and cleansing the data payload for ML ingestion.")
                
                st.warning(f"**🔎 Anomaly Detection Agent:** I have evaluated the matrices using IsolationForest! The inputs are mathematically divergent from our allowed network baseline trajectories. Flagging anomaly.")
                
                st.error(f"**🎯 Threat Classification Agent:** Behavior analyzed via RainforestClassifier. I am classifying this vector as **{a['threat_type']}** with {a['confidence']:.2f} confidence certainty.")
                
                st.success(f"**🧠 Explainability Agent:** Let me translate that into human readable logic: {a['explanation']}")
                
                st.error(f"**⚠️ Risk Assessment Agent:** I compute the severity as **{a['risk_level']}**. The continuous multi-metric risk algorithm outputs an exact score of {a['risk_score']:.1f}/100.")
                
                st.error(f"**🛡️ Response Agent:** I am formulating the mitigation strategy. Recommendation mapped: *{a['response_recommendation']}*")
