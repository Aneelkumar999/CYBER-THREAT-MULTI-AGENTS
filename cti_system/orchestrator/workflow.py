from typing import Dict, Any, TypedDict
from langgraph.graph import StateGraph, START, END

# Import Agents
from cti_system.agents.preprocessor import PreprocessingAgent
from cti_system.agents.detector import AnomalyDetectionAgent
from cti_system.agents.classifier import ThreatClassificationAgent
from cti_system.agents.explainer import ExplainabilityAgent
from cti_system.agents.risk_assessor import RiskAssessmentAgent
from cti_system.agents.responder import ResponseAgent

# Define the State
class CTIState(TypedDict):
    original_log: Dict[str, Any]
    features: list
    is_anomaly: bool
    anomaly_score: float
    threat_type: str
    confidence: float
    explanation: str
    risk_level: str
    risk_score: float
    response_recommendation: str
    status: str
    error: str

class CTIWorkflow:
    def __init__(self):
        # Initialize sub-agents
        self.preprocessor = PreprocessingAgent()
        self.detector = AnomalyDetectionAgent()
        self.classifier = ThreatClassificationAgent()
        self.explainer = ExplainabilityAgent()
        self.risk_assessor = RiskAssessmentAgent()
        self.responder = ResponseAgent()
        
        # Build graph
        self.graph = self._build_graph()
        
    def _build_graph(self):
        workflow = StateGraph(CTIState)
        
        # Add Nodes
        workflow.add_node("preprocess", self.preprocessor.process)
        workflow.add_node("detect", self.detector.detect)
        workflow.add_node("classify", self.classifier.classify)
        workflow.add_node("explain", self.explainer.explain)
        workflow.add_node("risk_assess", self.risk_assessor.assess)
        workflow.add_node("respond", self.responder.respond)
        
        # Add Edges
        workflow.add_edge(START, "preprocess")
        workflow.add_edge("preprocess", "detect")
        
        # Conditional routing: if no anomaly, skip to risk assessment (which sets low risk)
        workflow.add_conditional_edges(
            "detect",
            self._route_anomaly,
            {
                "anomaly": "classify",
                "normal": "risk_assess"
            }
        )
        
        workflow.add_edge("classify", "explain")
        workflow.add_edge("explain", "risk_assess")
        workflow.add_edge("risk_assess", "respond")
        workflow.add_edge("respond", END)
        
        return workflow.compile()
        
    def _route_anomaly(self, state: CTIState) -> str:
        if state.get("is_anomaly"):
            return "anomaly"
        return "normal"
        
    def process_log(self, log: Dict[str, Any]) -> CTIState:
        """Processes a single log through the MAS pipeline."""
        initial_state = CTIState(
            original_log=log,
            features=[],
            is_anomaly=False,
            anomaly_score=0.0,
            threat_type="Normal",
            confidence=1.0,
            explanation="",
            risk_level="Low",
            risk_score=0.0,
            response_recommendation="",
            status="started",
            error=""
        )
        
        # Run graph
        result = self.graph.invoke(initial_state)
        return result
