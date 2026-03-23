from dataclasses import dataclass, asdict, field
from typing import List, Dict, Any
from datetime import datetime
import uuid

@dataclass
class Alert:
    alert_id: str
    timestamp: str
    detection_type: str
    severity: str
    mitre_technique: str
    entities: Dict[str, Any] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    rule_confidence: float = 0.0
    ai_confidence: float = 0.0
    status: str= "open" 
    analyst_label: str = "Needs Review"
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def new_alert(
        detection_type: str,    
        severity: str,
        mitre_technique: str,
        entities: Dict[str, Any],
        evidence: Dict[str, Any],
        rule_confidence: float = 0.0,
        
        recommended_actions: List[str] = None
) -> Alert:
    return Alert(
        alert_id=f"ALERT-{uuid.uuid4().hex[:10].upper()}",
        timestamp=datetime.utcnow().isoformat() + "Z",
        detection_type=detection_type,
        severity=severity,
        mitre_technique=mitre_technique,
        entities=entities,
        evidence=evidence,
        rule_confidence= max(0.0, min(1.0, rule_confidence)),
        recommended_actions=recommended_actions or []
    )