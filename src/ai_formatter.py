import json
import requests
from typing import Dict, Any, List

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "llama3.1:8b"

def _extract_json_block(text: str) -> Dict[str, Any]:
    """
    Try to parse full text as JSON first.
    If that fails, extract JSON object between first '{' and last '}'.
    """
    text = text.strip()


    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass


    start = text.index("{")
    end = text.rindex("}")
    if start != -1 and end != -1 and end > start:
        candidate = text[start:end +1]
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
    return{}

def _safe_ai_payload() -> Dict[str, Any]:
    """
    Safe fallback if model output is invalid
    """

    return {
        "what_happened": "AI output unavailable. Use rule evidence for triage.",
        "why_it_matters": "Potential malicious behavior detected by rule logic.",
        "top_3_actions": [
            "Validate alert evidence in Splunk",
            "Check related auth/process events in surrounding time window",
            "Escalate to analyst if suspicious pattern persists",
        ],
        "mitre_mapping": [],
        "confidence": 0.4,
    }

def _build_prompt(alert: Dict[str, Any]) -> str:
    """
    Prompt asks model to return strict JSON only.
    """
    return f"""
    You are a SOCE analyst assistant
    Given this alert JSON, produce ONLY valid JSON with this exact schema:

    {{
    "what_happened": "string",
    "why_it_matters": "string",
    "top_3_actions": ["string", "string", "string"],
    "mitre_mapping": ["string"],
    "confidence":0.0
    }}
    Rules:
    - Output JSON only. No markdown. No extra text
    - confidence must be number between 0.0 and 1.0
    - top_3_actions must contain exactly 3 concise actions
    - Use the alert's mitre_technique where applicable

    Alert JSON:
    {json.dumps(alert, ensure_ascii=False)}
    """.strip()

def enrich_one_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """"
    Call Ollama and enrich one alert with structured AI fields.
    """
    prompt = _build_prompt(alert)
    request_body = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature":0
        }
    }
    try:
        resp = requests.post(OLLAMA_URL, json = request_body, timeout = 180)
        resp.raise_for_status()
        body = resp.json()
        raw = str(body.get("response", "")).strip()
        if not raw:
            print("[AI ERROR] Empty response field from Ollama")
            ai = _safe_ai_payload()
            alert["ai_summary"] = ai
            alert["ai_confidence"] = ai["confidence"]
            return alert
    except Exception as e:
        ai = _safe_ai_payload()
        alert["ai_summary"]= ai 
        alert["ai_confidence"]= ai["confidence"]
        return alert
    
    parsed = _extract_json_block(raw)
    if not parsed:
        parsed = _safe_ai_payload()
    
    what_happened = str(parsed.get("what_happened", "")).strip() or _safe_ai_payload()["what_happened"]
    why_it_matters = str(parsed.get("why_it_matters","")).strip() or _safe_ai_payload()["why_it_matters"]

    actions = parsed.get("top_3_actions", [])
    if not isinstance(actions, list):
        actions= []
    actions = [str(a).strip() for a in actions if str(a).strip()]
    if len(actions) < 3:
        fallback = _safe_ai_payload()["top_3_actions"]
        actions = (actions + fallback)[:3]
    else:
        actions = actions[:3]

    mitre_mapping = parsed.get("mitre_mapping", [])
    if not isinstance(mitre_mapping, list):
        mitre_mapping = []
    mitre_mapping = [str(m).strip() for m in mitre_mapping if str(m).strip()]
    try:
        confidence = float(parsed.get("confidence", 0.4))
    except (TypeError, ValueError):
        confidence = 0.4
    confidence = max(0.0, min(1.0, confidence))

    ai = {
        "what_happened": what_happened,
        "why_it_matters": why_it_matters,
        "top_3_actions": actions,
        "mitre_mapping": mitre_mapping,
        "confidence": confidence,
        }      
    alert["ai_summary"]= ai
    alert["ai_confidence"] = confidence
    return alert

def enrich_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched = []
    for alert in alerts:
        enriched.append(enrich_one_alert(alert))
    return enriched