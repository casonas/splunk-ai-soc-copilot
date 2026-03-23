import json
from pathlib import Path
from typing import Dict, Any, List

def _normalize_iocs(alert: Dict[str, Any]) -> Dict[str, Any]:
    entities = alert.get("entities", {})
    return {
        "source_ip": entities.get("source_ip"),
        "account_name": entities.get("account_name"),
        "hosts": entities.get("target_hosts", entities.get("hosts", [])),

    }

def alert_to_ticket(alert: Dict[str, Any]) -> Dict[str, Any]:
    ai = alert.get("ai_summary", {})
    ticket = {
        "ticket_id": f"TICKET-{alert.get('alert_id', 'UNKNOWN')}",
        "alert_id": alert.get("alert_id"),
        "title": f"{alert.get('detection_type', 'Security Alert')} - {alert.get('severity', 'unknown').upper()}",
        "status": alert.get("status", "open"),
        "severity": alert.get("severity", "medium"),
        "mitre_id": alert.get("mitre_technique", ""),
        "iocs": _normalize_iocs(alert),
        "rule_confidence": alert.get("rule_confidence", 0.0),
        "ai_confidence": alert.get("ai_confidence", 0.0),
        "summary": {
            "what_happened": ai.get("what_happened", ""),
            "why_it_matters": ai.get("why_it_matters", ""),
        },
        "recommended_actions": ai.get("top_3_actions", []) or alert.get("recommended_actions", []),
        "analyst": {
            "label": alert.get("analyst_label", "Needs Review"),
            "note": alert.get("analyst_note", ""),
        },
        "evidence": alert.get("evidence", {}),
        "timeline": alert.get("investigation_timeline", []),
        "timestamp": alert.get("timestamp"),
    }

    return ticket


def export_tickets(
    alerts_path: str = "reports/alerts_enriched.json",
    tickets_dir: str = "reports/tickets",
) -> List[str]:
    in_file = Path(alerts_path)
    out_dir = Path(tickets_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if not in_file.exists():
        raise FileNotFoundError(f"Missing alerts file: {in_file}")

    alerts = json.loads(in_file.read_text(encoding="utf-8"))

    written_files: List[str] = []
    for alert in alerts:
        ticket = alert_to_ticket(alert)
        alert_id = alert.get("alert_id", "UNKNOWN")
        out_file = out_dir / f"{alert_id}.ticket.json"
        out_file.write_text(json.dumps(ticket, indent=2), encoding="utf-8")
        written_files.append(str(out_file.resolve()))

    return written_files