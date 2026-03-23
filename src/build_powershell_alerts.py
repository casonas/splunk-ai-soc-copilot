from typing import List, Dict, Any
from alert_schema import Alert, new_alert


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _severity_from_count(count: int) -> str:
    if count >= 20:
        return "critical"
    if count >= 8:
        return "high"
    if count >= 3:
        return "medium"
    return "low"


def _rule_confidence_from_count(count: int) -> float:
    if count >= 20:
        return 0.97
    if count >= 8:
        return 0.90
    if count >= 3:
        return 0.78
    return 0.60


def build_powershell_alerts(rows: List[Dict[str, Any]]) -> List[Alert]:
    alerts: List[Alert] = []

    for row in rows:
        host = row.get("host", "unknown")
        account = row.get("Account_Name", "unknown")
        proc = row.get("New_Process_Name", "unknown")
        parent = row.get("Parent_Process_Name", "unknown")
        cmd = row.get("Process_Command_Line", "")
        count = _safe_int(row.get("count", 1), default=1)

        severity = _severity_from_count(count)
        rule_confidence = _rule_confidence_from_count(count)

        recommended_actions = [
            "Isolate host if command indicates remote payload execution",
            "Collect PowerShell script block logs and parent process chain",
            "Disable/rotate affected credentials and hunt for same command pattern",
        ]

        alert = new_alert(
            detection_type="Suspicious PowerShell Execution",
            severity=severity,
            mitre_technique="T1059.001",
            entities={
                "host": host,
                "account_name": account,
                "process": proc,
                "parent_process": parent,
            },
            evidence={
                "process_command_line": cmd,
                "event_count": count,
                "raw_row": row,
            },
            rule_confidence=rule_confidence,
            recommended_actions=recommended_actions,
        )

        alerts.append(alert)

    return alerts