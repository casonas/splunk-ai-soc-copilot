from typing import List, Dict, Any
from alert_schema import Alert, new_alert

def _safe_int(value: Any, default: int = 0) -> int:
    """
    Safely convert unknown input to int.
    Handles values like "3162, 3162, None, "".
    """
    try:
        return int(value)
    except (ValueError, TypeError):
        return default
    
def _severity_from_fail_count(fail_count: int) -> str:
    """
    Map failed attempt counts to severity levels.
    """
    if fail_count >= 1000:
        return "Critical"
    elif fail_count >= 100:
        return "High"
    elif fail_count >= 25:
        return "Medium"
    else:
        return "Low"
    
def _rule_confidence_from_fail_count(fail_count: int) -> float:
    """
    Map failed attempt counts to a confidence score between 0 and 1.
    """
    if fail_count >= 1000:
        return 0.98
    elif fail_count >= 100:
        return 0.90
    elif fail_count >= 25:
        return 0.75
    else:
        return 0.50
    
def build_bruteforce_alerts(rows: List[Dict[str, Any]]) -> List[Alert]:
    """
    Convert Splunk brute-force results rows into Alert dataclass objects.
    
    Expected row keys from your working SPL:
    - Account_Name
    - Source_Network_Address
    - count
    - hosts
    """
    alerts: List[Alert] = []
    for row in rows:
        account_name = row.get("Account_Name", "unknown")
        source_ip = row.get("Source_Network_Address", "unknown")
        fail_count = _safe_int(row.get("count", 0), default=0)
        hosts= row.get("hosts", [])
        if isinstance(hosts, str):
            hosts = [hosts]
        elif hosts is None:
            hosts = []
        severity = _severity_from_fail_count(fail_count)
        rule_confidence = _rule_confidence_from_fail_count(fail_count)

        recommended_actions = [
            "Temporarily disable or challenge the targeted account",
            "Block or rate-limit source IP at firewall/WAF",
            "Force password reset and verify MFA enrollment",
            "Review successful logons from same source in adjacent time window"
            ]
        alert = new_alert(
            detection_type="Brute-force Login Failures",
            severity=severity,
            mitre_technique="T1110",
            entities={
                "account_name": account_name,
                "source_ip": source_ip,
                "target_hosts": hosts
            },
            evidence={
                "failed_attempts": fail_count
            },
            rule_confidence=rule_confidence,
            recommended_actions=recommended_actions
        )
        alerts.append(alert)
    return alerts
