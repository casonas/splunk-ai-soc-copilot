from typing import List, Dict, Any
from alert_schema import Alert, new_alert


def _safe_int(v: Any, d: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return d


def _sev(host_count: int) -> str:
    if host_count >= 10:
        return "critical"
    if host_count >= 5:
        return "high"
    if host_count >= 3:
        return "medium"
    return "low"


def _conf(host_count: int) -> float:
    if host_count >= 10:
        return 0.96
    if host_count >= 5:
        return 0.88
    if host_count >= 3:
        return 0.78
    return 0.60


def build_lateral_alerts(rows: List[Dict[str, Any]]) -> List[Alert]:
    alerts: List[Alert] = []

    for row in rows:
        account = row.get("Account_Name", "unknown")
        src_ip = row.get("Source_Network_Address", "unknown")
        host_count = _safe_int(row.get("host_count", row.get("dc(host)", 0)), 0)

        hosts = row.get("hosts", [])
        if isinstance(hosts, str):
            hosts = [hosts]
        elif hosts is None:
            hosts = []

        alert = new_alert(
            detection_type="Possible Lateral Movement",
            severity=_sev(host_count),
            mitre_technique="T1021",
            entities={
                "account_name": account,
                "source_ip": src_ip,
                "hosts": hosts,
            },
            evidence={
                "host_count": host_count,
                "raw_row": row,
            },
            rule_confidence=_conf(host_count),
            recommended_actions=[
                "Validate account activity across listed hosts",
                "Isolate suspected pivot host(s)",
                "Review 4624/4672 chain and disable compromised credentials",
            ],
        )

        alerts.append(alert)

    return alerts