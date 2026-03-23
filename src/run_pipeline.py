import os
from typing import List, Dict, Any
from timeline_builder import build_timeline


from splunk_client import SplunkClient
from detections import DETECTIONS
from build_alerts import build_bruteforce_alerts
from build_powershell_alerts import build_powershell_alerts
from build_lateral_alerts import build_lateral_alerts
from save_alerts import save_alerts_to_json
from ai_formatter import enrich_alerts
from ticket_exporter import export_tickets


def _require_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise ValueError(f"Missing required env var: {name}")
    return value


def main() -> None:
    # 1) Read Splunk credentials from environment
    splunk_host = os.getenv("SPLUNK_HOST", "localhost")
    splunk_user = _require_env("SPLUNK_USER")
    splunk_pass = _require_env("SPLUNK_PASS")
    verify_ssl = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"

    client = SplunkClient(
        host=splunk_host,
        username=splunk_user,
        password=splunk_pass,
        verify_ssl=verify_ssl,
    )

    # 2) Run searches directly in Splunk
    bf_rows = client.run_search_csv(DETECTIONS["bruteforce"])
    ps_rows = client.run_search_csv(DETECTIONS["powershell"])
    lat_rows = client.run_search_csv(DETECTIONS["lateral"])

    print(f"Splunk brute-force rows: {len(bf_rows)}")
    print(f"Splunk powershell rows: {len(ps_rows)}")
    print(f"Splunk lateral rows: {len(lat_rows)}")

    # 3) Build standardized alerts
    bf_alerts = build_bruteforce_alerts(bf_rows)
    ps_alerts = build_powershell_alerts(ps_rows)
    lat_alerts = build_lateral_alerts(lat_rows)

    all_alerts = bf_alerts + ps_alerts + lat_alerts
    print(f"Total alerts built: {len(all_alerts)}")

    # 4) Save base alerts
    alerts_path = save_alerts_to_json(all_alerts, "reports/alerts.json")
    print(f"Saved base alerts: {alerts_path}")

    # 5) Enrich with AI
    alert_dicts: List[Dict[str, Any]] = [a.to_dict() for a in all_alerts]
    enriched = enrich_alerts(alert_dicts)
    for i in range(len(enriched)):
        enriched[i]["investigation_timeline"] = build_timeline(enriched[i])


    # Save enriched alerts
    import json
    from pathlib import Path

    enriched_path = Path("reports/alerts_enriched.json")
    enriched_path.parent.mkdir(parents=True, exist_ok=True)
    enriched_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")

    print(f"Saved enriched alerts: {enriched_path.resolve()}")

    # 6) Export tickets
    ticket_files = export_tickets(
        alerts_path="reports/alerts_enriched.json",
        tickets_dir="reports/tickets",
    )

    print(f"Exported tickets: {len(ticket_files)}")
    for f in ticket_files[:5]:
        print(f" - {f}")

    print("Pipeline complete ✅")


if __name__ == "__main__":
    main()