import json
from pathlib import Path
from ai_formatter import enrich_alerts


def main() -> None:
    input_path = Path("reports/alerts.json")
    output_path = Path("reports/alerts_enriched.json")

    if not input_path.exists():
        raise FileNotFoundError(f"Missing input file: {input_path}")

    alerts = json.loads(input_path.read_text(encoding="utf-8"))
    enriched = enrich_alerts(alerts)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(enriched, indent=2), encoding="utf-8")

    print(f"Loaded alerts: {len(alerts)}")
    print(f"Saved enriched alerts: {output_path.resolve()}")


if __name__ == "__main__":
    main()
