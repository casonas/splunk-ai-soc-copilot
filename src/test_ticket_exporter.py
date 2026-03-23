from ticket_exporter import export_tickets


def main() -> None:
    files = export_tickets(
        alerts_path="reports/alerts_enriched.json",
        tickets_dir="reports/tickets",
    )
    print(f"Exported {len(files)} tickets:")
    for f in files:
        print(f"- {f}")


if __name__ == "__main__":
    main()
