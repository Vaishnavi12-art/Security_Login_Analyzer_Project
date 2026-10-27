
import csv
from pathlib import Path
from collections import Counter
from datetime import datetime

# Automatically locate files in this folder
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "security_log.txt"
REPORT_FILE = BASE_DIR / "security_report.txt"

# Detection settings
FAILED_LOGIN_LIMIT = 5


def analyze_logs():
    print("=" * 50)
    print("       SECURITY LOG ANALYZER")
    print("=" * 50)

    if not LOG_FILE.exists():
        print("ERROR: security_log.txt not found!")
        return

    total_events = 0
    successful_logins = 0
    failed_logins = 0
    failed_ips = Counter()
    alerts = []

    with LOG_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.reader(file)

        for row in reader:
            if len(row) != 5:
                continue

            timestamp, level, ip, event, username = [
                item.strip() for item in row
            ]

            total_events += 1

            if event == "LOGIN_SUCCESS":
                successful_logins += 1

            elif event == "LOGIN_FAILED":
                failed_logins += 1
                failed_ips[ip] += 1

    for ip, count in failed_ips.items():
        if count >= FAILED_LOGIN_LIMIT:
            alerts.append(
                f"WARNING: {ip} has {count} failed login attempts!"
            )

    report = [
        "SECURITY LOG ANALYZER REPORT",
        "=" * 35,
        f"Analysis time: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"Total log events: {total_events}",
        f"Successful logins: {successful_logins}",
        f"Failed logins: {failed_logins}",
        "",
        "FAILED LOGIN DETAILS",
        "-" * 35
    ]

    if failed_ips:
        for ip, count in failed_ips.most_common():
            report.append(f"IP Address: {ip} | Failed Attempts: {count}")
    else:
        report.append("No failed login attempts found.")

    report.extend(["", "SECURITY ALERTS", "-" * 35])

    if alerts:
        report.extend(alerts)
    else:
        report.append("No threshold-based alerts detected.")

    report_text = "\n".join(report)

    print(report_text)

    REPORT_FILE.write_text(report_text, encoding="utf-8")

    print("\nAnalysis completed successfully!")
    print("Report saved as: security_report.txt")


if __name__ == "__main__":
    try:
        analyze_logs()
    except PermissionError:
        print("ERROR: Permission denied. Check folder permissions.")
    except OSError as error:
        print(f"File error: {error}")
