# test_report.py
from reporting.report_generator import ReportGenerator
from database.db_manager import DatabaseManager
import os

# Load findings from last scan session in DB
db = DatabaseManager()
sessions = db.get_all_sessions()

if not sessions:
    print("[!] No scan sessions found. Run main.py first.")
    exit(1)

# Use the latest session
latest_session = sessions[-1]
print(f"[*] Generating report for Session ID: {latest_session.id}")
print(f"[*] Target: {latest_session.target_url}")
print(f"[*] Findings: {latest_session.total_findings}")
print(f"[*] Duration: {latest_session.duration_seconds}s")

# Generate report
generator = ReportGenerator(session_id=latest_session.id)
report_file = generator.generate_html(
    scan_info={
        "target": latest_session.target_url,
        "duration": latest_session.duration_seconds
    }
)

if report_file:
    print(f"\n[*] ✅ Report generated successfully!")
    print(f"[*] Open this file in your browser:")
    print(f"[*] {os.path.abspath(report_file)}")
