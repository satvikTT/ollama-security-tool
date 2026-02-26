# app.py - Main Flask Chat Interface
from flask import Flask, render_template, request, jsonify, send_file
import threading
import time
import os
import requests
from bs4 import BeautifulSoup
from datetime import datetime

from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.cmdi_scanner import CMDiScanner
from scanners.misconfig_scanner import MisconfigScanner
from grc.risk_assessor import RiskAssessor
from grc.compliance_mapper import ComplianceMapper
from database.db_manager import DatabaseManager
from reporting.report_generator import ReportGenerator
from core.authorization import AuthorizationChecker

app = Flask(__name__)

# Global scan state
scan_state = {
    "running": False,
    "messages": [],
    "report_file": None
}

def add_message(role, content, msg_type="text"):
    """Add a message to the chat"""
    scan_state["messages"].append({
        "role": role,
        "content": content,
        "type": msg_type,
        "time": datetime.now().strftime("%H:%M:%S")
    })

def dvwa_login(session):
    """Login to DVWA"""
    try:
        login_url = "http://localhost/dvwa/login.php"
        response = session.get(login_url, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input["value"] if token_input else ""
        session.post(login_url, data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token
        }, allow_redirects=True)

        # Set security level
        security_url = "http://localhost/dvwa/security.php"
        resp = session.get(security_url)
        soup = BeautifulSoup(resp.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input["value"] if token_input else ""
        session.post(security_url, data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": token
        })
        return True
    except Exception as e:
        return False

def run_scan(target_url):
    """Run full security scan in background thread"""
    scan_state["running"] = True
    scan_state["report_file"] = None
    all_findings = []

    try:
        add_message("bot", f"🔍 Starting security assessment on: **{target_url}**")
        time.sleep(0.5)

        # Check if DVWA target
        is_dvwa = "localhost" in target_url or "127.0.0.1" in target_url

        # Setup session
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
        })

        # Login if DVWA
        if is_dvwa:
            add_message("bot", "🔐 Logging into DVWA lab environment...")
            if dvwa_login(session):
                add_message("bot", "✅ Login successful! Security level set to: Low")
            else:
                add_message("bot", "⚠️ DVWA login failed - continuing with unauthenticated scan")

        base = target_url.rstrip("/")

        # ── XSS Scanner ──────────────────────────────
        add_message("bot", "🔎 **[1/4]** Running XSS Scanner...")
        try:
            xss_url = f"{base}/vulnerabilities/xss_r/" if is_dvwa else base
            xss = XSSScanner(xss_url, session)
            xss_findings = xss.scan()
            all_findings.extend(xss_findings)
            if xss_findings:
                add_message("bot", f"⚠️ XSS Scanner: Found **{len(xss_findings)}** vulnerability/vulnerabilities!", "warning")
                for f in xss_findings:
                    add_message("bot", f"  → {f['type']} | Payload: `{f['payload'][:50]}`", "finding")
            else:
                add_message("bot", "✅ XSS Scanner: No vulnerabilities found")
        except Exception as e:
            add_message("bot", f"⚠️ XSS Scanner error: {str(e)[:100]}")

        # ── SQLi Scanner ─────────────────────────────
        add_message("bot", "🔎 **[2/4]** Running SQL Injection Scanner...")
        try:
            sqli_url = f"{base}/vulnerabilities/sqli/" if is_dvwa else base
            sqli = SQLiScanner(sqli_url, session)
            sqli_findings = sqli.scan()
            all_findings.extend(sqli_findings)
            if sqli_findings:
                add_message("bot", f"⚠️ SQLi Scanner: Found **{len(sqli_findings)}** vulnerability/vulnerabilities!", "warning")
                for f in sqli_findings:
                    add_message("bot", f"  → {f['type']} | Evidence: {f['evidence'][:60]}", "finding")
            else:
                add_message("bot", "✅ SQLi Scanner: No vulnerabilities found")
        except Exception as e:
            add_message("bot", f"⚠️ SQLi Scanner error: {str(e)[:100]}")

        # ── CMDi Scanner ─────────────────────────────
        add_message("bot", "🔎 **[3/4]** Running Command Injection Scanner...")
        try:
            cmdi_url = f"{base}/vulnerabilities/exec/" if is_dvwa else base
            cmdi = CMDiScanner(cmdi_url, session)
            cmdi_findings = cmdi.scan()
            all_findings.extend(cmdi_findings)
            if cmdi_findings:
                add_message("bot", f"⚠️ CMDi Scanner: Found **{len(cmdi_findings)}** vulnerability/vulnerabilities!", "warning")
                for f in cmdi_findings:
                    add_message("bot", f"  → {f['type']} | Evidence: {f['evidence'][:60]}", "finding")
            else:
                add_message("bot", "✅ CMDi Scanner: No vulnerabilities found")
        except Exception as e:
            add_message("bot", f"⚠️ CMDi Scanner error: {str(e)[:100]}")

        # ── Misconfig Scanner ─────────────────────────
        add_message("bot", "🔎 **[4/4]** Running Misconfiguration Scanner...")
        try:
            misconfig = MisconfigScanner(base, session)
            misconfig_findings = misconfig.scan()
            all_findings.extend(misconfig_findings)
            if misconfig_findings:
                add_message("bot", f"⚠️ Misconfig Scanner: Found **{len(misconfig_findings)}** issue(s)!", "warning")
            else:
                add_message("bot", "✅ Misconfig Scanner: No issues found")
        except Exception as e:
            add_message("bot", f"⚠️ Misconfig Scanner error: {str(e)[:100]}")

        # ── GRC Assessment ────────────────────────────
        add_message("bot", "📊 Running GRC Risk Assessment & Compliance Mapping...")
        assessor = RiskAssessor()
        mapper = ComplianceMapper()
        db = DatabaseManager()
        session_id = db.create_scan_session(target_url)

        for finding in all_findings:
            risk = assessor.assess_finding(finding)
            mapping = mapper.map_finding(finding)
            vuln_id = db.save_finding(session_id, finding, risk)
            db.save_compliance_mapping(vuln_id, mapping)
            finding["cvss_score"] = risk["cvss_score"]
            finding["business_impact"] = risk["business_impact"]
            finding["recommendation"] = risk["recommendation"]

        db.complete_scan_session(session_id, len(all_findings), 0)

        # ── Generate Report ───────────────────────────
        add_message("bot", "📄 Generating HTML Report...")
        generator = ReportGenerator(session_id=session_id)
        report_file = generator.generate_html(
            scan_info={"target": target_url, "duration": "N/A"}
        )
        scan_state["report_file"] = report_file

        # ── Final Summary ─────────────────────────────
        critical = sum(1 for f in all_findings if f.get("severity") == "Critical")
        high     = sum(1 for f in all_findings if f.get("severity") == "High")
        medium   = sum(1 for f in all_findings if f.get("severity") == "Medium")
        low      = sum(1 for f in all_findings if f.get("severity") == "Low")

        summary = f"""
🎯 **Scan Complete!**

📊 **Summary:**
• Total Findings : {len(all_findings)}
• 🔴 Critical    : {critical}
• 🟠 High        : {high}
• 🟡 Medium      : {medium}
• 🟢 Low         : {low}

📋 **Compliance:** All findings mapped to OWASP Top 10, ISO 27001 & NIST CSF
📄 **Report:** Ready for download below
        """
        add_message("bot", summary, "summary")
        add_message("bot", "REPORT_READY", "report_link")

    except Exception as e:
        add_message("bot", f"❌ Scan error: {str(e)}", "error")

    finally:
        scan_state["running"] = False


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data = request.json
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "No target provided"}), 400

    if scan_state["running"]:
        return jsonify({"error": "Scan already running"}), 400

    # Clear previous messages
    scan_state["messages"] = []
    add_message("user", f"Scan {target}")
    add_message("bot", f"🚀 Received scan request for: **{target}**")

    # Run scan in background thread
    thread = threading.Thread(target=run_scan, args=(target,))
    thread.daemon = True
    thread.start()

    return jsonify({"status": "started"})

@app.route("/messages")
def messages():
    return jsonify({
        "messages": scan_state["messages"],
        "running": scan_state["running"],
        "has_report": scan_state["report_file"] is not None
    })

@app.route("/download_report")
def download_report():
    if scan_state["report_file"] and os.path.exists(scan_state["report_file"]):
        return send_file(
            scan_state["report_file"],
            as_attachment=True,
            download_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
    return jsonify({"error": "No report available"}), 404

if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    print("🚀 Starting LLM Security Tool Chat Interface...")
    print("📡 Open your browser at: http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
