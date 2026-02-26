# app.py
from flask import Flask, render_template, request, jsonify, send_file
import threading, time, os, requests
from bs4 import BeautifulSoup
from datetime import datetime

from core.web_crawler import WebCrawler
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
scan_state = {"running": False, "messages": [], "report_file": None}

def add_message(role, content, msg_type="text"):
    scan_state["messages"].append({
        "role": role, "content": content,
        "type": msg_type, "time": datetime.now().strftime("%H:%M:%S")
    })

def dvwa_login(session, base_url):
    try:
        login_url = f"{base_url.rstrip('/')}/login.php"
        r = session.get(login_url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        t = soup.find("input", {"name": "user_token"})
        token = t["value"] if t else ""
        session.post(login_url, data={
            "username": "admin", "password": "password",
            "Login": "Login", "user_token": token
        }, allow_redirects=True)
        sec_url = f"{base_url.rstrip('/')}/security.php"
        r2 = session.get(sec_url)
        soup2 = BeautifulSoup(r2.text, "html.parser")
        t2 = soup2.find("input", {"name": "user_token"})
        token2 = t2["value"] if t2 else ""
        session.post(sec_url, data={
            "security": "low", "seclev_submit": "Submit", "user_token": token2
        })
        return True
    except Exception:
        return False

def run_scan(target_url):
    scan_state["running"] = True
    scan_state["report_file"] = None
    all_findings = []

    try:
        add_message("bot", f"🔍 Starting security assessment on: **{target_url}**")
        time.sleep(0.3)

        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"})

        is_dvwa = "dvwa" in target_url.lower()

        if is_dvwa:
            add_message("bot", "🔐 DVWA detected — logging in automatically...")
            if dvwa_login(session, target_url):
                add_message("bot", "✅ DVWA login successful! Security level: Low")
            else:
                add_message("bot", "⚠️ DVWA login failed — continuing anyway")
        else:
            # PRE-SCAN: Crawl ONCE and share results with all scanners
            add_message("bot", "🕷️ Crawling website to discover forms &amp; parameters...")
            crawler = WebCrawler(target_url, session, max_pages=15)
            crawler.crawl()
            forms = crawler.forms_found
            url_params = crawler.url_params_found
            add_message("bot", f"✅ Crawl complete: **{len(forms)}** forms, **{len(url_params)}** URL param endpoints found")

        # ── XSS Scanner ──────────────────────────────
        add_message("bot", "🔎 **[1/4]** Running XSS Scanner...")
        try:
            xss = XSSScanner(target_url, session)
            if not is_dvwa:
                xss._crawler = crawler
                xss._pre_crawled = True
            xss_findings = xss.scan()
            all_findings.extend(xss_findings)
            if xss_findings:
                add_message("bot", f"⚠️ XSS: Found **{len(xss_findings)}** vulnerability/vulnerabilities!", "warning")
                for f in xss_findings:
                    add_message("bot", f"  → {f['type']} | Param: {f.get('parameter','?')[:50]}", "finding")
            else:
                add_message("bot", "✅ XSS Scanner: No vulnerabilities found")
        except Exception as e:
            add_message("bot", f"⚠️ XSS error: {str(e)[:100]}")

        # ── SQLi Scanner ─────────────────────────────
        add_message("bot", "🔎 **[2/4]** Running SQL Injection Scanner...")
        try:
            sqli = SQLiScanner(target_url, session)
            if not is_dvwa:
                sqli._crawler = crawler
                sqli._pre_crawled = True
            sqli_findings = sqli.scan()
            all_findings.extend(sqli_findings)
            if sqli_findings:
                add_message("bot", f"⚠️ SQLi: Found **{len(sqli_findings)}** vulnerability/vulnerabilities!", "warning")
                for f in sqli_findings:
                    add_message("bot", f"  → {f['type']} | Param: {f.get('parameter','?')}", "finding")
            else:
                add_message("bot", "✅ SQLi Scanner: No vulnerabilities found")
        except Exception as e:
            add_message("bot", f"⚠️ SQLi error: {str(e)[:100]}")

        # ── CMDi Scanner ─────────────────────────────
        add_message("bot", "🔎 **[3/4]** Running Command Injection Scanner...")
        try:
            cmdi = CMDiScanner(target_url, session)
            if not is_dvwa:
                cmdi._crawler = crawler
                cmdi._pre_crawled = True
            cmdi_findings = cmdi.scan()
            all_findings.extend(cmdi_findings)
            if cmdi_findings:
                add_message("bot", f"⚠️ CMDi: Found **{len(cmdi_findings)}** vulnerability/vulnerabilities!", "warning")
                for f in cmdi_findings:
                    add_message("bot", f"  → {f['type']} | {f['evidence'][:60]}", "finding")
            else:
                add_message("bot", "✅ CMDi Scanner: No vulnerabilities found")
        except Exception as e:
            add_message("bot", f"⚠️ CMDi error: {str(e)[:100]}")

        # ── Misconfig Scanner ─────────────────────────
        add_message("bot", "🔎 **[4/4]** Running Misconfiguration Scanner...")
        try:
            misconfig = MisconfigScanner(target_url, session)
            misconfig_findings = misconfig.scan()
            all_findings.extend(misconfig_findings)
            if misconfig_findings:
                add_message("bot", f"⚠️ Misconfig: Found **{len(misconfig_findings)}** issue(s)!", "warning")
            else:
                add_message("bot", "✅ Misconfig Scanner: No issues found")
        except Exception as e:
            add_message("bot", f"⚠️ Misconfig error: {str(e)[:100]}")

        # ── GRC + DB ──────────────────────────────────
        add_message("bot", "📊 Running GRC Risk Assessment &amp; Compliance Mapping...")
        assessor = RiskAssessor()
        mapper = ComplianceMapper()
        db = DatabaseManager()
        session_id = db.create_scan_session(target_url)

        for finding in all_findings:
            try:
                risk = assessor.assess_finding(finding)
                mapping = mapper.map_finding(finding)
                vuln_id = db.save_finding(session_id, finding, risk)
                db.save_compliance_mapping(vuln_id, mapping)
                finding["cvss_score"] = risk["cvss_score"]
                finding["business_impact"] = risk["business_impact"]
                finding["recommendation"] = risk["recommendation"]
            except Exception:
                continue

        db.complete_scan_session(session_id, len(all_findings), 0)

        # ── Report ────────────────────────────────────
        add_message("bot", "📄 Generating HTML Report...")
        gen = ReportGenerator(session_id=session_id)
        report_file = gen.generate_html(scan_info={"target": target_url, "duration": "N/A"})
        scan_state["report_file"] = report_file

        critical = sum(1 for f in all_findings if f.get("severity") == "Critical")
        high     = sum(1 for f in all_findings if f.get("severity") == "High")
        medium   = sum(1 for f in all_findings if f.get("severity") == "Medium")
        low      = sum(1 for f in all_findings if f.get("severity") == "Low")

        add_message("bot", f"""
🎯 **Scan Complete!**

📊 **Summary:**
• Total Findings : {len(all_findings)}
• 🔴 Critical    : {critical}
• 🟠 High        : {high}
• 🟡 Medium      : {medium}
• 🟢 Low         : {low}

📋 **Compliance:** All findings mapped to OWASP Top 10, ISO 27001 &amp; NIST CSF
📄 **Report:** Ready for download below
        """, "summary")
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
        return jsonify({"error": "Scan already in progress"}), 400
    if not target.startswith("http"):
        target = "http://" + target
    scan_state["messages"] = []
    add_message("user", f"Scan {target}")
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
        return send_file(scan_state["report_file"], as_attachment=True,
            download_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    return jsonify({"error": "No report"}), 404

if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    print("🚀 Starting LLM Security Tool...")
    print("📡 Open: http://localhost:5000")
    app.run(debug=False, host="0.0.0.0", port=5000)
