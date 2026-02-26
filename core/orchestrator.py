# core/orchestrator.py
import time
import requests
from bs4 import BeautifulSoup

from core.authorization import AuthorizationChecker
from core.config import config
from scanners.xss_scanner import XSSScanner
from scanners.sqli_scanner import SQLiScanner
from scanners.cmdi_scanner import CMDiScanner
from scanners.misconfig_scanner import MisconfigScanner
from grc.risk_assessor import RiskAssessor
from grc.compliance_mapper import ComplianceMapper
from database.db_manager import DatabaseManager

class Orchestrator:
    """
    Main orchestrator - coordinates all scanners, GRC assessment,
    and database storage in one unified workflow.
    """

    def __init__(self, target_url, dvwa_mode=False):
        self.target_url = target_url
        self.dvwa_mode  = dvwa_mode
        self.auth       = AuthorizationChecker()
        self.assessor   = RiskAssessor()
        self.mapper     = ComplianceMapper()
        self.db         = DatabaseManager()
        self.session    = requests.Session()
        self.all_findings = []

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
        })

    def _dvwa_login(self):
        """Login to DVWA and set security level to low"""
        print("[ORCH] Logging into DVWA...")
        login_url = "http://localhost/dvwa/login.php"
        response = self.session.get(login_url)
        soup = BeautifulSoup(response.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input["value"] if token_input else ""

        self.session.post(login_url, data={
            "username": "admin",
            "password": "password",
            "Login": "Login",
            "user_token": token
        }, allow_redirects=True)

        # Set security level
        security_url = "http://localhost/dvwa/security.php"
        resp = self.session.get(security_url)
        soup = BeautifulSoup(resp.text, "html.parser")
        token_input = soup.find("input", {"name": "user_token"})
        token = token_input["value"] if token_input else ""
        self.session.post(security_url, data={
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": token
        })
        print("[ORCH] ✅ DVWA login successful, security level: low")

    def _run_scanner(self, scanner_name, scanner):
        """Run a scanner and return findings"""
        print(f"\n[ORCH] {'='*50}")
        print(f"[ORCH] Running {scanner_name}...")
        print(f"[ORCH] {'='*50}")
        try:
            findings = scanner.scan()
            print(f"[ORCH] {scanner_name} complete: {len(findings)} finding(s)")
            return findings
        except Exception as e:
            print(f"[ORCH] Error in {scanner_name}: {e}")
            return []

    def _process_findings(self, findings, session_id):
        """Run GRC assessment and save findings to database"""
        for finding in findings:
            # Risk assessment
            risk = self.assessor.assess_finding(finding)

            # Compliance mapping
            mapping = self.mapper.map_finding(finding)

            # Save to database
            vuln_id = self.db.save_finding(session_id, finding, risk)
            self.db.save_compliance_mapping(vuln_id, mapping)

            # Add enriched finding to list
            finding["cvss_score"]      = risk["cvss_score"]
            finding["business_impact"] = risk["business_impact"]
            finding["recommendation"]  = risk["recommendation"]
            finding["compliance"]      = mapping

            self.all_findings.append(finding)

    def run(self):
        """Main scan workflow"""
        print(f"""
╔══════════════════════════════════════════════════════╗
║     LLM-Orchestrated Security Assessment Tool       ║
║     Target: {self.target_url[:40]:<40} ║
╚══════════════════════════════════════════════════════╝
        """)

        # Authorization check
        if not self.auth.check_authorization(self.target_url):
            if not self.auth.require_confirmation(self.target_url):
                print("[ORCH] ❌ Scan aborted by user.")
                return []

        # DVWA login if needed
        if self.dvwa_mode:
            self._dvwa_login()

        # Create DB session
        session_id = self.db.create_scan_session(self.target_url)
        start_time = time.time()

        # ── Run all scanners ──────────────────────────
        base = self.target_url.rstrip("/")

        xss_findings = self._run_scanner(
            "XSS Scanner",
            XSSScanner(f"{base}/vulnerabilities/xss_r/", self.session)
        )

        sqli_findings = self._run_scanner(
            "SQLi Scanner",
            SQLiScanner(f"{base}/vulnerabilities/sqli/", self.session)
        )

        cmdi_findings = self._run_scanner(
            "CMDi Scanner",
            CMDiScanner(f"{base}/vulnerabilities/exec/", self.session)
        )

        misconfig_findings = self._run_scanner(
            "Misconfig Scanner",
            MisconfigScanner(base, self.session)
        )

        all_raw = xss_findings + sqli_findings + cmdi_findings + misconfig_findings

        # ── GRC Assessment & Database Storage ─────────
        print(f"\n[ORCH] {'='*50}")
        print(f"[ORCH] Running GRC Assessment & Saving to Database...")
        print(f"[ORCH] {'='*50}")
        self._process_findings(all_raw, session_id)

        # Complete session
        duration = round(time.time() - start_time, 2)
        self.db.complete_scan_session(session_id, len(self.all_findings), duration)
        self.db.print_summary(session_id)

        # ── Final Summary ──────────────────────────────
        print(f"""
╔══════════════════════════════════════════════════════╗
║                 SCAN COMPLETE                       ║
╠══════════════════════════════════════════════════════╣
║  Total Findings : {len(self.all_findings):<34} ║
║  Duration       : {duration}s{'':<32} ║
║  Session ID     : {session_id:<34} ║
╚══════════════════════════════════════════════════════╝
        """)

        return self.all_findings
