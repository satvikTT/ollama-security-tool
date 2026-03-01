# scanners/xss_scanner.py
import requests
from bs4 import BeautifulSoup
from core.web_crawler import WebCrawler
from llm.payload_generator import LLMPayloadGenerator
from core.authorization import AuthorizationChecker
from core.stealth import stealth

class XSSScanner:
    DVWA_PATHS = ["/vulnerabilities/xss_r/", "/vulnerabilities/xss_s/"]

    def __init__(self, target_url, session=None):
        self.target_url = target_url.rstrip("/")
        self.session = session or requests.Session()
        self.payload_gen = LLMPayloadGenerator()
        self.auth = AuthorizationChecker()
        self.findings = []
        self.is_dvwa = "dvwa" in target_url.lower()
        self._crawler = None
        self._pre_crawled = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"})

    def check_xss(self, response, payload):
        return response and payload in response.text

    def _get_payloads(self):
        print("[XSS] Generating payloads via LLM...")
        llm = self.payload_gen.generate_xss_payloads(field_type="text", detected_filters="none", html_context="form", target_context="web app")
        static = [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>", "'\"><script>alert(1)</script>",
            "<body onload=alert(1)>", "<script>alert('XSS')</script>",
        ]
        for p in llm:
            if isinstance(p, dict) and p.get("payload"):
                static.append(p["payload"])
        return static

    def _scan_dvwa(self):
        print("[XSS] DVWA mode")
        payloads = self._get_payloads()
        for path in self.DVWA_PATHS:
            url = self.target_url + path
            for payload in payloads:
                if not payload: continue
                try:
                    stealth.wait()
                    r = self.session.get(url, timeout=10)
                    soup = BeautifulSoup(r.text, "html.parser")
                    t = soup.find("input", {"name": "user_token"})
                    token = t["value"] if t else ""
                    stealth.wait()
                    result = self.session.get(url, params={"name": payload, "user_token": token}, timeout=10)
                    if self.check_xss(result, payload):
                        self.findings.append({"type": "XSS - Reflected", "url": url, "parameter": "name", "payload": payload, "severity": "High", "evidence": f"Payload reflected at {url}"})
                        print(f"[XSS] ✅ VULNERABLE! {payload[:40]}")
                        break
                except Exception:
                    continue

    def _scan_generic(self):
        print("[XSS] Generic mode")
        if self._pre_crawled and self._crawler:
            crawler = self._crawler
            forms = crawler.forms_found
            url_params = crawler.url_params_found
        else:
            crawler = WebCrawler(self.target_url, self.session, max_pages=15)
            crawler.crawl()
            forms = crawler.forms_found
            url_params = crawler.url_params_found

        print(f"[XSS] {len(forms)} forms, {len(url_params)} URL param endpoints")
        payloads = self._get_payloads()

        # Test forms
        tested = set()
        for form in forms:
            action = form["action_url"]
            if action in tested: continue
            tested.add(action)
            for payload in payloads:
                if not payload: continue
                r = crawler.submit_form(form, payload)
                if self.check_xss(r, payload):
                    self.findings.append({"type": "XSS - Reflected", "url": action, "parameter": "form", "payload": payload, "severity": "High", "evidence": f"Payload reflected at {action}"})
                    print(f"[XSS] ✅ VULNERABLE (form)! {payload[:40]}")
                    break

        # Test URL params
        tested_bases = set()
        for up in url_params:
            base = up["base_url"]
            if base in tested_bases: continue
            tested_bases.add(base)
            for param_name in up["params"]:
                for payload in payloads:
                    if not payload: continue
                    r = crawler.test_url_param(up, payload, param_name)
                    if self.check_xss(r, payload):
                        self.findings.append({"type": "XSS - Reflected", "url": base, "parameter": param_name, "payload": payload, "severity": "High", "evidence": f"Payload reflected via URL param '{param_name}'"})
                        print(f"[XSS] ✅ VULNERABLE (URL param: {param_name})!")
                        break

    def scan(self):
        if not self.auth.check_authorization(self.target_url):
            print("[XSS] ❌ Unauthorized!"); return []
        print(f"\n[XSS] 🔍 Scanning: {self.target_url}")
        if self.is_dvwa: self._scan_dvwa()
        else: self._scan_generic()
        print(f"\n[XSS] Done. Found {len(self.findings)} finding(s).")
        return self.findings