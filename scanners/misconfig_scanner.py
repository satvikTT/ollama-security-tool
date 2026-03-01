# scanners/misconfig_scanner.py
import requests
from bs4 import BeautifulSoup
from core.authorization import AuthorizationChecker
from core.stealth import stealth

class MisconfigScanner:
    """Misconfiguration and security header vulnerability scanner"""

    def __init__(self, target_url, session=None):
        self.target_url = target_url
        self.base_url = self._get_base_url(target_url)
        self.session = session or requests.Session()
        self.auth = AuthorizationChecker()
        self.findings = []

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
        })

        # Security headers that should be present
        self.required_headers = {
            "X-Frame-Options": "Prevents clickjacking attacks",
            "X-Content-Type-Options": "Prevents MIME type sniffing",
            "X-XSS-Protection": "Enables browser XSS filter",
            "Strict-Transport-Security": "Enforces HTTPS connections",
            "Content-Security-Policy": "Prevents XSS and data injection",
            "Referrer-Policy": "Controls referrer information",
            "Permissions-Policy": "Controls browser feature access",
        }

        # Sensitive files that should NOT be publicly accessible
        self.sensitive_files = [
            "/.git/HEAD",
            "/.git/config",
            "/.env",
            "/config.php",
            "/config.inc.php",
            "/wp-config.php",
            "/backup.sql",
            "/backup.zip",
            "/database.sql",
            "/.htaccess",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/admin/",
            "/administrator/",
            "/phpmyadmin/",
            "/robots.txt",
            "/sitemap.xml",
        ]

        # Directory listing indicators
        self.dir_listing_patterns = [
            "index of /",
            "directory listing",
            "parent directory",
            "[to parent directory]",
        ]

    def _get_base_url(self, url):
        """Extract base URL from full URL"""
        parts = url.split("/")
        return f"{parts[0]}//{parts[2]}"

    def check_security_headers(self):
        """Check for missing security headers"""
        print("[Misconfig] --- Checking Security Headers ---")
        try:
            stealth.wait()
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers

            for header, description in self.required_headers.items():
                if header not in headers:
                    finding = {
                        "type": "Missing Security Header",
                        "url": self.target_url,
                        "detail": header,
                        "severity": "Medium",
                        "evidence": f"Header '{header}' not found in response",
                        "description": description
                    }
                    self.findings.append(finding)
                    print(f"[Misconfig] ⚠️  Missing: {header}")
                else:
                    print(f"[Misconfig] ✅ Present: {header}: {headers[header][:50]}")

        except Exception as e:
            print(f"[Misconfig] Error checking headers: {e}")

    def check_sensitive_files(self):
        """Check if sensitive files are publicly accessible"""
        print("\n[Misconfig] --- Checking Sensitive File Exposure ---")
        for path in self.sensitive_files:
            url = self.base_url + path
            try:
                stealth.wait()
                response = self.session.get(url, timeout=8, allow_redirects=False)

                # File exists and is accessible
                if response.status_code == 200 and len(response.text) > 10:
                    finding = {
                        "type": "Sensitive File Exposed",
                        "url": url,
                        "detail": path,
                        "severity": "High",
                        "evidence": f"HTTP 200 returned for sensitive path: {path}",
                        "description": "Sensitive file is publicly accessible"
                    }
                    self.findings.append(finding)
                    print(f"[Misconfig] ✅ EXPOSED: {url} (HTTP {response.status_code})")
                else:
                    print(f"[Misconfig] ✓ Protected: {path} (HTTP {response.status_code})")

            except Exception:
                print(f"[Misconfig] ✓ Not accessible: {path}")

    def check_directory_listing(self):
        """Check if directory listing is enabled"""
        print("\n[Misconfig] --- Checking Directory Listing ---")
        dirs_to_check = [
            "/",
            "/dvwa/",
            "/uploads/",
            "/backup/",
            "/admin/",
            "/images/",
        ]

        for path in dirs_to_check:
            url = self.base_url + path
            try:
                stealth.wait()
                response = self.session.get(url, timeout=8)
                text_lower = response.text.lower()

                for pattern in self.dir_listing_patterns:
                    if pattern in text_lower:
                        finding = {
                            "type": "Directory Listing Enabled",
                            "url": url,
                            "detail": path,
                            "severity": "Medium",
                            "evidence": f"Directory listing pattern '{pattern}' found",
                            "description": "Server exposes directory contents"
                        }
                        self.findings.append(finding)
                        print(f"[Misconfig] ⚠️  Directory listing enabled: {url}")
                        break
                else:
                    print(f"[Misconfig] ✓ No listing: {path}")

            except Exception:
                pass

    def check_server_info(self):
        """Check for server information disclosure"""
        print("\n[Misconfig] --- Checking Server Information Disclosure ---")
        try:
            stealth.wait()
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers

            info_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
            for header in info_headers:
                if header in headers:
                    finding = {
                        "type": "Information Disclosure",
                        "url": self.target_url,
                        "detail": f"{header}: {headers[header]}",
                        "severity": "Low",
                        "evidence": f"Server reveals: {header} = {headers[header]}",
                        "description": "Server version/technology information exposed"
                    }
                    self.findings.append(finding)
                    print(f"[Misconfig] ⚠️  Info disclosed: {header}: {headers[header]}")
                else:
                    print(f"[Misconfig] ✓ Hidden: {header}")

        except Exception as e:
            print(f"[Misconfig] Error checking server info: {e}")

    def scan(self):
        """Main misconfiguration scan method"""

        if not self.auth.check_authorization(self.target_url):
            print("[Misconfig] ❌ Scan aborted - Target not authorized!")
            return []

        print(f"\n[Misconfig] 🔍 Starting Misconfiguration scan on: {self.target_url}")
        print(f"[Misconfig] Base URL: {self.base_url}")

        # Run all checks
        self.check_security_headers()
        self.check_sensitive_files()
        self.check_directory_listing()
        self.check_server_info()

        print(f"\n[Misconfig] Scan complete. Found {len(self.findings)} issue(s).")
        return self.findings