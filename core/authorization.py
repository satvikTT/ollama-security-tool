# core/authorization.py
import re
from urllib.parse import urlparse

class AuthorizationChecker:
    """
    Ethical safeguard - ensures scanning is only performed
    on authorized targets. This is a critical component.
    """

    SAFE_LAB_HOSTS = [
    "localhost",
    "127.0.0.1",
    "dvwa",
    "webgoat",
    "bwapp",
    "testphp.vulnweb.com",
    "demo.testfire.net",   
    "www.webscantest.com", 
    "vulnerablewebapp.com",
    "testasp.vulnweb.com",
    "testphp.vulnweb.com",
    "testfire.net",       
    "testphp.vulnweb.com",       
    ]
    def __init__(self):
        self.authorized_targets = []
        self.scan_log = []

    def add_authorized_target(self, url):
        """Manually authorize a target URL"""
        self.authorized_targets.append(url)
        print(f"[AUTH] Target authorized: {url}")

    def is_safe_lab(self, url):
        """Check if target is a known safe lab environment"""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return any(safe in host for safe in self.SAFE_LAB_HOSTS)

    def check_authorization(self, url):
        """
        Main authorization check before any scan.
        Returns True only if target is authorized.
        """
        # Always allow known lab environments
        if self.is_safe_lab(url):
            print(f"[AUTH] ✅ Safe lab environment detected: {url}")
            return True

        # Check manually authorized targets
        if any(url.startswith(t) for t in self.authorized_targets):
            print(f"[AUTH] ✅ Manually authorized target: {url}")
            return True

        # Block unauthorized targets
        print(f"[AUTH] ❌ UNAUTHORIZED TARGET: {url}")
        print("[AUTH] Only scan systems you own or have explicit written permission to test.")
        return False

    def require_confirmation(self, url):
        """Ask user to confirm authorization before scanning"""
        print(f"\n{'='*50}")
        print(f"  TARGET: {url}")
        print(f"{'='*50}")
        print("⚠️  ETHICAL WARNING:")
        print("   Only scan systems you own or have written authorization to test.")
        print("   Unauthorized scanning is illegal and unethical.\n")
        confirm = input("Do you confirm you are authorized to scan this target? (yes/no): ")
        return confirm.lower() == "yes"