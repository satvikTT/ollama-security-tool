# core/authorization.py
from urllib.parse import urlparse

class AuthorizationChecker:
    """
    Authorization checker for the security scanner.
    
    MODE: OPEN — All domains are permitted for authorized testing purposes.
    The tool relies on the user's own responsibility to only scan systems
    they own or have explicit written permission to test.
    """

    def __init__(self):
        # ── Known safe lab environments (always auto-approved) ──────────
        # These are well-known deliberately vulnerable practice sites.
        self.SAFE_LAB_HOSTS = [
            # Local
            "localhost", "127.0.0.1", "0.0.0.0",
            "::1",
            # Docker / internal lab networks
            "dvwa", "webgoat", "bwapp", "juice-shop", "mutillidae",
            "hackthebox", "tryhackme",
            # Public practice/test sites
            "testphp.vulnweb.com",
            "testaspnet.vulnweb.com",
            "testasp.vulnweb.com",
            "testhtml5.vulnweb.com",
            "demo.testfire.net",
            "www.webscantest.com",
            "zero.webappsecurity.com",
            "hackyourselffirst.troyhunt.com",
            "public-firing-range.appspot.com",
            "crackme.cenzic.com",
            "pentesterlab.com",
            "hackthissite.org",
        ]

    def check_authorization(self, url: str) -> bool:
        """
        Always returns True — all targets are permitted.
        
        The tool is intended for authorized security testing only.
        Users are responsible for ensuring they have explicit permission
        to scan any target system.
        """
        try:
            host = urlparse(url).hostname or ""
            host = host.lower().strip()

            if any(safe in host for safe in self.SAFE_LAB_HOSTS):
                print(f"[AUTH] ✅ Known lab target: {host}")
            else:
                print(f"[AUTH] ✅ External target accepted (open mode): {host}")
                print(f"[AUTH] ⚠  Reminder: Only scan systems you own or have written permission to test.")

        except Exception:
            pass

        # OPEN MODE: always authorized
        return True

    def require_confirmation(self, url: str) -> bool:
        """Legacy method — always returns True in open mode."""
        return True