# test_xss.py
import requests
from bs4 import BeautifulSoup
from scanners.xss_scanner import XSSScanner

def login_dvwa(session):
    """Login to DVWA handling CSRF token"""
    login_url = "http://localhost/dvwa/login.php"
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""
    print(f"[*] CSRF Token: {token[:20]}...")

    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }
    response = session.post(login_url, data=login_data, allow_redirects=True)

    if "logout" in response.text.lower() or "welcome" in response.text.lower():
        print("[*] ✅ Login successful!")
        return True
    else:
        print("[*] ❌ Login failed.")
        return False

def set_security_level(session, level="low"):
    """Set DVWA security level via settings page (avoids cookie conflict)"""
    security_url = "http://localhost/dvwa/security.php"
    resp = session.get(security_url)
    soup = BeautifulSoup(resp.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""
    session.post(security_url, data={
        "security": level,
        "seclev_submit": "Submit",
        "user_token": token
    })
    print(f"[*] Security level set to: {level}")

# Create session
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"
})

print("[*] Logging into DVWA...")
success = login_dvwa(session)

if not success:
    print("[!] Cannot proceed without login. Make sure DVWA is running.")
    exit(1)

# Set security level properly (no cookie conflict)
set_security_level(session, "low")

# Target the XSS reflected page in DVWA
target = "http://localhost/dvwa/vulnerabilities/xss_r/"
print(f"[*] Target: {target}")

# Run XSS Scanner
scanner = XSSScanner(target_url=target, session=session)
findings = scanner.scan()

# Display Results
print("\n" + "="*50)
print("         XSS SCAN RESULTS")
print("="*50)

if findings:
    for i, finding in enumerate(findings, 1):
        print(f"\n[Finding #{i}]")
        print(f"  Type     : {finding['type']}")
        print(f"  URL      : {finding['url']}")
        print(f"  Payload  : {finding['payload']}")
        print(f"  Severity : {finding['severity']}")
        print(f"  Evidence : {finding['evidence']}")
else:
    print("No XSS vulnerabilities found.")

print("\n" + "="*50)
