# test_cmdi.py
import requests
from bs4 import BeautifulSoup
from scanners.cmdi_scanner import CMDiScanner

def login_dvwa(session):
    login_url = "http://localhost/dvwa/login.php"
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""
    response = session.post(login_url, data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }, allow_redirects=True)
    if "logout" in response.text.lower():
        print("[*] ✅ Login successful!")
        return True
    print("[*] ❌ Login failed.")
    return False

def set_security_level(session, level="low"):
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

# Setup session
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"})

print("[*] Logging into DVWA...")
if not login_dvwa(session):
    exit(1)

set_security_level(session, "low")

# Target DVWA Command Injection page
target = "http://localhost/dvwa/vulnerabilities/exec/"
print(f"[*] Target: {target}")

# Run CMDi Scanner
scanner = CMDiScanner(target_url=target, session=session)
findings = scanner.scan()

# Display Results
print("\n" + "="*50)
print("       CMDi SCAN RESULTS")
print("="*50)

if findings:
    for i, finding in enumerate(findings, 1):
        print(f"\n[Finding #{i}]")
        print(f"  Type      : {finding['type']}")
        print(f"  URL       : {finding['url']}")
        print(f"  Parameter : {finding['parameter']}")
        print(f"  Payload   : {finding['payload']}")
        print(f"  Severity  : {finding['severity']}")
        print(f"  Evidence  : {finding['evidence']}")
else:
    print("No Command Injection vulnerabilities found.")

print("\n" + "="*50)
