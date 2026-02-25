# test_misconfig.py
import requests
from bs4 import BeautifulSoup
from scanners.misconfig_scanner import MisconfigScanner

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

# Setup session
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"})

print("[*] Logging into DVWA...")
if not login_dvwa(session):
    exit(1)

# Target DVWA base
target = "http://localhost/dvwa/"
print(f"[*] Target: {target}")

# Run Misconfig Scanner
scanner = MisconfigScanner(target_url=target, session=session)
findings = scanner.scan()

# Display Results
print("\n" + "="*55)
print("        MISCONFIGURATION SCAN RESULTS")
print("="*55)

if findings:
    # Group by severity
    critical = [f for f in findings if f['severity'] == 'Critical']
    high     = [f for f in findings if f['severity'] == 'High']
    medium   = [f for f in findings if f['severity'] == 'Medium']
    low      = [f for f in findings if f['severity'] == 'Low']

    for severity, group in [("High", high), ("Medium", medium), ("Low", low)]:
        if group:
            print(f"\n--- {severity} Severity ({len(group)} findings) ---")
            for i, finding in enumerate(group, 1):
                print(f"\n  [{i}] {finding['type']}")
                print(f"      Detail   : {finding['detail']}")
                print(f"      Evidence : {finding['evidence']}")
else:
    print("No misconfigurations found.")

print(f"\nTotal Issues Found: {len(findings)}")
print("="*55)
