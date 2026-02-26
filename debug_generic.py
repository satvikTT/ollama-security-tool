# debug_generic.py
import requests
from bs4 import BeautifulSoup
from core.web_crawler import WebCrawler

target = "http://testphp.vulnweb.com"

session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner - Authorized Testing)"})

print(f"[*] Testing target: {target}")
print(f"[*] Checking if site is reachable...")

try:
    r = session.get(target, timeout=10)
    print(f"[*] Status: {r.status_code}")
except Exception as e:
    print(f"[*] ❌ Site unreachable: {e}")
    exit(1)

print(f"\n[*] Starting crawler...")
crawler = WebCrawler(target, session, max_pages=15)
forms = crawler.crawl()

print(f"\n[*] ===== CRAWL RESULTS =====")
print(f"[*] Pages visited: {len(crawler.pages_crawled)}")
print(f"[*] Forms found: {len(forms)}")

for i, form in enumerate(forms, 1):
    print(f"\n--- Form #{i} ---")
    print(f"  Page URL   : {form['page_url']}")
    print(f"  Action URL : {form['action_url']}")
    print(f"  Method     : {form['method'].upper()}")
    print(f"  Inputs     : {[(inp['name'], inp['type']) for inp in form['inputs']]}")

# Now manually test XSS on a known vulnerable URL
print(f"\n[*] ===== MANUAL XSS TEST =====")
test_url = "http://testphp.vulnweb.com/search.php?test=query"
payload = "<script>alert(1)</script>"

params = {"searchFor": payload, "goButton": "go"}
r = session.get("http://testphp.vulnweb.com/search.php", params=params)
print(f"[*] Status: {r.status_code}")
print(f"[*] Payload in response: {payload in r.text}")

# Test SQLi
print(f"\n[*] ===== MANUAL SQLi TEST =====")
sqli_payload = "'"
r2 = session.get("http://testphp.vulnweb.com/listproducts.php", params={"cat": sqli_payload})
print(f"[*] Status: {r2.status_code}")
errors = ["sql syntax", "mysql", "warning", "error"]
for e in errors:
    if e in r2.text.lower():
        print(f"[*] ✅ SQL error found: '{e}' in response!")
        break
else:
    print(f"[*] No SQL errors found")
    print(f"[*] Response snippet: {r2.text[500:800]}")
