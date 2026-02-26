# main.py
from core.orchestrator import Orchestrator

if __name__ == "__main__":
    print("Starting LLM Security Assessment Tool...")

    # Target DVWA base URL
    target = "http://localhost/dvwa"

    # Run full scan
    orchestrator = Orchestrator(
        target_url=target,
        dvwa_mode=True   # Auto-login to DVWA
    )

    findings = orchestrator.run()

    # Print all enriched findings
    print("\n" + "="*55)
    print("     FULL ENRICHED FINDINGS REPORT")
    print("="*55)

    for i, f in enumerate(findings, 1):
        print(f"\n[{i}] {f['type']}")
        print(f"     URL      : {f['url']}")
        print(f"     Severity : {f['severity']} | CVSS: {f.get('cvss_score', 'N/A')}")
        print(f"     Impact   : {f.get('business_impact', 'N/A')[:80]}...")
        if f.get("compliance", {}).get("owasp_top10"):
            owasp = f["compliance"]["owasp_top10"]
            print(f"     OWASP    : {owasp['id']} - {owasp['name']}")
