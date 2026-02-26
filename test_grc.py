# test_grc.py
from grc.risk_assessor import RiskAssessor
from grc.compliance_mapper import ComplianceMapper

# Sample findings from our scanners
sample_findings = [
    {
        "type": "XSS - Reflected",
        "url": "http://localhost/dvwa/vulnerabilities/xss_r/",
        "payload": "<script>alert(1)</script>",
        "severity": "High",
        "evidence": "Payload reflected in response"
    },
    {
        "type": "SQL Injection - Error Based",
        "url": "http://localhost/dvwa/vulnerabilities/sqli/",
        "payload": "'",
        "severity": "Critical",
        "evidence": "SQL error detected: 'you have an error in your sql syntax'"
    },
    {
        "type": "Command Injection - Direct",
        "url": "http://localhost/dvwa/vulnerabilities/exec/",
        "payload": "127.0.0.1 & dir",
        "severity": "Critical",
        "evidence": "Command output pattern detected: 'windows'"
    },
    {
        "type": "Missing Security Header",
        "url": "http://localhost/dvwa/",
        "detail": "Content-Security-Policy",
        "severity": "Medium",
        "evidence": "Header not found in response"
    },
    {
        "type": "Sensitive File Exposed",
        "url": "http://localhost/phpmyadmin/",
        "detail": "/phpmyadmin/",
        "severity": "High",
        "evidence": "HTTP 200 returned for sensitive path"
    }
]

# ── Risk Assessment ──────────────────────────────
print("="*55)
print("        GRC RISK ASSESSMENT")
print("="*55)

assessor = RiskAssessor()
assessed = assessor.assess_all(sample_findings)

for i, result in enumerate(assessed, 1):
    print(f"\n[Finding #{i}]")
    print(f"  Type            : {result['type']}")
    print(f"  CVSS Score      : {result['cvss_score']}")
    print(f"  Severity        : {result['severity']}")
    print(f"  Business Impact : {result['business_impact']}")
    print(f"  Recommendation  : {result['recommendation']}")

# ── Compliance Mapping ───────────────────────────
print("\n" + "="*55)
print("        COMPLIANCE FRAMEWORK MAPPING")
print("="*55)

mapper = ComplianceMapper()
mappings = mapper.map_all_findings(sample_findings)

for mapping in mappings:
    mapper.print_mapping(mapping)

print("\n" + "="*55)
print("GRC Assessment Complete!")
print("="*55)
