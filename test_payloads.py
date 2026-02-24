# test_payloads.py
from llm.payload_generator import LLMPayloadGenerator

gen = LLMPayloadGenerator()

# Test XSS payload generation
print("\n========== XSS Payloads ==========")
xss = gen.generate_xss_payloads(
    field_type="text input",
    detected_filters="none",
    html_context="search box",
    target_context="DVWA low security"
)
for p in xss:
    print(f"  Technique: {p.get('technique')}")
    print(f"  Payload  : {p.get('payload')}\n")

# Test SQLi payload generation
print("\n========== SQLi Payloads ==========")
sqli = gen.generate_sqli_payloads(
    db_type="MySQL",
    param_name="id",
    observed_behavior="returns user information"
)
for p in sqli:
    print(f"  Type    : {p.get('type')}")
    print(f"  Payload : {p.get('payload')}")
    print(f"  Expected: {p.get('expected_behavior')}\n")

# Test CMDi payload generation
print("\n========== CMDi Payloads ==========")
cmdi = gen.generate_cmdi_payloads(
    os_type="Linux",
    param_name="ip"
)
for p in cmdi:
    print(f"  Type    : {p.get('type')}")
    print(f"  Payload : {p.get('payload')}")
    print(f"  Expected: {p.get('expected_behavior')}\n")

# Test result interpretation
print("\n========== Result Interpretation ==========")
interpretation = gen.interpret_result(
    vulnerability_type="XSS",
    payload="<script>alert(1)</script>",
    response_snippet="<input value='<script>alert(1)</script>'>"
)
print(f"  Result: {interpretation}")