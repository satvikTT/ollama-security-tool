# llm/prompt_templates.py

class PromptTemplates:
    """Collection of prompt templates for security testing tasks"""

    @staticmethod
    def xss_payload_generation(field_type, detected_filters, html_context, target_context):
        return f"""
You are a security testing assistant working in an authorized lab environment.
Generate 5 XSS payloads for the following context:

- Input field type: {field_type}
- Observed filters: {detected_filters}
- HTML context: {html_context}
- Target context: {target_context}

Requirements:
1. Each payload must be unique and test different bypass techniques
2. Consider: HTML encoding, JavaScript events, filter evasion
3. Return ONLY a JSON array with 'payload' and 'technique' keys
4. No explanation, just the JSON array

Example format:
[
  {{"payload": "<script>alert(1)</script>", "technique": "Basic script tag"}},
  {{"payload": "<img src=x onerror=alert(1)>", "technique": "Image error event"}}
]
"""

    @staticmethod
    def sqli_payload_generation(db_type, param_name, observed_behavior):
        return f"""
You are a security testing assistant working in an authorized lab environment.
Generate 5 SQL injection payloads for:

- Database type: {db_type}
- Input parameter: {param_name}
- Application behavior: {observed_behavior}

Generate payloads testing:
1. Boolean-based blind injection
2. Time-based blind injection
3. Union-based injection
4. Error-based injection
5. Stacked queries

Return ONLY a JSON array with 'payload', 'type', and 'expected_behavior' fields.
No explanation, just the JSON array.

Example format:
[
  {{"payload": "' OR 1=1--", "type": "Boolean-based", "expected_behavior": "Returns all rows"}}
]
"""

    @staticmethod
    def cmdi_payload_generation(os_type, param_name):
        return f"""
You are a security testing assistant working in an authorized lab environment.
Generate 5 command injection payloads for:

- Operating System: {os_type}
- Input parameter: {param_name}

Return ONLY a JSON array with 'payload', 'type', and 'expected_behavior' fields.
No explanation, just the JSON array.

Example format:
[
  {{"payload": "; whoami", "type": "Basic injection", "expected_behavior": "Returns current user"}}
]
"""

    @staticmethod
    def result_interpretation(vulnerability_type, payload, response_snippet):
        return f"""
You are a security analyst. Analyze this vulnerability test result:

- Vulnerability Type: {vulnerability_type}
- Payload Used: {payload}
- Response Snippet: {response_snippet}

Answer these questions:
1. Was the payload successful? (yes/no)
2. Confidence level? (high/medium/low)
3. Why do you think so?
4. Is this a false positive? (yes/no)

Return ONLY a JSON object with keys: 'successful', 'confidence', 'reasoning', 'false_positive'
"""

    @staticmethod
    def risk_assessment(vulnerability_type, target_url, payload, evidence):
        return f"""
You are a GRC security analyst. Assess the risk of this finding:

- Vulnerability: {vulnerability_type}
- Target: {target_url}
- Payload: {payload}
- Evidence: {evidence}

Provide:
1. CVSS Score (0-10)
2. Severity (Critical/High/Medium/Low)
3. Business Impact (1-2 sentences)
4. Recommended fix (1-2 sentences)

Return ONLY a JSON object with keys: 'cvss_score', 'severity', 'business_impact', 'recommendation'
"""