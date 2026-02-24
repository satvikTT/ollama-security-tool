# llm/payload_generator.py
import json
from llm.ollama_client import OllamaClient
from llm.prompt_templates import PromptTemplates

class LLMPayloadGenerator:
    """Uses Ollama LLM to generate adaptive security testing payloads"""

    def __init__(self):
        self.llm = OllamaClient()
        self.templates = PromptTemplates()
        self.generated_payloads = []

    def _parse_json_response(self, response):
        """Safely parse JSON from LLM response"""
        try:
            # Clean response - remove markdown code blocks if present
            clean = response.strip()
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0].strip()
            elif "```" in clean:
                clean = clean.split("```")[1].split("```")[0].strip()
            return json.loads(clean)
        except json.JSONDecodeError as e:
            print(f"[PAYLOAD] Warning: Could not parse JSON response: {e}")
            print(f"[PAYLOAD] Raw response: {response[:200]}")
            return None

    def generate_xss_payloads(self, field_type="text", detected_filters="none",
                               html_context="input field", target_context="login form"):
        """Generate XSS payloads using LLM"""
        print(f"[PAYLOAD] Generating XSS payloads for {field_type} field...")
        prompt = self.templates.xss_payload_generation(
            field_type, detected_filters, html_context, target_context
        )
        response = self.llm.chat(prompt)
        payloads = self._parse_json_response(response)
        if payloads:
            print(f"[PAYLOAD] ✅ Generated {len(payloads)} XSS payloads")
            self.generated_payloads.extend(payloads)
        return payloads or []

    def generate_sqli_payloads(self, db_type="MySQL", param_name="id",
                                observed_behavior="returns user data"):
        """Generate SQL injection payloads using LLM"""
        print(f"[PAYLOAD] Generating SQLi payloads for parameter '{param_name}'...")
        prompt = self.templates.sqli_payload_generation(db_type, param_name, observed_behavior)
        response = self.llm.chat(prompt)
        payloads = self._parse_json_response(response)
        if payloads:
            print(f"[PAYLOAD] ✅ Generated {len(payloads)} SQLi payloads")
            self.generated_payloads.extend(payloads)
        return payloads or []

    def generate_cmdi_payloads(self, os_type="Linux", param_name="ip"):
        """Generate command injection payloads using LLM"""
        print(f"[PAYLOAD] Generating CMDi payloads for parameter '{param_name}'...")
        prompt = self.templates.cmdi_payload_generation(os_type, param_name)
        response = self.llm.chat(prompt)
        payloads = self._parse_json_response(response)
        if payloads:
            print(f"[PAYLOAD] ✅ Generated {len(payloads)} CMDi payloads")
            self.generated_payloads.extend(payloads)
        return payloads or []

    def interpret_result(self, vulnerability_type, payload, response_snippet):
        """Use LLM to interpret scan results and reduce false positives"""
        print(f"[PAYLOAD] Interpreting result for {vulnerability_type}...")
        prompt = self.templates.result_interpretation(
            vulnerability_type, payload, response_snippet
        )
        response = self.llm.chat(prompt)
        return self._parse_json_response(response)