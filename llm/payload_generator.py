# llm/payload_generator.py
import json
import re
from llm.ollama_client import OllamaClient
from llm.prompt_templates import PromptTemplates

class LLMPayloadGenerator:
    """Uses Ollama LLM to generate adaptive security testing payloads"""

    def __init__(self):
        self.llm = OllamaClient()
        self.templates = PromptTemplates()
        self.generated_payloads = []

    def _parse_json_response(self, response):
        """Safely parse JSON from LLM response - handles None/truncated/malformed responses"""
        # Guard against None response (e.g. Ollama not running)
        if response is None:
            print("[PAYLOAD] Warning: Received None response from LLM")
            return None

        try:
            clean = response.strip()

            # Remove markdown code blocks if present
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0].strip()
            elif "```" in clean:
                clean = clean.split("```")[1].split("```")[0].strip()

            # --- Attempt 1: Full clean parse ---
            try:
                if "[" in clean:
                    start = clean.index("[")
                    end = clean.rindex("]") + 1
                    return json.loads(clean[start:end])
                elif "{" in clean:
                    start = clean.index("{")
                    end = clean.rindex("}") + 1
                    return json.loads(clean[start:end])
            except Exception:
                pass

            # --- Attempt 2: Extract individual JSON objects ---
            objects = []
            pattern = r'\{[^{}]*\}'
            matches = re.findall(pattern, clean, re.DOTALL)
            for match in matches:
                try:
                    fixed = match.replace("\\'", "'")
                    fixed = re.sub(r'[\x00-\x1f\x7f]', '', fixed)
                    obj = json.loads(fixed)
                    objects.append(obj)
                except Exception:
                    continue

            if objects:
                return objects

            print(f"[PAYLOAD] Warning: Could not parse JSON response")
            print(f"[PAYLOAD] Raw response: {response[:200]}")
            return None

        except Exception as e:
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
