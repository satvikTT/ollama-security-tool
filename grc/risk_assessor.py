# grc/risk_assessor.py
from llm.ollama_client import OllamaClient
from llm.prompt_templates import PromptTemplates
import json
import re

class RiskAssessor:
    """Calculates CVSS scores and assesses business risk using LLM"""

    # CVSS v3.1 data per vulnerability type
    # Vector format: CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}
    # AV=Attack Vector  AC=Attack Complexity  PR=Privileges Required  UI=User Interaction
    # S=Scope  C=Confidentiality  I=Integrity  A=Availability
    # Values: N=None/Network  L=Low/Local  H=High  A=Adjacent  P=Physical  R=Required  C=Changed  U=Unchanged
    CVSS_DATA = {
        "XSS - Reflected": {
            "score": 6.1, "severity": "Medium",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        },
        "XSS - Stored": {
            "score": 8.8, "severity": "High",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N"
        },
        "SQL Injection - Error Based": {
            "score": 9.8, "severity": "Critical",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "SQL Injection - Boolean Based": {
            "score": 9.8, "severity": "Critical",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "SQL Injection - Time Based Blind": {
            "score": 8.1, "severity": "High",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "Command Injection - Direct": {
            "score": 10.0, "severity": "Critical",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        },
        "Command Injection - Time Based Blind": {
            "score": 9.0, "severity": "Critical",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H"
        },
        "Missing Security Header": {
            "score": 5.3, "severity": "Medium",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        },
        "Sensitive File Exposed": {
            "score": 7.5, "severity": "High",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        },
        "Information Disclosure": {
            "score": 3.7, "severity": "Low",
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
        },
        "Directory Listing Enabled": {
            "score": 5.3, "severity": "Medium",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
        },
    }

    def __init__(self):
        self.llm = OllamaClient()
        self.templates = PromptTemplates()

    def get_cvss_score(self, vuln_type):
        """Get CVSS data (score, severity, vector) for vulnerability type"""
        for key, value in self.CVSS_DATA.items():
            if key.lower() in vuln_type.lower() or vuln_type.lower() in key.lower():
                return value
        return {"score": 5.0, "severity": "Medium", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"}

    def assess_business_risk(self, finding):
        """Use LLM to assess business impact of a finding"""
        prompt = self.templates.risk_assessment(
            vulnerability_type=finding.get("type", "Unknown"),
            target_url=finding.get("url", "Unknown"),
            payload=finding.get("payload", finding.get("detail", "N/A")),
            evidence=finding.get("evidence", "N/A")
        )

        response = self.llm.chat(prompt)

        if response is None:
            return self._default_assessment(finding)

        try:
            clean = response.strip()
            if "```json" in clean:
                clean = clean.split("```json")[1].split("```")[0].strip()
            elif "```" in clean:
                clean = clean.split("```")[1].split("```")[0].strip()
            if "{" in clean:
                start = clean.index("{")
                end = clean.rindex("}") + 1
                return json.loads(clean[start:end])
        except Exception:
            pass

        return self._default_assessment(finding)

    def _default_assessment(self, finding):
        """Fallback assessment when LLM is unavailable"""
        cvss = self.get_cvss_score(finding.get("type", ""))
        return {
            "cvss_score": cvss["score"],
            "cvss_vector": cvss["vector"],
            "severity": cvss["severity"],
            "business_impact": "This vulnerability could lead to unauthorized access or data exposure.",
            "recommendation": "Apply patches and follow OWASP remediation guidelines immediately."
        }

    def assess_finding(self, finding):
        """Full risk assessment for a single finding"""
        print(f"[GRC] Assessing risk for: {finding.get('type')}...")

        # Get CVSS data (score + vector)
        cvss = self.get_cvss_score(finding.get("type", ""))

        # Get LLM business risk assessment
        llm_assessment = self.assess_business_risk(finding)

        return {
            "type":          finding.get("type"),
            "url":           finding.get("url"),
            "cvss_score":    cvss["score"],
            "cvss_vector":   cvss["vector"],
            "severity":      cvss["severity"],
            "business_impact": llm_assessment.get("business_impact", "N/A"),
            "recommendation":  llm_assessment.get("recommendation", "N/A"),
            "payload":  finding.get("payload", finding.get("detail", "N/A")),
            "evidence": finding.get("evidence", "N/A")
        }

    def assess_all(self, findings):
        """Assess risk for all findings"""
        print(f"[GRC] Starting risk assessment for {len(findings)} finding(s)...")
        assessed = []
        for finding in findings:
            result = self.assess_finding(finding)
            assessed.append(result)
        print(f"[GRC] Risk assessment complete.")
        return assessed