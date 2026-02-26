# grc/compliance_mapper.py
import json
import os

class ComplianceMapper:
    """Maps vulnerabilities to compliance frameworks (OWASP, ISO 27001, NIST CSF)"""

    def __init__(self):
        base = os.path.join(os.path.dirname(__file__), "frameworks")
        self.owasp   = self._load(os.path.join(base, "owasp_top10.json"))
        self.iso27001 = self._load(os.path.join(base, "iso27001.json"))
        self.nist    = self._load(os.path.join(base, "nist_csf.json"))

    def _load(self, path):
        """Load a JSON framework file"""
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[GRC] Warning: Could not load framework file {path}: {e}")
            return {"mappings": {}}

    def _get_vuln_key(self, vuln_type):
        """Extract base vulnerability type from finding type string"""
        vuln_type = vuln_type.lower()
        if "xss" in vuln_type:
            return "XSS"
        elif "sql" in vuln_type:
            return "SQL Injection"
        elif "command" in vuln_type or "cmdi" in vuln_type:
            return "Command Injection"
        elif "missing security header" in vuln_type:
            return "Missing Security Header"
        elif "sensitive file" in vuln_type:
            return "Sensitive File Exposed"
        elif "information disclosure" in vuln_type:
            return "Information Disclosure"
        elif "directory listing" in vuln_type:
            return "Directory Listing Enabled"
        return None

    def map_finding(self, finding):
        """Map a single finding to all compliance frameworks"""
        vuln_key = self._get_vuln_key(finding.get("type", ""))

        mapping = {
            "vulnerability_type": finding.get("type"),
            "owasp_top10": None,
            "iso27001": None,
            "nist_csf": None
        }

        if not vuln_key:
            return mapping

        # OWASP mapping
        if vuln_key in self.owasp.get("mappings", {}):
            mapping["owasp_top10"] = self.owasp["mappings"][vuln_key]

        # ISO 27001 mapping
        if vuln_key in self.iso27001.get("mappings", {}):
            mapping["iso27001"] = self.iso27001["mappings"][vuln_key]

        # NIST CSF mapping
        if vuln_key in self.nist.get("mappings", {}):
            mapping["nist_csf"] = self.nist["mappings"][vuln_key]

        return mapping

    def map_all_findings(self, findings):
        """Map all findings to compliance frameworks"""
        return [self.map_finding(f) for f in findings]

    def print_mapping(self, mapping):
        """Pretty print a compliance mapping"""
        print(f"\n  Vulnerability : {mapping['vulnerability_type']}")

        if mapping["owasp_top10"]:
            o = mapping["owasp_top10"]
            print(f"  OWASP Top 10  : {o['id']} - {o['name']}")

        if mapping["iso27001"]:
            i = mapping["iso27001"]
            print(f"  ISO 27001     : {i['control_id']} - {i['control_name']}")

        if mapping["nist_csf"]:
            n = mapping["nist_csf"]
            print(f"  NIST CSF      : {n['function']} > {n['category_name']}")
