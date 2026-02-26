# database/db_manager.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, ScanSession, Vulnerability, ComplianceMapping
from datetime import datetime
import os

class DatabaseManager:
    """Manages all database operations for the security tool"""

    def __init__(self, db_path="database/security_tool.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.engine = create_engine(f"sqlite:///{db_path}", echo=False)
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
        print(f"[DB] Database initialized at: {db_path}")

    def create_scan_session(self, target_url):
        """Create a new scan session and return its ID"""
        scan = ScanSession(
            target_url=target_url,
            scan_date=datetime.utcnow(),
            status="running"
        )
        self.session.add(scan)
        self.session.commit()
        print(f"[DB] Scan session created: ID={scan.id}")
        return scan.id

    def save_finding(self, session_id, finding, risk_assessment=None):
        """Save a vulnerability finding to the database"""
        vuln = Vulnerability(
            session_id      = session_id,
            vuln_type       = finding.get("type", "Unknown"),
            url             = finding.get("url", ""),
            parameter       = finding.get("parameter", finding.get("detail", "")),
            payload         = finding.get("payload", ""),
            severity        = finding.get("severity", "Unknown"),
            cvss_score      = risk_assessment.get("cvss_score") if risk_assessment else None,
            evidence        = finding.get("evidence", ""),
            business_impact = risk_assessment.get("business_impact") if risk_assessment else None,
            recommendation  = risk_assessment.get("recommendation") if risk_assessment else None,
            discovered_at   = datetime.utcnow()
        )
        self.session.add(vuln)
        self.session.commit()
        return vuln.id

    def save_compliance_mapping(self, vulnerability_id, mapping):
        """Save compliance framework mappings for a finding"""
        frameworks = {
            "owasp_top10": mapping.get("owasp_top10"),
            "iso27001":    mapping.get("iso27001"),
            "nist_csf":    mapping.get("nist_csf")
        }

        for framework_name, data in frameworks.items():
            if data:
                cm = ComplianceMapping(
                    vulnerability_id = vulnerability_id,
                    framework        = framework_name,
                    control_id       = data.get("id") or data.get("control_id") or data.get("category_id", ""),
                    control_name     = data.get("name") or data.get("control_name") or data.get("category_name", ""),
                    description      = data.get("description", "")
                )
                self.session.add(cm)
        self.session.commit()

    def complete_scan_session(self, session_id, total_findings, duration):
        """Mark scan session as completed"""
        scan = self.session.query(ScanSession).filter_by(id=session_id).first()
        if scan:
            scan.status = "completed"
            scan.total_findings = total_findings
            scan.duration_seconds = duration
            self.session.commit()
            print(f"[DB] Scan session {session_id} completed: {total_findings} findings")

    def get_all_sessions(self):
        """Get all scan sessions"""
        return self.session.query(ScanSession).all()

    def get_findings_by_session(self, session_id):
        """Get all findings for a scan session"""
        return self.session.query(Vulnerability).filter_by(session_id=session_id).all()

    def get_all_findings(self):
        """Get all findings across all sessions"""
        return self.session.query(Vulnerability).all()

    def print_summary(self, session_id):
        """Print a summary of findings for a session"""
        findings = self.get_findings_by_session(session_id)
        print(f"\n[DB] === Session {session_id} Summary ===")
        print(f"[DB] Total Findings: {len(findings)}")

        severity_counts = {}
        for f in findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        for severity, count in sorted(severity_counts.items()):
            print(f"[DB]   {severity}: {count}")
