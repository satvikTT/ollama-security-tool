# database/models.py
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()

class ScanSession(Base):
    """Represents a complete scan session"""
    __tablename__ = "scan_sessions"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    target_url  = Column(String(500), nullable=False)
    scan_date   = Column(DateTime, default=datetime.utcnow)
    total_findings = Column(Integer, default=0)
    status      = Column(String(50), default="completed")
    duration_seconds = Column(Float, default=0.0)

    def __repr__(self):
        return f"<ScanSession id={self.id} target={self.target_url}>"


class Vulnerability(Base):
    """Represents a single vulnerability finding"""
    __tablename__ = "vulnerabilities"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    session_id      = Column(Integer, nullable=False)
    vuln_type       = Column(String(200), nullable=False)
    url             = Column(String(500), nullable=False)
    parameter       = Column(String(200), nullable=True)
    payload         = Column(Text, nullable=True)
    severity        = Column(String(50), nullable=False)
    cvss_score      = Column(Float, nullable=True)
    evidence        = Column(Text, nullable=True)
    business_impact = Column(Text, nullable=True)
    recommendation  = Column(Text, nullable=True)
    discovered_at   = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Vulnerability type={self.vuln_type} severity={self.severity}>"


class ComplianceMapping(Base):
    """Stores compliance framework mappings for findings"""
    __tablename__ = "compliance_mappings"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_id = Column(Integer, nullable=False)
    framework       = Column(String(100), nullable=False)
    control_id      = Column(String(100), nullable=True)
    control_name    = Column(String(200), nullable=True)
    description     = Column(Text, nullable=True)

    def __repr__(self):
        return f"<ComplianceMapping framework={self.framework} control={self.control_id}>"
