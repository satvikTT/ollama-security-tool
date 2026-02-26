# reporting/report_generator.py
import os
from datetime import datetime
from database.db_manager import DatabaseManager

class ReportGenerator:
    """Generates professional HTML security assessment reports"""

    def __init__(self, session_id=None):
        self.db = DatabaseManager()
        self.session_id = session_id
        os.makedirs("reports", exist_ok=True)

    def _get_severity_color(self, severity):
        colors = {
            "Critical": "#dc2626",
            "High":     "#ea580c",
            "Medium":   "#d97706",
            "Low":      "#65a30d",
        }
        return colors.get(severity, "#6b7280")

    def _get_severity_bg(self, severity):
        colors = {
            "Critical": "#fef2f2",
            "High":     "#fff7ed",
            "Medium":   "#fffbeb",
            "Low":      "#f7fee7",
        }
        return colors.get(severity, "#f9fafb")

    def _count_by_severity(self, findings):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            sev = f.severity if hasattr(f, 'severity') else f.get('severity', 'Low')
            if sev in counts:
                counts[sev] += 1
        return counts

    def generate_html(self, findings=None, scan_info=None):
        """Generate a full HTML security report"""

        # Load from DB if no findings passed
        if findings is None and self.session_id:
            findings = self.db.get_findings_by_session(self.session_id)

        if not findings:
            print("[REPORT] No findings to report.")
            return None

        counts = self._count_by_severity(findings)
        total  = len(findings)
        now    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        target = scan_info.get("target", "Unknown") if scan_info else "DVWA Lab"
        duration = scan_info.get("duration", "N/A") if scan_info else "N/A"

        # Build findings HTML
        findings_html = ""
        for i, f in enumerate(findings, 1):
            # Handle both DB objects and dicts
            if hasattr(f, 'vuln_type'):
                vuln_type  = f.vuln_type
                url        = f.url
                severity   = f.severity
                cvss       = f.cvss_score or "N/A"
                evidence   = f.evidence or "N/A"
                payload    = f.payload or "N/A"
                impact     = f.business_impact or "N/A"
                recommend  = f.recommendation or "N/A"
            else:
                vuln_type  = f.get("type", "Unknown")
                url        = f.get("url", "N/A")
                severity   = f.get("severity", "Medium")
                cvss       = f.get("cvss_score", "N/A")
                evidence   = f.get("evidence", "N/A")
                payload    = f.get("payload", f.get("detail", "N/A"))
                impact     = f.get("business_impact", "N/A")
                recommend  = f.get("recommendation", "N/A")

            color = self._get_severity_color(severity)
            bg    = self._get_severity_bg(severity)

            findings_html += f"""
            <div class="finding" style="border-left: 5px solid {color}; background: {bg};">
                <div class="finding-header">
                    <span class="finding-num">#{i}</span>
                    <span class="finding-title">{vuln_type}</span>
                    <span class="badge" style="background:{color};">{severity}</span>
                    <span class="cvss">CVSS: {cvss}</span>
                </div>
                <div class="finding-body">
                    <div class="finding-row"><b>URL:</b> <code>{url}</code></div>
                    <div class="finding-row"><b>Payload/Detail:</b> <code>{payload}</code></div>
                    <div class="finding-row"><b>Evidence:</b> {evidence}</div>
                    <div class="finding-row impact"><b>💼 Business Impact:</b> {impact}</div>
                    <div class="finding-row recommend"><b>🔧 Recommendation:</b> {recommend}</div>
                </div>
            </div>
            """

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f1f5f9; color: #1e293b; }}

  .header {{ background: linear-gradient(135deg, #1e293b, #334155);
             color: white; padding: 40px; text-align: center; }}
  .header h1 {{ font-size: 2.2em; margin-bottom: 8px; }}
  .header p  {{ color: #94a3b8; font-size: 1em; }}

  .container {{ max-width: 1100px; margin: 30px auto; padding: 0 20px; }}

  .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr);
                gap: 16px; margin-bottom: 30px; }}
  .meta-card {{ background: white; border-radius: 10px; padding: 20px;
                text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .meta-card .num {{ font-size: 2em; font-weight: bold; }}
  .meta-card .label {{ color: #64748b; font-size: 0.85em; margin-top: 4px; }}

  .section-title {{ font-size: 1.3em; font-weight: bold; margin: 30px 0 15px;
                    padding-bottom: 8px; border-bottom: 2px solid #e2e8f0; }}

  .severity-bar {{ display: grid; grid-template-columns: repeat(4,1fr);
                   gap: 12px; margin-bottom: 30px; }}
  .sev-card {{ background: white; border-radius: 10px; padding: 16px;
               text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
  .sev-card .sev-num {{ font-size: 2.5em; font-weight: bold; }}
  .sev-card .sev-label {{ font-size: 0.85em; color: #64748b; }}

  .finding {{ background: white; border-radius: 10px; margin-bottom: 16px;
              padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .finding-header {{ display: flex; align-items: center; gap: 12px;
                     margin-bottom: 14px; flex-wrap: wrap; }}
  .finding-num {{ background: #e2e8f0; color: #475569; border-radius: 50%;
                  width: 28px; height: 28px; display: flex; align-items: center;
                  justify-content: center; font-size: 0.8em; font-weight: bold; }}
  .finding-title {{ font-weight: bold; font-size: 1.05em; flex: 1; }}
  .badge {{ color: white; padding: 3px 12px; border-radius: 20px;
            font-size: 0.8em; font-weight: bold; }}
  .cvss {{ background: #1e293b; color: white; padding: 3px 12px;
           border-radius: 20px; font-size: 0.8em; }}

  .finding-row {{ margin-bottom: 8px; font-size: 0.92em; line-height: 1.5; }}
  .finding-row code {{ background: #f1f5f9; padding: 2px 8px; border-radius: 4px;
                       font-size: 0.9em; word-break: break-all; }}
  .impact {{ background: #fff7ed; padding: 8px 12px; border-radius: 6px; }}
  .recommend {{ background: #f0fdf4; padding: 8px 12px; border-radius: 6px; }}

  .compliance-table {{ width: 100%; border-collapse: collapse; background: white;
                       border-radius: 10px; overflow: hidden;
                       box-shadow: 0 2px 8px rgba(0,0,0,0.06); }}
  .compliance-table th {{ background: #1e293b; color: white; padding: 12px 16px;
                          text-align: left; font-size: 0.9em; }}
  .compliance-table td {{ padding: 11px 16px; border-bottom: 1px solid #e2e8f0;
                          font-size: 0.88em; }}
  .compliance-table tr:hover td {{ background: #f8fafc; }}

  .footer {{ text-align: center; padding: 30px; color: #94a3b8; font-size: 0.85em; }}
</style>
</head>
<body>

<div class="header">
  <h1>🔒 Security Assessment Report</h1>
  <p>LLM-Orchestrated Web Vulnerability Assessment with GRC Integration</p>
  <p style="margin-top:10px;">Generated: {now} &nbsp;|&nbsp; Target: {target}</p>
</div>

<div class="container">

  <!-- Meta Cards -->
  <div class="meta-grid" style="margin-top:30px;">
    <div class="meta-card">
      <div class="num" style="color:#3b82f6;">{total}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="meta-card">
      <div class="num" style="color:#dc2626;">{counts['Critical']}</div>
      <div class="label">Critical</div>
    </div>
    <div class="meta-card">
      <div class="num" style="color:#ea580c;">{counts['High']}</div>
      <div class="label">High</div>
    </div>
    <div class="meta-card">
      <div class="num" style="color:#6b7280;">{duration}s</div>
      <div class="label">Scan Duration</div>
    </div>
  </div>

  <!-- Severity Breakdown -->
  <div class="section-title">📊 Severity Breakdown</div>
  <div class="severity-bar">
    <div class="sev-card">
      <div class="sev-num" style="color:#dc2626;">{counts['Critical']}</div>
      <div class="sev-label">Critical</div>
    </div>
    <div class="sev-card">
      <div class="sev-num" style="color:#ea580c;">{counts['High']}</div>
      <div class="sev-label">High</div>
    </div>
    <div class="sev-card">
      <div class="sev-num" style="color:#d97706;">{counts['Medium']}</div>
      <div class="sev-label">Medium</div>
    </div>
    <div class="sev-card">
      <div class="sev-num" style="color:#65a30d;">{counts['Low']}</div>
      <div class="sev-label">Low</div>
    </div>
  </div>

  <!-- Findings -->
  <div class="section-title">🔍 Vulnerability Findings</div>
  {findings_html}

  <!-- Compliance Table -->
  <div class="section-title">📋 Compliance Framework Mapping</div>
  <table class="compliance-table">
    <thead>
      <tr>
        <th>#</th>
        <th>Vulnerability</th>
        <th>Severity</th>
        <th>OWASP Top 10</th>
        <th>ISO 27001</th>
        <th>NIST CSF</th>
      </tr>
    </thead>
    <tbody>
"""

        # Build compliance table rows
        from grc.compliance_mapper import ComplianceMapper
        mapper = ComplianceMapper()

        for i, f in enumerate(findings, 1):
            if hasattr(f, 'vuln_type'):
                finding_dict = {"type": f.vuln_type, "severity": f.severity}
            else:
                finding_dict = f

            mapping = mapper.map_finding(finding_dict)
            severity = finding_dict.get("severity") if isinstance(finding_dict, dict) else f.severity
            color = self._get_severity_color(severity)

            owasp = mapping.get("owasp_top10")
            iso   = mapping.get("iso27001")
            nist  = mapping.get("nist_csf")

            owasp_text = f"{owasp['id']} - {owasp['name']}" if owasp else "N/A"
            iso_text   = f"{iso['control_id']} - {iso['control_name']}" if iso else "N/A"
            nist_text  = f"{nist['function']} > {nist['category_name']}" if nist else "N/A"

            vuln_name = finding_dict.get("type") if isinstance(finding_dict, dict) else f.vuln_type

            html += f"""
      <tr>
        <td>{i}</td>
        <td>{vuln_name}</td>
        <td><span style="color:{color};font-weight:bold;">{severity}</span></td>
        <td>{owasp_text}</td>
        <td>{iso_text}</td>
        <td>{nist_text}</td>
      </tr>"""

        html += """
    </tbody>
  </table>

  <div class="footer" style="margin-top:40px;">
    <p>Generated by LLM-Orchestrated Security Assessment Tool</p>
    <p>⚠️ This report is for authorized security testing only. Handle with confidentiality.</p>
  </div>

</div>
</body>
</html>"""

        # Save report
        filename = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[REPORT] ✅ Report saved: {filename}")
        return filename
