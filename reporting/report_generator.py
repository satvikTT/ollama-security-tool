# reporting/report_generator.py
import os
from datetime import datetime
from database.db_manager import DatabaseManager
from database.models import ComplianceMapping

class ReportGenerator:
    """
    Cyberpunk-themed HTML security report dashboard.
    Reads findings + compliance mappings directly from SQLite via
    DatabaseManager and the ComplianceMapping SQLAlchemy model.
    """

    def __init__(self, session_id=None):
        self.session_id = session_id
        self.db = DatabaseManager()
        os.makedirs("reports", exist_ok=True)

    def _sev_color(self, sev):
        return {"Critical":"#ff2d55","High":"#ff9500",
                "Medium":"#ffd60a","Low":"#00ff88"}.get(sev,"#a0f0d0")

    def _sev_glow(self, sev):
        return {"Critical":"rgba(255,45,85,0.25)","High":"rgba(255,149,0,0.25)",
                "Medium":"rgba(255,214,10,0.2)","Low":"rgba(0,255,136,0.15)"
                }.get(sev,"rgba(0,255,136,0.1)")

    def _get_compliance(self, vuln_id, short=False):
        """
        Query ComplianceMapping table directly.
        db_manager.save_compliance_mapping() stores frameworks as:
            "owasp_top10", "iso27001", "nist_csf"
        Returns (owasp_str, iso_str, nist_str)
        """
        try:
            rows = self.db.session.query(ComplianceMapping).filter_by(
                vulnerability_id=vuln_id
            ).all()
        except Exception as e:
            print(f"[REPORT] Compliance query failed for vuln_id={vuln_id}: {e}")
            return "—", "—", "—"

        owasp = iso = nist = "—"
        for row in rows:
            fw  = (row.framework or "").lower()
            cid = (row.control_id   or "").strip()
            cn  = (row.control_name or "").strip()
            val = cid if short else (f"{cid} — {cn}" if cn else cid)
            if not val:
                val = "—"
            if "owasp" in fw: owasp = val
            if "iso"   in fw: iso   = val
            if "nist"  in fw: nist  = val

        return owasp, iso, nist

    def generate_html(self, scan_info=None):
        findings  = self.db.get_findings_by_session(self.session_id)
        target    = (scan_info or {}).get("target", "Unknown")
        generated = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")

        total    = len(findings)
        critical = sum(1 for f in findings if f.severity == "Critical")
        high     = sum(1 for f in findings if f.severity == "High")
        medium   = sum(1 for f in findings if f.severity == "Medium")
        low      = sum(1 for f in findings if f.severity == "Low")

        # ── Finding cards ──────────────────────────────
        if not findings:
            cards_html = '<div class="no-findings">// NO VULNERABILITIES DETECTED</div>'
        else:
            cards = []
            for i, f in enumerate(findings, 1):
                col     = self._sev_color(f.severity)
                glow    = self._sev_glow(f.severity)
                cvss    = str(f.cvss_score) if f.cvss_score else "N/A"
                vector  = f.cvss_vector if f.cvss_vector else "N/A"
                param   = f.parameter       or "—"
                payload = f.payload         or "—"
                evidence= f.evidence        or "—"
                impact  = f.business_impact or "No impact analysis recorded."
                rec     = f.recommendation  or "No recommendation recorded."
                owasp, iso, nist = self._get_compliance(f.id)

                cards.append(f"""
      <div class="card" style="border-left-color:{col};--glow:{glow};">
        <div class="card-head">
          <span class="idx" style="color:{col};border-color:{col};">#{i:02d}</span>
          <span class="vtitle">{f.vuln_type}</span>
          <div class="badges">
            <span class="bsev" style="color:{col};border-color:{col};box-shadow:0 0 8px {glow};">{f.severity}</span>
            <span class="bcvss">CVSS&nbsp;{cvss}</span>
          </div>
        </div>
        <div class="cvss-vector-row">
          <span class="vector-label">// CVSS VECTOR</span>
          <code class="vector-string">{vector}</code>
        </div>
        <div class="card-body">
          <div class="frow"><span class="flabel">// URL</span><code>{f.url}</code></div>
          <div class="frow"><span class="flabel">// PARAMETER</span><code>{param}</code></div>
          <div class="frow"><span class="flabel">// PAYLOAD</span><code style="color:#ffd60a;">{payload}</code></div>
          <div class="frow"><span class="flabel">// EVIDENCE</span><span class="fval">{evidence}</span></div>
          <div class="panels">
            <div class="panel-impact">
              <div class="plabel" style="color:#ff9500;">⚠ BUSINESS IMPACT</div>
              <div class="ptext">{impact}</div>
            </div>
            <div class="panel-rec">
              <div class="plabel" style="color:#00ff88;">✓ REMEDIATION</div>
              <div class="ptext">{rec}</div>
            </div>
          </div>
          <div class="comp-row">
            <div class="comp-cell"><span class="clabel">// OWASP TOP 10</span><span class="cval">{owasp}</span></div>
            <div class="comp-cell"><span class="clabel">// ISO 27001</span><span class="cval">{iso}</span></div>
            <div class="comp-cell"><span class="clabel">// NIST CSF 2.0</span><span class="cval">{nist}</span></div>
          </div>
        </div>
      </div>""")
            cards_html = "\n".join(cards)

        # ── Compliance matrix table ────────────────────
        trows = []
        for i, f in enumerate(findings, 1):
            col = self._sev_color(f.severity)
            owasp, iso, nist = self._get_compliance(f.id, short=True)
            trows.append(f"""
          <tr>
            <td class="tmono">#{i:02d}</td>
            <td>{f.vuln_type}</td>
            <td><span style="color:{col};font-weight:700;">{f.severity}</span></td>
            <td class="tval">{owasp}</td>
            <td class="tval">{iso}</td>
            <td class="tval">{nist}</td>
          </tr>""")
        table_rows = "\n".join(trows)

        bt = max(total, 1)
        cw, hw, mw, lw = (round(x/bt*100) for x in [critical, high, medium, low])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Report — {target}</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;700;900&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{{--g:#00ff88;--c:#00e5ff;--r:#ff2d55;--o:#ff9500;--y:#ffd60a;
    --bg:#020d0a;--bg2:#041410;--bg3:#061a15;--pn:#071f19;
    --b1:#0a3528;--b2:#0f4a38;--tx:#a0f0d0;--tx2:#5a9980;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{font-family:'Rajdhani',sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;}}
  body::before{{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,
      rgba(0,255,136,0.012) 2px,rgba(0,255,136,0.012) 4px);}}

  .hdr{{background:var(--bg2);border-bottom:1px solid var(--b2);padding:26px 40px;position:relative;overflow:hidden;}}
  .hdr::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
    background:linear-gradient(90deg,transparent,var(--g),var(--c),var(--g),transparent);opacity:.5;}}
  .hdr-top{{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;}}
  .hdr-badge{{font-family:'Share Tech Mono',monospace;font-size:.76em;color:var(--tx2);
    border:1px solid var(--b2);padding:4px 12px;letter-spacing:.1em;}}
  .hdr-title{{font-family:'Orbitron',monospace;font-size:1.6em;font-weight:900;color:var(--g);
    text-shadow:0 0 20px rgba(0,255,136,.4);letter-spacing:.12em;text-align:center;flex:1;}}
  .hdr-ts{{font-family:'Share Tech Mono',monospace;font-size:.74em;color:var(--tx2);
    text-align:right;letter-spacing:.04em;line-height:1.7;}}
  .hdr-meta{{display:flex;justify-content:center;flex-wrap:wrap;gap:28px;
    font-family:'Share Tech Mono',monospace;font-size:.8em;color:var(--tx2);letter-spacing:.06em;}}
  .hdr-meta span{{color:var(--c);}}

  .wrap{{max-width:1200px;margin:0 auto;padding:30px 30px 70px;}}

  .sec{{font-family:'Orbitron',monospace;font-size:.82em;font-weight:700;color:var(--g);
    letter-spacing:.2em;text-transform:uppercase;margin:34px 0 16px;
    display:flex;align-items:center;gap:12px;}}
  .sec::after{{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--b2),transparent);}}

  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:10px;}}
  .sc{{background:var(--pn);border:1px solid var(--b2);padding:22px 16px;text-align:center;position:relative;overflow:hidden;}}
  .sc::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;}}
  .sc.tot::before{{background:var(--c);}} .sc.crit::before{{background:var(--r);}}
  .sc.hi::before{{background:var(--o);}} .sc.med::before{{background:var(--y);}}
  .snum{{font-family:'Orbitron',monospace;font-size:2.7em;font-weight:900;line-height:1;margin-bottom:8px;}}
  .slbl{{font-family:'Share Tech Mono',monospace;font-size:.73em;color:var(--tx2);letter-spacing:.12em;}}

  .rbar{{background:var(--pn);border:1px solid var(--b2);padding:20px 24px;margin-bottom:10px;}}
  .rlbl{{font-family:'Share Tech Mono',monospace;font-size:.74em;color:var(--tx2);letter-spacing:.1em;margin-bottom:10px;}}
  .rtrack{{display:flex;height:10px;overflow:hidden;gap:2px;margin-bottom:14px;}}
  .rseg{{height:100%;}}
  .rlegend{{display:flex;gap:22px;flex-wrap:wrap;font-family:'Share Tech Mono',monospace;font-size:.76em;color:var(--tx2);}}
  .rli{{display:flex;align-items:center;gap:7px;}}
  .rdot{{width:9px;height:9px;border-radius:50%;}}

  .card{{background:var(--pn);border:1px solid var(--b2);border-left:3px solid;
    margin-bottom:16px;transition:box-shadow .2s;}}
  .card:hover{{box-shadow:0 0 22px var(--glow,rgba(0,255,136,.08));}}
  .card-head{{display:flex;align-items:center;gap:14px;padding:14px 20px;
    border-bottom:1px solid var(--b1);flex-wrap:wrap;}}
  .idx{{font-family:'Orbitron',monospace;font-size:.72em;font-weight:700;
    border:1px solid;padding:2px 8px;letter-spacing:.08em;flex-shrink:0;}}
  .vtitle{{font-size:1.1em;font-weight:700;color:var(--tx);flex:1;letter-spacing:.03em;}}
  .badges{{display:flex;gap:8px;align-items:center;flex-shrink:0;}}
  .bsev{{font-family:'Share Tech Mono',monospace;font-size:.73em;
    border:1px solid;padding:3px 12px;letter-spacing:.08em;font-weight:700;}}
  .bcvss{{font-family:'Share Tech Mono',monospace;font-size:.73em;
    color:var(--tx2);border:1px solid var(--b2);padding:3px 12px;}}
  .cvss-vector-row{{display:flex;align-items:center;gap:12px;
    padding:7px 20px 8px;border-bottom:1px solid var(--b1);
    background:rgba(0,229,255,0.03);}}
  .vector-label{{font-family:'Share Tech Mono',monospace;font-size:.65em;
    color:#5a9980;letter-spacing:.1em;white-space:nowrap;}}
  .vector-string{{font-family:'Share Tech Mono',monospace;font-size:.76em;
    color:#00e5ff;letter-spacing:.03em;word-break:break-all;}}
  .card-body{{padding:18px 20px;}}

  .frow{{display:flex;align-items:baseline;gap:12px;margin-bottom:9px;flex-wrap:wrap;}}
  .flabel{{font-family:'Share Tech Mono',monospace;font-size:.78em;color:var(--tx2);
    letter-spacing:.08em;flex-shrink:0;width:120px;}}
  .frow code{{font-family:'Share Tech Mono',monospace;font-size:.88em;color:var(--c);
    background:rgba(0,229,255,.06);border:1px solid rgba(0,229,255,.15);
    padding:2px 10px;word-break:break-all;flex:1;}}
  .fval{{color:var(--tx);font-size:.95em;flex:1;line-height:1.5;}}

  .panels{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:14px 0 12px;}}
  .panel-impact,.panel-rec{{padding:14px 16px;border:1px solid;}}
  .panel-impact{{border-color:rgba(255,149,0,.3);background:rgba(255,149,0,.05);}}
  .panel-rec{{border-color:rgba(0,255,136,.25);background:rgba(0,255,136,.04);}}
  .plabel{{font-family:'Share Tech Mono',monospace;font-size:.67em;letter-spacing:.14em;margin-bottom:8px;}}
  .ptext{{font-size:.96em;color:var(--tx);line-height:1.55;}}

  .comp-row{{display:flex;gap:8px;flex-wrap:wrap;}}
  .comp-cell{{flex:1;min-width:160px;background:var(--bg3);border:1px solid var(--b1);padding:10px 14px;}}
  .clabel{{font-family:'Share Tech Mono',monospace;font-size:.65em;color:var(--tx2);
    letter-spacing:.1em;display:block;margin-bottom:5px;}}
  .cval{{font-family:'Share Tech Mono',monospace;font-size:.82em;color:var(--c);}}

  .tbl-wrap{{border:1px solid var(--b2);overflow:hidden;}}
  table{{width:100%;border-collapse:collapse;}}
  th{{font-family:'Orbitron',monospace;font-size:.66em;font-weight:700;color:var(--g);
    letter-spacing:.12em;background:var(--bg2);padding:13px 16px;text-align:left;
    border-bottom:1px solid var(--b2);}}
  td{{font-size:.92em;padding:11px 16px;border-bottom:1px solid var(--b1);color:var(--tx);
    font-family:'Rajdhani',sans-serif;font-weight:500;}}
  tr:nth-child(even) td{{background:rgba(0,255,136,.015);}}
  tr:hover td{{background:rgba(0,229,255,.04);}}
  .tmono{{font-family:'Share Tech Mono',monospace;color:var(--tx2);}}
  .tval{{color:var(--c);font-family:'Share Tech Mono',monospace;font-size:.86em;}}

  .no-findings{{font-family:'Share Tech Mono',monospace;color:var(--g);
    text-align:center;padding:40px;border:1px solid var(--b2);letter-spacing:.1em;}}
  .ftr{{text-align:center;padding:28px;border-top:1px solid var(--b1);margin-top:40px;
    font-family:'Share Tech Mono',monospace;font-size:.74em;color:var(--tx2);
    letter-spacing:.07em;line-height:2;}}
</style>
</head>
<body>

<div class="hdr">
  <div class="hdr-top">
    <div class="hdr-badge">// CLASSIFIED — AUTHORIZED PERSONNEL ONLY</div>
    <div class="hdr-title">LLM SECURITY ASSESSMENT REPORT</div>
    <div class="hdr-ts">GENERATED<br>{generated}</div>
  </div>
  <div class="hdr-meta">
    TARGET: <span>{target}</span> &nbsp;·&nbsp;
    FINDINGS: <span>{total}</span> &nbsp;·&nbsp;
    ENGINE: <span>OLLAMA + LLM PAYLOADS</span> &nbsp;·&nbsp;
    FRAMEWORKS: <span>OWASP · ISO 27001 · NIST CSF</span>
  </div>
</div>

<div class="wrap">

  <div class="sec">// EXECUTIVE SUMMARY</div>
  <div class="stats">
    <div class="sc tot"><div class="snum" style="color:var(--c);">{total}</div><div class="slbl">TOTAL FINDINGS</div></div>
    <div class="sc crit"><div class="snum" style="color:var(--r);">{critical}</div><div class="slbl">CRITICAL</div></div>
    <div class="sc hi"><div class="snum" style="color:var(--o);">{high}</div><div class="slbl">HIGH</div></div>
    <div class="sc med"><div class="snum" style="color:var(--y);">{medium}</div><div class="slbl">MEDIUM / LOW</div></div>
  </div>

  <div class="rbar">
    <div class="rlbl">// RISK DISTRIBUTION</div>
    <div class="rtrack">
      <div class="rseg" style="width:{cw}%;background:#ff2d55;"></div>
      <div class="rseg" style="width:{hw}%;background:#ff9500;"></div>
      <div class="rseg" style="width:{mw}%;background:#ffd60a;"></div>
      <div class="rseg" style="width:{lw}%;background:#00ff88;"></div>
    </div>
    <div class="rlegend">
      <div class="rli"><div class="rdot" style="background:#ff2d55;"></div>CRITICAL ({critical})</div>
      <div class="rli"><div class="rdot" style="background:#ff9500;"></div>HIGH ({high})</div>
      <div class="rli"><div class="rdot" style="background:#ffd60a;"></div>MEDIUM ({medium})</div>
      <div class="rli"><div class="rdot" style="background:#00ff88;"></div>LOW ({low})</div>
    </div>
  </div>

  <div class="sec">// VULNERABILITY FINDINGS</div>
  {cards_html}

  <div class="sec">// COMPLIANCE MAPPING MATRIX</div>
  <div class="tbl-wrap">
    <table>
      <thead><tr>
        <th>#</th><th>VULNERABILITY</th><th>SEVERITY</th>
        <th>OWASP TOP 10</th><th>ISO 27001</th><th>NIST CSF 2.0</th>
      </tr></thead>
      <tbody>{table_rows}</tbody>
    </table>
  </div>

  <div class="ftr">
    <div>GENERATED BY LLM-ORCHESTRATED SECURITY ASSESSMENT TOOL v1.0</div>
    <div style="color:#ff2d55;">⚠ SENSITIVE SECURITY DATA — HANDLE WITH STRICT CONFIDENTIALITY</div>
    <div>AUTHORIZED PENETRATION TESTING ONLY — UNAUTHORIZED USE IS PROHIBITED</div>
  </div>

</div>
</body>
</html>"""

        filename = f"reports/security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(filename, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"[REPORT] ✅ Report saved: {filename}")
        return filename