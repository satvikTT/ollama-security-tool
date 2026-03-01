# reporting/pdf_exporter.py
"""
PDF Export Module
-----------------
Converts the HTML security report to a downloadable PDF.

Install (one time):
    pip install weasyprint

If weasyprint fails on Windows (needs GTK3), use pdfkit instead:
    pip install pdfkit
    + download wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html

Falls back to plain-text if neither library is available.
"""

import os
import re
from datetime import datetime


def export_pdf(html_path: str, session_id=None) -> str | None:
    """
    Convert an HTML report to PDF.
    Returns the output file path on success, None on failure.
    Tries weasyprint → pdfkit → plain-text fallback in that order.
    """
    if not os.path.exists(html_path):
        print(f"[PDF] ❌ HTML file not found: {html_path}")
        return None

    os.makedirs("reports", exist_ok=True)

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    base     = f"reports/security_report_session_{session_id}" if session_id else f"reports/security_report_{ts}"
    pdf_path = base + ".pdf"

    # ── Strategy 1: weasyprint ────────────────────────────────────
    try:
        from weasyprint import HTML, CSS

        # Google Fonts won't load offline during conversion —
        # inject a fallback so layout stays intact
        fallback = CSS(string="""
            @import url('data:text/css,');
            body, .hdr-title, .sec, .idx, .vtitle, .flabel,
            .clabel, .rlbl, .bcvss, .bsev, code, pre {
                font-family: 'Courier New', Courier, monospace !important;
            }
        """)

        HTML(filename=html_path).write_pdf(
            pdf_path,
            stylesheets=[fallback],
            presentational_hints=True,
        )
        print(f"[PDF] ✅ Exported via weasyprint → {pdf_path}")
        return pdf_path

    except ImportError:
        print("[PDF] weasyprint not installed — trying pdfkit...")
    except Exception as e:
        print(f"[PDF] weasyprint error: {e} — trying pdfkit...")

    # ── Strategy 2: pdfkit (needs wkhtmltopdf binary) ────────────
    try:
        import pdfkit

        options = {
            "page-size":                "A4",
            "margin-top":               "10mm",
            "margin-right":             "10mm",
            "margin-bottom":            "10mm",
            "margin-left":              "10mm",
            "encoding":                 "UTF-8",
            "enable-local-file-access": None,
            "print-media-type":         None,
            "no-outline":               None,
        }
        pdfkit.from_file(html_path, pdf_path, options=options)
        print(f"[PDF] ✅ Exported via pdfkit → {pdf_path}")
        return pdf_path

    except ImportError:
        print("[PDF] pdfkit not installed — using plain-text fallback...")
    except Exception as e:
        print(f"[PDF] pdfkit error: {e} — using plain-text fallback...")

    # ── Strategy 3: plain-text (always works) ────────────────────
    txt_path = base + "_report.txt"
    try:
        _plain_text_export(html_path, txt_path)
        print(f"[PDF] ⚠ Plain-text fallback exported → {txt_path}")
        return txt_path
    except Exception as e:
        print(f"[PDF] ❌ All export methods failed: {e}")
        return None


def _plain_text_export(html_path: str, txt_path: str):
    """Strip HTML, write structured plain-text report."""
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # Remove style/script blocks
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL)
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL)

    # Block elements → newlines
    html = re.sub(r"<(div|p|h[1-6]|li|tr|br)[^>]*>", "\n", html)
    html = re.sub(r"<td[^>]*>", "  |  ", html)

    # Strip remaining tags
    html = re.sub(r"<[^>]+>", "", html)

    # Decode common HTML entities
    html = html.replace("&amp;", "&").replace("&lt;", "<") \
               .replace("&gt;", ">").replace("&nbsp;", " ") \
               .replace("&#8203;", "")

    lines = [l.strip() for l in html.splitlines() if l.strip()]
    text  = "\n".join(lines)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write("=" * 64 + "\n")
        f.write("  LLM SECURITY ASSESSMENT REPORT\n")
        f.write("  Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.write("=" * 64 + "\n\n")
        f.write(text)


def find_report_for_session(session_id: int) -> str | None:
    """
    Find the HTML report file for a given session ID.
    Checks the reports/ directory for matching filenames.
    """
    import glob

    patterns = [
        f"reports/*session_{session_id}*.html",
        f"reports/security_report_*.html",
    ]
    for pattern in patterns:
        matches = glob.glob(pattern)
        if matches:
            matches.sort(reverse=True)
            return matches[0]
    return None