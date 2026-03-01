# 🔒 LLM-Orchestrated Web Vulnerability Assessment System

> *Bridging Technical Security with Business Risk through LLM-Powered Intelligence*

An AI-powered, **privacy-first** web vulnerability scanner that uses a locally hosted LLM (Ollama) to generate context-aware attack payloads, assess business risk, and produce professional security reports — all without sending a single byte of target data to the cloud.

---

## ✨ Features

### Phase 1 — Core System
| Module | Description |
|--------|-------------|
| 🕷️ **Web Crawler** | Discovers forms & URL parameters across up to 15 pages |
| 🤖 **LLM Payload Generator** | Ollama (Llama 3.2) generates adaptive, context-aware payloads |
| 🔎 **XSS Scanner** | Reflected + Stored XSS across all discovered inputs |
| 💉 **SQLi Scanner** | Error-based, Boolean-based, Time-based Blind injection |
| 💻 **CMDi Scanner** | Direct + Time-based Blind command injection |
| ⚙️ **Misconfig Scanner** | Security headers, sensitive files, directory listing, info disclosure |
| 📊 **GRC Layer** | CVSS v3.1 scoring + OWASP Top 10 / ISO 27001 / NIST CSF mapping |
| 🗄️ **SQLite Database** | All sessions, findings, and compliance mappings persisted |
| 📄 **HTML Report** | Cyberpunk-themed interactive security report |
| 🌐 **Flask Chat UI** | Real-time scan progress via chat-style interface |

### Phase 2 — Expansion Features
| Feature | Description |
|---------|-------------|
| 📋 **Scan History Dashboard** | Browse, search, sort all past scan sessions at `/history` |
| 🧮 **CVSS Vector Strings** | Full `CVSS:3.1/AV:N/AC:L/...` vector on every finding |
| 🥷 **Stealth Mode** | 3 rate-limit profiles to evade WAF detection |
| 📑 **PDF Export** | One-click PDF download of any report from the history dashboard |

---

## 🚀 Quick Start

### 1. Prerequisites

```bash
# Python 3.9+
python --version

# Ollama installed and running
ollama serve
ollama pull llama3.2
```

### 2. Clone & Install

```bash
git clone https://github.com/yourusername/ollama-security-tool.git
cd ollama-security-tool

pip install -r requirements.txt

# For PDF export (recommended)
pip install weasyprint
```

### 3. Run

```bash
python app.py
```

Open **http://localhost:5000** in your browser.

---

## 📦 Installation

### requirements.txt

```
flask
requests
beautifulsoup4
sqlalchemy
weasyprint        # PDF export (optional but recommended)
```

> **Windows users:** If `weasyprint` fails (requires GTK3), use `pdfkit` instead:
> ```bash
> pip install pdfkit
> # Download wkhtmltopdf from: https://wkhtmltopdf.org/downloads.html
> ```
> The tool falls back to plain-text export automatically if neither is installed.

---

## 🗂️ Project Structure

```
ollama-security-tool/
├── app.py                      # Flask app — all routes
├── core/
│   ├── web_crawler.py          # Multi-page crawler
│   ├── authorization.py        # Domain authorization checker
│   └── stealth.py              # ★ Rate limiter (Phase 2)
├── llm/
│   ├── ollama_client.py        # Ollama API wrapper
│   └── prompt_templates.py     # Per-vulnerability prompt templates
├── scanners/
│   ├── xss_scanner.py          # XSS (Reflected + Stored)
│   ├── sqli_scanner.py         # SQL Injection (3 types)
│   ├── cmdi_scanner.py         # Command Injection
│   └── misconfig_scanner.py    # Misconfiguration checks
├── grc/
│   ├── risk_assessor.py        # CVSS v3.1 + LLM risk narratives
│   └── compliance_mapper.py    # OWASP / ISO 27001 / NIST CSF
├── database/
│   ├── models.py               # SQLAlchemy ORM models
│   └── db_manager.py           # CRUD operations
├── reporting/
│   ├── report_generator.py     # Cyberpunk HTML report
│   └── pdf_exporter.py         # ★ PDF export (Phase 2)
└── templates/
    ├── index.html              # Main scanner UI
    └── history.html            # ★ Scan history dashboard (Phase 2)
```

---

## 🥷 Stealth Mode

Stealth mode adds randomised delays between HTTP requests to avoid WAF detection.

### How to use

Toggle it from the UI — look for the **`// STEALTH MODE`** bar just below the URL input field.

| Profile | Delay Range | Use Case |
|---------|-------------|----------|
| `NORMAL` | 0.1 – 0.4s | Local lab targets (DVWA) |
| `STEALTH` | 0.8 – 2.5s | Public test sites, cloud WAFs |
| `AGGRESSIVE` | 3.0 – 7.0s | High-security / monitored targets |

> Stealth is **OFF by default** — zero performance impact unless enabled.

### API

```bash
# Enable via API
curl -X POST http://localhost:5000/set_stealth \
  -H "Content-Type: application/json" \
  -d '{"enabled": true, "mode": "stealth"}'

# Check current status
curl http://localhost:5000/stealth_status
```

---

## 📋 Scan History Dashboard

Visit **http://localhost:5000/history** after running at least one scan.

- 4 summary cards: total scans, completed, total findings, critical count
- Search sessions by target URL in real time
- Sort by: newest, oldest, most findings, fewest findings
- Per-session: severity breakdown badges, status, HTML report link, PDF download

---

## 📑 PDF Export

PDF reports are accessible from the history dashboard via the **`// PDF`** button on any completed session.

The exporter tries three methods in order:

1. **weasyprint** — best CSS fidelity, preserves cyberpunk theme
2. **pdfkit** — fallback if weasyprint unavailable
3. **Plain text** — always works, no dependencies required

---

## 🧮 CVSS v3.1 Vector Strings

Every finding in the report now displays the full CVSS vector string in NVD format:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
```

| Vulnerability | Score | Vector |
|---------------|-------|--------|
| Command Injection — Direct | **10.0** Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` |
| SQL Injection — Error Based | **9.8** Critical | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| XSS — Stored | **8.8** High | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` |
| Sensitive File Exposed | **7.5** High | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| XSS — Reflected | **6.1** Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| Missing Security Header | **5.3** Medium | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |

---

## 🎯 Supported Test Targets

| Target | Notes |
|--------|-------|
| DVWA (localhost) | Full auto-login, sets security level to Low |
| testphp.vulnweb.com | Public practice site |
| testaspnet.vulnweb.com | Public practice site |
| demo.testfire.net | Public practice site |
| Any authorised target | Open mode — user responsible for written permission |

> ⚠️ **AUTHORIZED USE ONLY.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.

---

## 🔬 Evaluation Results

Tested against **DVWA** (Damn Vulnerable Web Application) at Low security level:

| Scanner | Findings | Critical | High | Med/Low |
|---------|----------|----------|------|---------|
| XSS | 5 | 0 | 3 | 2 |
| SQLi | 4 | 3 | 1 | 0 |
| CMDi | 3 | 2 | 1 | 0 |
| Misconfig | 5 | 0 | 1 | 4 |
| **Total** | **17** | **5** | **6** | **6** |

**True Positive Rate: 94.1%**

---

## 📜 Compliance Frameworks

Every finding is automatically mapped to:

- **OWASP Top 10 (2021)** — A01 through A10
- **ISO/IEC 27001:2022** — Annex A control identifiers
- **NIST Cybersecurity Framework 2.0** — Function + Category

---

## ⚖️ Ethical & Legal Notice

This tool is built for **authorised penetration testing and academic research only**.

- All LLM inference runs locally via Ollama — no target data leaves your machine
- The authorization module logs a reminder for every non-lab domain
- Users are solely responsible for obtaining written permission before scanning any target

---

## 🏫 Academic Context

Built as a 4th Year B.Tech-M.Tech Dual Degree final project demonstrating:

- Local LLM integration for adaptive security testing
- GRC pipeline with CVSS v3.1, OWASP, ISO 27001, NIST CSF
- Full-stack Python development (Flask, SQLAlchemy, BeautifulSoup)
- Privacy-first design with zero cloud dependency

---

## 📚 References

- [OWASP Top 10 (2021)](https://owasp.org/Top10/)
- [CVSS v3.1 Specification — FIRST](https://www.first.org/cvss/v3.1/specification-document)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- [Ollama](https://ollama.com)
- [DVWA](https://github.com/digininja/DVWA)
