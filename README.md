# bughunter — All-in-one Domain Bug Finder

## Description

bughunter is a comprehensive Python-based tool designed for security researchers and penetration testers to perform automated bug hunting and reconnaissance on target domains. It integrates multiple scanning techniques to identify potential vulnerabilities, misconfigurations, and security issues in a single run.

## Features

- **Subdomain Discovery**: Uses Certificate Transparency logs and DNS brute-forcing with common subdomains.
- **Admin/Login/Registration Panel Enumeration**: Crawls and brute-forces common authentication paths.
- **Clickjacking Checks**: Evaluates X-Frame-Options and CSP headers on discovered auth pages.
- **SPF (Sender Policy Framework) Evaluation**: Checks for SPF records and provides basic linting.
- **Security Headers Evaluation**: Scans for essential security headers like CSP, X-Frame-Options, etc.
- **Java Library Version Scanning**: Finds publicly accessible .jar files and extracts manifest information.
- **CVE Lookup**: Performs best-effort CVE searches via the CIRCL.LU public API for detected components.
- **Detailed Reporting**: Generates JSON and Markdown reports with findings.

## Installation

1. Ensure Python 3.10+ is installed.
2. Clone or download the repository.
3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
   Note: `dnspython` and `tldextract` are optional but highly recommended for full functionality.

## Usage

Run the tool from the command line:

```
python bughunter.py -d example.com -o out --max-pages 150 --threads 20
```

### Arguments

- `-d, --domain`: Target domain (required, e.g., example.com)
- `-o, --output`: Output directory (default: out)
- `--threads`: Thread count (default: 12, reserved for future use)
- `--max-pages`: Max pages to crawl (default: 150)
- `--timeout`: HTTP timeout in seconds (default: 10)

### Example Output

The tool will generate:
- JSON report: `out/example.com_bughunter.json`
- Markdown report: `out/example.com_bughunter.md`

A console summary is also printed upon completion.

## Legal & Ethics

- Run bughunter only on domains you own or have explicit written permission to test.
- You are responsible for complying with all applicable laws, regulations, and policies.
- Use this tool ethically and responsibly.

## Dependencies

- `requests`: For HTTP requests
- `beautifulsoup4`: For HTML parsing
- `dnspython`: For DNS resolution (optional)
- `tldextract`: For domain parsing (optional)

## Tested With

- Python 3.10+

## Contribution
SanikaG31:- https://github.com/SanikaG31
diptibangde10:- https://github.com/diptibangde10

## License

This project is provided as-is for educational and security research purposes.

