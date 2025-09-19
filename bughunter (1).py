#!/usr/bin/env python3
"""
bughunter — All‑in‑one Domain Bug Finder

Features implemented:
1) Subdomain Discovery (CT + small brute wordlist)
2) Admin/Login/Registration Panel Enumeration
3) Clickjacking Checks on discovered auth pages
4) SPF (Sender Policy Framework) Evaluation
5) Security Headers Evaluation 
6) Java Library Version Scanning (find downloadable .jar files, read MANIFEST)
7) CVE Lookup (best‑effort, via circl.lu public API when online)
8) Detailed Reporting (JSON + Markdown)

Usage:
  python bughunter.py -d example.com -o out --max-pages 150 --threads 20

Legal & Ethics:
  Run only on domains you own or have explicit written permission to test.
  You are responsible for complying with all applicable laws and policies.

Dependencies (install if missing):
  pip install requests beautifulsoup4 dnspython tldextract

Tested with Python 3.10+
"""
from __future__ import annotations


# ----------------- ASCII Banner -----------------
BANNER = r"""
██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗██║   ██║██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██╗██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""
print(BANNER)
print("Bughunter-one domain bug finder \n")

import argparse
import concurrent.futures as cf
import dataclasses
import ipaddress
import json
import os
import queue
import random
import re
import socket
import string
import sys
import time
import zipfile
from base64 import b64encode
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import requests
from bs4 import BeautifulSoup

# Optional but highly recommended
try:
    import dns.resolver  # type: ignore
except Exception:
    dns = None  # We'll gracefully degrade

try:
    import tldextract  # type: ignore
except Exception:
    tldextract = None

requests.packages.urllib3.disable_warnings()  # noqa

DEFAULT_TIMEOUT = 10
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0 Safari/537.36 bughunter/1.0"
)

COMMON_SUBS = [
    "www", "mail", "smtp", "webmail", "imap", "pop", "vpn", "sso", "okta",
    "portal", "intranet", "dev", "test", "stage", "staging", "preprod", "qa",
    "admin", "api", "cdn", "static", "assets", "files", "git", "jira", "confluence",
    "shop", "store", "pay", "billing", "accounts", "login", "auth", "blog", "help",
    "status", "monitor", "grafana", "kibana", "db", "mysql", "pg", "mssql",
]

COMMON_AUTH_PATHS = [
    "/admin/", "/admin", "/administrator/", "/wp-admin/", "/user/login/", "/user/login",
    "/users/sign_in", "/login", "/signin", "/auth/login", "/account/login",
    "/register", "/signup", "/users/sign_up", "/auth/register", "/account/register",
    "/portal/login", "/cms/login", "/staff/login", "/dashboard/login",
]

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",  # legacy
]

JAR_HINT_PATHS = [
    "/lib/", "/WEB-INF/lib/", "/static/", "/assets/", "/downloads/",
]

CVE_API = "https://cve.circl.lu/api/search/{}"  # free public; best-effort

@dataclass
class URLFinding:
    url: str
    status: Optional[int]
    title: str = ""
    has_form: bool = False
    notes: List[str] = field(default_factory=list)

@dataclass
class SPFResult:
    present: bool
    raw_records: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class HeaderCheck:
    header: str
    present: bool
    value: Optional[str]

@dataclass
class JavaLib:
    url: str
    manifest: Dict[str, str] = field(default_factory=dict)
    size_bytes: Optional[int] = None

@dataclass
class CVEEntry:
    id: str
    summary: str
    cvss: Optional[float]
    url: str

@dataclass
class Report:
    domain: str
    started_at: str
    finished_at: str = ""
    subdomains: Set[str] = field(default_factory=set)
    auth_pages: List[URLFinding] = field(default_factory=list)
    clickjacking_issues: List[str] = field(default_factory=list)
    spf: Optional[SPFResult] = None
    headers: Dict[str, HeaderCheck] = field(default_factory=dict)
    java_libs: List[JavaLib] = field(default_factory=list)
    components: Set[str] = field(default_factory=set)
    cves: Dict[str, List[CVEEntry]] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def to_json(self) -> str:
        def encode(obj):
            if isinstance(obj, (set,)):
                return list(obj)
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            raise TypeError
        return json.dumps(dataclasses.asdict(self), indent=2, default=encode)

    def to_markdown(self) -> str:
        md = [f"# bughunter Report for `{self.domain}`", ""]
        md.append(f"**Scan started:** {self.started_at}")
        if self.finished_at:
            md.append(f"\n**Scan finished:** {self.finished_at}")
        md.append("\n---\n")

        # Subdomains
        md.append("## Subdomains Found")
        if self.subdomains:
            for s in sorted(self.subdomains):
                md.append(f"- {s}")
        else:
            md.append("- None")

        # Auth pages
        md.append("\n## Admin/Login/Registration Pages")
        if self.auth_pages:
            for f in self.auth_pages:
                icon = "✅" if f.status and 200 <= f.status < 400 else "⚠️"
                md.append(f"- {icon} **{f.url}** — status: {f.status} | title: {f.title} | form: {f.has_form}")
                if f.notes:
                    for n in f.notes:
                        md.append(f"  - {n}")
        else:
            md.append("- None found")

        # Clickjacking
        md.append("\n## Clickjacking Issues")
        if self.clickjacking_issues:
            for i in self.clickjacking_issues:
                md.append(f"- {i}")
        else:
            md.append("- No obvious clickjacking risk on checked pages (missing headers not observed).")

        # SPF
        md.append("\n## SPF (Sender Policy Framework)")
        if self.spf:
            md.append(f"- Present: {self.spf.present}")
            if self.spf.raw_records:
                md.append("- Records:")
                for r in self.spf.raw_records:
                    md.append(f"  - `{r}`")
            for w in self.spf.warnings:
                md.append(f"- ⚠️ Warning: {w}")
            for e in self.spf.errors:
                md.append(f"- ❌ Error: {e}")
        else:
            md.append("- Not checked / resolver unavailable")

        # Security headers
        md.append("\n## Security Headers (root and auth pages)")
        for k, v in self.headers.items():
            icon = "✅" if v.present else "❌"
            value = (v.value or "").replace("\n", " ")
            md.append(f"- {icon} **{k}**: {value}")

        # Java libs
        md.append("\n## Java Libraries Detected (.jar)")
        if self.java_libs:
            for lib in self.java_libs:
                size = f" ({lib.size_bytes} bytes)" if lib.size_bytes else ""
                md.append(f"- {lib.url}{size}")
                if lib.manifest:
                    for mk, mv in lib.manifest.items():
                        md.append(f"  - {mk}: {mv}")
        else:
            md.append("- None found (publicly accessible)")

        # Components
        md.append("\n## Components / Fingerprints")
        if self.components:
            for c in sorted(self.components):
                md.append(f"- {c}")
        else:
            md.append("- None")

        # CVEs
        md.append("\n## CVEs (best‑effort)")
        if self.cves:
            for comp, entries in self.cves.items():
                md.append(f"- **{comp}**:")
                for e in entries[:10]:  # cap
                    score = f" (CVSS {e.cvss})" if e.cvss is not None else ""
                    md.append(f"  - {e.id}{score}: {e.summary[:160]}… — {e.url}")
        else:
            md.append("- None matched or API unavailable")

        # Errors
        if self.errors:
            md.append("\n## Errors / Notes")
            for err in self.errors:
                md.append(f"- {err}")

        return "\n".join(md) + "\n"


class bughunter:
    def __init__(self, domain: str, output: Path, threads: int = 10, max_pages: int = 150, timeout: int = DEFAULT_TIMEOUT):
        self.domain = self.normalize_domain(domain)
        self.output = output
        self.threads = max(1, threads)
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})
        self.report = Report(domain=self.domain, started_at=datetime.utcnow().isoformat() + "Z")

    # ----------------- helpers -----------------
    @staticmethod
    def normalize_domain(d: str) -> str:
        d = d.strip().lower()
        d = d.replace("http://", "").replace("https://", "").strip("/")
        if "/" in d:
            d = d.split("/", 1)[0]
        return d

    def base_urls(self) -> List[str]:
        return [f"https://{self.domain}", f"http://{self.domain}"]

    def fetch(self, url: str, method: str = "GET", allow_redirects: bool = True) -> Optional[requests.Response]:
        try:
            r = self.session.request(method, url, timeout=self.timeout, verify=False, allow_redirects=allow_redirects)
            return r
        except Exception:
            return None

    # ----------------- subdomains -----------------
    def discover_subdomains(self) -> Set[str]:
        found: Set[str] = set()
        # 1) Certificate Transparency via crt.sh
        try:
            q = self.domain
            url = f"https://crt.sh/?q=%25.{q}&output=json"
            r = self.fetch(url)
            if r and r.ok:
                try:
                    data = r.json()
                    for entry in data:
                        name_value = entry.get("name_value", "")
                        for h in name_value.split("\n"):
                            h = h.strip().lower()
                            if h.endswith(q) and "*" not in h:
                                found.add(h)
                except Exception:
                    pass
        except Exception:
            pass
        # 2) Small brute using DNS A/AAAA lookups
        for sub in COMMON_SUBS:
            host = f"{sub}.{self.domain}"
            if self.resolve_host(host):
                found.add(host)
        # Always include root domain
        found.add(self.domain)
        self.report.subdomains = found
        return found

    def resolve_host(self, host: str) -> bool:
        try:
            if dns:
                answers = dns.resolver.resolve(host, "A")
                return len(list(answers)) > 0
            else:
                socket.gethostbyname(host)
                return True
        except Exception:
            return False

    # ----------------- panel enumeration -----------------
    def enumerate_auth_pages(self, bases: List[str]) -> List[URLFinding]:
        findings: List[URLFinding] = []
        seen: Set[str] = set()

        # Add brute paths
        candidates = []
        for b in bases:
            for p in COMMON_AUTH_PATHS:
                candidates.append(b.rstrip("/") + p)

        # Quick crawl of homepage + a few internal links
        to_visit = queue.Queue()
        visited = set()
        for b in bases:
            to_visit.put(b)

        def visit(url: str):
            if url in visited or len(visited) >= self.max_pages:
                return []
            visited.add(url)
            r = self.fetch(url)
            if not r:
                return []
            links = []
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                title = (soup.title.string or "").strip() if soup.title else ""
                # Guess auth pages by heuristics
                if re.search(r"(login|sign\s*in|register|sign\s*up|admin)", r.text, re.I):
                    findings.append(self._build_finding(url, r, title))
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith("http"):
                        full = href
                    else:
                        # make absolute
                        full = requests.compat.urljoin(url, href)
                    if self.domain in self.normalize_domain(full):
                        links.append(full)
            except Exception:
                pass
            return links

        # BFS crawl
        while not to_visit.empty() and len(visited) < self.max_pages:
            u = to_visit.get()
            for link in visit(u):
                if link not in visited:
                    to_visit.put(link)

        # Brute list
        for c in candidates:
            if c in seen:
                continue
            seen.add(c)
            r = self.fetch(c, method="GET", allow_redirects=True)
            if not r:
                continue
            title = ""
            has_form = False
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                title = (soup.title.string or "").strip() if soup.title else ""
                has_form = bool(soup.find("form"))
            except Exception:
                pass
            if r.status_code < 500:  # record even 403/401/404 hints
                findings.append(URLFinding(url=c, status=r.status_code, title=title, has_form=has_form))

        # De‑duplicate by URL
        uniq = {}
        for f in findings:
            uniq[f.url] = f
        findings = list(uniq.values())
        self.report.auth_pages = findings
        return findings

    def _build_finding(self, url: str, r: requests.Response, title: str = "") -> URLFinding:
        has_form = False
        notes: List[str] = []
        try:
            soup = BeautifulSoup(r.text, "html.parser")
            has_form = bool(soup.find("form"))
        except Exception:
            pass
        return URLFinding(url=url, status=r.status_code, title=title, has_form=has_form, notes=notes)

    # ----------------- clickjacking -----------------
    def check_clickjacking(self, urls: List[str]) -> List[str]:
        issues: List[str] = []
        for u in urls:
            r = self.fetch(u, method="GET")
            if not r:
                continue
            xf = r.headers.get("X-Frame-Options") or r.headers.get("x-frame-options")
            csp = r.headers.get("Content-Security-Policy") or r.headers.get("content-security-policy")
            frame_protected = False
            if xf and xf.lower() in {"deny", "sameorigin"}:
                frame_protected = True
            if csp and re.search(r"frame-ancestors\s+('none'|self|https?:)", csp, re.I):
                frame_protected = True
            if not frame_protected:
                issues.append(f"{u} missing X-Frame-Options and CSP frame-ancestors — potential clickjacking risk")
        self.report.clickjacking_issues = issues
        return issues

    # ----------------- SPF -----------------
    def check_spf(self) -> Optional[SPFResult]:
        if not dns:
            return None
        res = SPFResult(present=False)
        try:
            answers = dns.resolver.resolve(self.domain, "TXT")
            for rdata in answers:
                txt = b"".join([bytes(x) if isinstance(x, (bytes, bytearray)) else x.encode() for x in rdata.strings])
                rec = txt.decode(errors="ignore")
                if rec.lower().startswith("v=spf1"):
                    res.present = True
                    res.raw_records.append(rec)
            # lint basic
            for rec in res.raw_records:
                if "all" not in rec:
                    res.warnings.append("SPF record missing ~all or -all mechanism")
                lookups = len(re.findall(r"include:|a|mx|ptr|exists|redirect=", rec))
                if lookups > 10:
                    res.warnings.append(f"SPF DNS lookup mechanisms possibly exceed 10 ({lookups})")
                if "?all" in rec:
                    res.warnings.append("SPF ends with ?all (neutral) — consider ~all or -all")
        except Exception as e:
            res.errors.append(str(e))
        self.report.spf = res
        return res

    # ----------------- security headers -----------------
    def evaluate_security_headers(self, urls: List[str]) -> Dict[str, HeaderCheck]:
        headers_map: Dict[str, HeaderCheck] = {}
        check_urls = list(set(urls + [u + "/" if not u.endswith("/") else u for u in urls]))
        for u in check_urls[:10]:  # don't overdo
            r = self.fetch(u)
            if not r:
                continue
            for h in SECURITY_HEADERS:
                v = r.headers.get(h) or r.headers.get(h.title())
                present = v is not None
                prev = headers_map.get(h)
                if not prev or (present and not prev.present):
                    headers_map[h] = HeaderCheck(header=h, present=present, value=v)
            # Fingerprint components
            server = r.headers.get("Server")
            if server:
                self.report.components.add(f"Server: {server}")
            xpb = r.headers.get("X-Powered-By")
            if xpb:
                self.report.components.add(f"X-Powered-By: {xpb}")
        self.report.headers = headers_map
        return headers_map

    # ----------------- java libs -----------------
    def scan_java_libs(self, bases: List[str]) -> List[JavaLib]:
        libs: List[JavaLib] = []
        # Discover links from homepages
        discovered_links: Set[str] = set()
        for b in bases:
            r = self.fetch(b)
            if not r:
                continue
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    full = requests.compat.urljoin(b, href)
                    if full.endswith(".jar") and self.domain in self.normalize_domain(full):
                        discovered_links.add(full)
            except Exception:
                pass
            # Probe common jar directories (listing enabled scenarios)
            for p in JAR_HINT_PATHS:
                hint = b.rstrip("/") + p
                rr = self.fetch(hint)
                if rr and rr.ok and "<a" in rr.text.lower():
                    try:
                        sp = BeautifulSoup(rr.text, "html.parser")
                        for a in sp.find_all("a", href=True):
                            f = requests.compat.urljoin(hint, a["href"].strip())
                            if f.endswith(".jar") and self.domain in self.normalize_domain(f):
                                discovered_links.add(f)
                    except Exception:
                        pass
        # Fetch manifests best‑effort
        for link in sorted(discovered_links):
            size = None
            try:
                hr = self.fetch(link, method="HEAD")
                if hr and hr.ok and hr.headers.get("Content-Length"):
                    size = int(hr.headers["Content-Length"])  # type: ignore
            except Exception:
                pass
            manifest = {}
            try:
                r = self.fetch(link)
                if r and r.ok and r.content:
                    with open(os.devnull, "wb") as _:
                        pass
                    from io import BytesIO
                    bio = BytesIO(r.content)
                    with zipfile.ZipFile(bio) as zf:
                        if "META-INF/MANIFEST.MF" in zf.namelist():
                            with zf.open("META-INF/MANIFEST.MF") as mf:
                                for line in mf.read().decode(errors="ignore").splitlines():
                                    if ":" in line:
                                        k, v = line.split(":", 1)
                                        manifest[k.strip()] = v.strip()
            except Exception:
                pass
            libs.append(JavaLib(url=link, manifest=manifest, size_bytes=size))
            # Try to synthesize component string
            name = manifest.get("Implementation-Title") or manifest.get("Bundle-Name") or Path(link).name
            ver = manifest.get("Implementation-Version") or manifest.get("Bundle-Version")
            if name:
                comp = f"{name} {ver}".strip()
                self.report.components.add(comp)
        self.report.java_libs = libs
        return libs

    # ----------------- CVE lookup -----------------
    def cve_lookup(self, components: Set[str]) -> Dict[str, List[CVEEntry]]:
        results: Dict[str, List[CVEEntry]] = {}
        for comp in sorted(components):
            q = re.sub(r"\s+", "+", comp)
            url = CVE_API.format(q)
            try:
                r = self.fetch(url)
                if not r or not r.ok:
                    continue
                data = r.json()
                entries: List[CVEEntry] = []
                # circl.lu returns a list of dicts with 'id','summary','cvss','references'
                for item in data[:20]:
                    cid = item.get("id") or item.get("cve") or "CVE-?"
                    summ = item.get("summary") or item.get("description") or ""
                    cvss = item.get("cvss")
                    ref_url = ""
                    refs = item.get("references") or []
                    if isinstance(refs, list) and refs:
                        ref_url = refs[0]
                    entries.append(CVEEntry(id=cid, summary=summ, cvss=cvss, url=ref_url))
                if entries:
                    results[comp] = entries
            except Exception:
                continue
        self.report.cves = results
        return results

    # ----------------- run orchestrator -----------------
    def run(self) -> Report:
        # 1) Subdomains
        subs = self.discover_subdomains()
        # Build base URLs (root first, then a few subdomains)
        bases = []
        for s in sorted(subs):
            if s == self.domain or s.endswith("." + self.domain):
                bases.append(f"https://{s}")
        bases = bases[:15] or self.base_urls()

        # 2) Auth enumeration
        findings = self.enumerate_auth_pages(self.base_urls())

        # 3) Clickjacking on auth pages found or common paths
        cj_urls = [f.url for f in findings if f.status and f.status < 500]
        if not cj_urls:
            cj_urls = [b + p for b in self.base_urls() for p in ["/login", "/register", "/admin"]]
        self.check_clickjacking(cj_urls)

        # 4) SPF
        self.check_spf()

        # 5) Security headers (root + one auth page)
        check_urls = self.base_urls() + cj_urls[:3]
        self.evaluate_security_headers(check_urls)

        # 6) Java libs
        self.scan_java_libs(self.base_urls())

        # 7) CVEs from components
        if self.report.components:
            self.cve_lookup(self.report.components)

        # Finish
        self.report.finished_at = datetime.utcnow().isoformat() + "Z"
        self.save_reports()
        return self.report

    # ----------------- output -----------------
    def save_reports(self) -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        json_path = self.output / f"{self.domain}_bughunter.json"
        md_path = self.output / f"{self.domain}_bughunter.md"
        with open(json_path, "w", encoding="utf-8") as f:
            f.write(self.report.to_json())
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(self.report.to_markdown())
        print(f"[+] Saved JSON: {json_path}")
        print(f"[+] Saved Markdown: {md_path}")


# ----------------- CLI -----------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="bughunter — All‑in‑one Domain Bug Finder")
    p.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    p.add_argument("-o", "--output", default="out", help="Output directory")
    p.add_argument("--threads", type=int, default=12, help="Thread count (reserved for future use)")
    p.add_argument("--max-pages", type=int, default=150, help="Max pages to crawl roughly")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP timeout seconds")
    return p.parse_args()


def main():
    args = parse_args()
    tool = bughunter(domain=args.domain, output=Path(args.output), threads=args.threads, max_pages=args.max_pages, timeout=args.timeout)
    rep = tool.run()
    # Print a tiny console summary
    print("\n========== SUMMARY ==========")
    print(f"Domain: {rep.domain}")
    print(f"Subdomains: {len(rep.subdomains)} found")
    print(f"Auth pages: {len(rep.auth_pages)} found")
    print(f"Clickjacking issues: {len(rep.clickjacking_issues)}")
    if rep.spf:
        print(f"SPF present: {rep.spf.present}")
    print(f"Security headers checked: {len(rep.headers)}")
    print(f"Java libs: {len(rep.java_libs)}")
    print(f"Components fingerprinted: {len(rep.components)}")
    print(f"Components with CVEs: {len(rep.cves)}")
    print("=============================\n")


if __name__ == "__main__":
    main()
