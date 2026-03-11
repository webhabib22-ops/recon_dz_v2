# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
RECON-DZ v2 - Advanced Security Reconnaissance Framework
Professional-grade tool for authorized security assessment
Educational and defensive purposes only

Version: 2.1.0  (DNS + SSL/TLS modules added)
"""

import asyncio
import argparse
import json
import sys
import ssl
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp
import urllib3
urllib3.disable_warnings()

from core.async_engine   import AsyncReconEngine, detect_waf_response
from core.algeria_threats import AlgeriaThreatDatabase
from core.dns_intel      import DNSIntelEngine
from core.ssl_intel      import SSLTLSEngine


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  BANNER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

BANNER = """
â•”â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•—
â•‘   RECON-DZ v2.1.0  â€”  Intelligence Reconnaissance       â•‘
â•‘   DNS | WHOIS | Subdomains | SSL/TLS | Endpoints         â•‘
â•‘   For authorized security assessment only               â•‘
â•šâ•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
"""


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  MAIN FRAMEWORK
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class RECONDZv2:
    VERSION  = "2.1.0"
    CODENAME = "Intelligence Recon"
    LICENSE  = "Authorized Security Assessment Only"

    def __init__(self, verbose: bool = False, internal_mode: bool = False):
        self.verbose       = verbose
        self.internal_mode = internal_mode
        self.engine: Optional[AsyncReconEngine] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.algeria_db    = AlgeriaThreatDatabase()
        self.results: Dict = {}
        self.session_id    = datetime.now().strftime("%Y%m%d_%H%M%S")

    async def initialize(self, max_concurrent: int = 30):
        print(BANNER)
        print(f"[*] Initializing RECON-DZ v{self.VERSION}...")

        # aiohttp session Ù…Ø´ØªØ±ÙƒØ© Ù„ÙƒÙ„ Ø§Ù„ÙˆØ­Ø¯Ø§Øª
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode    = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(
            limit=max_concurrent,
            ssl=ssl_ctx,
            enable_cleanup_closed=True,
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=20),
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                   "AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"},
        )

        self.engine = AsyncReconEngine(
            max_concurrent=max_concurrent,
            enable_stealth=True,
            internal_mode=self.internal_mode,
            delay_range=(0.2, 0.8) if not self.internal_mode else (0.05, 0.2),
        )
        await self.engine.initialize()
        print("[+] Engine ready\n")
        return self

    async def close(self):
        if self.engine:
            await self.engine.close()
        if self.session:
            await self.session.close()

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    #  MAIN SCAN
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    async def scan(self, target: str, depth: str = "normal",
                   scan_dns: bool = True, scan_ssl: bool = True) -> Dict:
        print(f"{'='*60}")
        print(f"  Target:  {target}")
        print(f"  Session: {self.session_id}")
        print(f"  Depth:   {depth}")
        print(f"{'='*60}\n")

        # â”€â”€ Phase 1: Algeria Intelligence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        print("[Phase 1/6] Algeria Threat Intelligence")
        algeria_info = self.algeria_db.identify_target(target)
        if algeria_info:
            print(f"[+] Algerian infrastructure detected")
            print(f"    Sector:      {algeria_info.sector.upper()}")
            print(f"    Criticality: {algeria_info.criticality.upper()}")
            print(f"    ISP:         {algeria_info.isp}")
            if algeria_info.compliance_requirements:
                print(f"    Compliance:  {', '.join(algeria_info.compliance_requirements)}")
            if algeria_info.threat_actors:
                print(f"    Threat actors: {', '.join(algeria_info.threat_actors)}")
        else:
            print("[*] Non-Algerian target â€” general scan mode")

        # â”€â”€ Phase 2: DNS Intelligence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        dns_result = None
        if scan_dns:
            print(f"\n[Phase 2/6] DNS Intelligence")
            dns_engine = DNSIntelEngine(
                session  = self.session,
                brute    = (depth in ("normal", "deep")),
                threads  = 80 if depth == "deep" else 50,
                verbose  = self.verbose,
            )
            dns_result = await dns_engine.full_scan(target)
            dns_dict   = dns_engine.to_dict(dns_result)

            print(f"\n[DNS Summary]")
            print(f"  Records:    {dns_result.stats.get('total_dns_records', 0)}")
            print(f"  Subdomains: {dns_result.stats.get('total_subdomains', 0)}")
            print(f"  IPs:        {', '.join(dns_result.ips[:5])}")
            if dns_result.whois:
                w = dns_result.whois
                print(f"  Registrar:  {w.registrar}")
                print(f"  Created:    {w.creation_date}")
                print(f"  Expires:    {w.expiry_date}")
                print(f"  DNSSEC:     {w.dnssec}")
            if dns_result.security_issues:
                print(f"  DNS Issues: {len(dns_result.security_issues)}")
                for issue in dns_result.security_issues:
                    m = "[!!]" if issue["severity"]=="CRITICAL" else "[!]"
                    print(f"    {m} [{issue['severity']}] {issue['title']}")
        else:
            dns_dict = {}
            print("\n[Phase 2/6] DNS Intelligence â€” skipped (--no-dns)")

        # â”€â”€ Phase 3: SSL/TLS Analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ssl_result = None
        if scan_ssl:
            print(f"\n[Phase 3/6] SSL/TLS Deep Analysis")
            ssl_engine = SSLTLSEngine(
                session = self.session,
                verbose = self.verbose,
            )
            ssl_result = await ssl_engine.full_scan(target, port=443)
            ssl_dict   = ssl_engine.to_dict(ssl_result)

            print(f"\n[SSL Summary]")
            print(f"  Grade:     {ssl_result.grade}  (Score: {ssl_result.grade_score}/100)")
            print(f"  Protocols: {', '.join(ssl_result.supported_protocols)}")
            if ssl_result.cert:
                c = ssl_result.cert
                print(f"  Cert CN:   {c.subject_cn}")
                print(f"  Issued by: {c.issuer_cn}")
                print(f"  Expires:   {c.not_after} ({c.days_remaining} days)")
                print(f"  SANs:      {len(c.san_domains)} domains")
            if ssl_result.vulnerabilities:
                print(f"  Vulns:     {len(ssl_result.vulnerabilities)}")
                for v in ssl_result.vulnerabilities[:5]:
                    print(f"    [!] {v['vuln']}: {v['description'][:55]}")
        else:
            ssl_dict = {}
            print("\n[Phase 3/6] SSL/TLS Analysis â€” skipped (--no-ssl)")

        # â”€â”€ Phase 4: Connectivity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        print(f"\n[Phase 4/6] Connectivity Assessment")
        response, protocol, actual_target = await self.engine.request_with_fallback(
            target, www_fallback=True
        )

        if response.status == 0:
            print(f"[-] Target unreachable: {response.error}")
            return {"error": "unreachable", "details": response.error}

        base_url = f"{protocol}{actual_target}"
        print(f"[+] Connected: {base_url}")
        print(f"    Status: {response.status}  "
              f"Time: {response.elapsed:.2f}s  "
              f"Size: {len(response.body)} bytes")
        print(f"    Server: {response.get_header('server', 'Unknown')}")
        print(f"    Powered-by: {response.get_header('x-powered-by', '-')}")

        # Technology hints
        techs = response.extract_technology_hints()
        if techs:
            print(f"    Technologies: {', '.join(techs)}")

        # WAF detection
        waf = detect_waf_response(response)
        print(f"    WAF: {waf if waf else 'None detected'}")

        # â”€â”€ Phase 5: Endpoint Discovery â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        print(f"\n[Phase 5/6] Endpoint Discovery")
        paths     = self._get_discovery_paths(algeria_info)
        urls      = [f"{base_url.rstrip('/')}{p}" for p in paths]
        print(f"[*] Testing {len(urls)} endpoints...")

        discovered = []
        for i, url in enumerate(urls, 1):
            resp = await self.engine.request(url)
            if resp.status != 0:
                endpoint = {
                    "url":         url,
                    "status":      resp.status,
                    "size":        len(resp.body),
                    "title":       self._extract_title(resp.body),
                    "server":      resp.get_header("server"),
                    "redirect_to": resp.final_url if resp.final_url != url else "",
                }
                interesting = (
                    resp.is_success or
                    resp.status in (301, 302, 307, 308) or
                    resp.status in (401, 403)
                )
                if interesting:
                    discovered.append(endpoint)

                if resp.status in (200, 201, 301, 302, 401, 403):
                    icon = "[+]" if resp.status in (200, 201) else \
                           "[>]" if resp.status in (301, 302) else "[!]"
                    title_str = f' "{endpoint["title"][:35]}"' \
                                if endpoint.get("title") else ""
                    redir_str = f' -> {endpoint["redirect_to"][:40]}' \
                                if endpoint.get("redirect_to") else ""
                    print(f"    {icon} [{resp.status}] {url}{title_str}{redir_str}")

            if i % 10 == 0 and i < len(urls):
                print(f"    Progress: {i}/{len(urls)}")

        # â”€â”€ Phase 6: Security Analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        print(f"\n[Phase 6/6] Security Analysis")
        findings = self._analyze_findings(
            response, discovered, algeria_info, ssl_result, dns_result
        )

        if findings:
            print(f"[+] {len(findings)} security observations:")
            for f in findings[:10]:
                sev = f["severity"].upper()
                m = "[!!]" if sev=="CRITICAL" else "[!]" if sev=="HIGH" else "[*]"
                print(f"    {m} [{sev}] {f['name']}")
        else:
            print("[*] No immediate security concerns")

        # â”€â”€ Compile & Save â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self.results = {
            "framework": {
                "version": self.VERSION,
                "session": self.session_id,
            },
            "target": {
                "input":    target,
                "resolved": actual_target,
                "protocol": protocol,
            },
            "algerian_context": algeria_info.__dict__ if algeria_info else None,
            "dns_intel":  dns_dict,
            "ssl_intel":  ssl_dict,
            "connection": {
                "status":     response.status,
                "time":       response.elapsed,
                "server":     response.get_header("server"),
                "powered_by": response.get_header("x-powered-by"),
                "waf":        waf,
            },
            "technologies": techs,
            "discovery": {
                "tested":    len(urls),
                "found":     len(discovered),
                "endpoints": discovered,
            },
            "findings":  findings,
            "statistics":self.engine.stats,
            "timestamp": datetime.now().isoformat(),
        }

        self._save_report(target)
        self._print_summary(algeria_info, ssl_result, dns_result,
                            discovered, findings)
        return self.results

    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    #  HELPERS
    # â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _get_discovery_paths(self, algeria_info) -> List[str]:
        base = [
            "/", "/robots.txt", "/.well-known/security.txt",
            "/sitemap.xml", "/favicon.ico",
            "/.env", "/.git/HEAD", "/phpinfo.php",
            "/backup.zip", "/backup.sql",
            "/api/", "/api/v1/", "/api/v2/",
        ]
        if not algeria_info:
            return base + ["/admin", "/login", "/wp-admin", "/wp-login.php"]

        sector_paths = {
            "government": [
                "/admin", "/administrator", "/wp-admin", "/cpanel",
                "/webmail", "/mail", "/intranet", "/portal", "/ent",
            ],
            "banking": [
                "/api", "/mobile", "/auth", "/login", "/ib",
                "/e-banking", "/corporate",
            ],
            "telecom": [
                "/portal", "/customer", "/api", "/myaccount",
                "/recharge", "/services",
            ],
            "education": [
                "/portal", "/student", "/campus", "/moodle",
                "/courses", "/library", "/staff", "/ent",
                "/scolarite", "/inscription",
            ],
            "commercial": [
                "/admin", "/login", "/shop", "/panier",
                "/compte", "/commande",
            ],
        }
        return base + sector_paths.get(
            algeria_info.sector, ["/admin", "/login"]
        )

    def _extract_title(self, body: str) -> Optional[str]:
        import re
        m = re.search(r"<title[^>]*>([^<]+)</title>", body, re.I)
        return m.group(1).strip()[:80] if m else None

    def _analyze_findings(self, response, discovered,
                           algeria_info, ssl_result, dns_result) -> List[Dict]:
        findings = []

        # â”€â”€ Ù…Ù† SSL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if ssl_result:
            for vuln in ssl_result.vulnerabilities:
                findings.append({
                    "name":           f"SSL/TLS: {vuln['vuln']}",
                    "severity":       vuln["severity"].lower(),
                    "detail":         vuln["description"],
                    "recommendation": vuln.get("fix", ""),
                    "source":         "ssl_analysis",
                    "cve":            vuln.get("cve", ""),
                })
            if ssl_result.grade in ("C", "D", "F"):
                findings.append({
                    "name":           f"Poor SSL/TLS Grade: {ssl_result.grade}",
                    "severity":       "high",
                    "detail":         f"SSL Labs equivalent grade: {ssl_result.grade} "
                                      f"(score {ssl_result.grade_score}/100)",
                    "recommendation": "Review TLS configuration, disable old protocols",
                    "source":         "ssl_analysis",
                })

        # â”€â”€ Ù…Ù† DNS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if dns_result:
            for issue in dns_result.security_issues:
                findings.append({
                    "name":           f"DNS: {issue['title']}",
                    "severity":       issue["severity"].lower(),
                    "detail":         issue["detail"],
                    "recommendation": issue["fix"],
                    "source":         "dns_analysis",
                })

        # â”€â”€ Ù…Ù† HTTP headers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        sec_headers = [
            "x-frame-options", "x-content-type-options",
            "content-security-policy", "strict-transport-security",
            "referrer-policy", "permissions-policy",
        ]
        missing = [h for h in sec_headers if not response.get_header(h)]
        if missing:
            findings.append({
                "name":           "Missing Security Headers",
                "severity":       "medium",
                "detail":         f"Missing: {', '.join(missing)}",
                "recommendation": "Add all security headers in web server config",
                "source":         "http_headers",
            })

        # â”€â”€ Server version disclosure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        server = response.get_header("server")
        if server and any(x in server.lower()
                          for x in ["apache/", "nginx/", "iis/", "php/"]):
            findings.append({
                "name":           "Server Version Disclosure",
                "severity":       "low",
                "detail":         f"Server header: {server}",
                "recommendation": "Remove version info: ServerTokens Prod (Apache) / server_tokens off (Nginx)",
                "source":         "http_headers",
            })

        # â”€â”€ Exposed sensitive files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        sensitive = [d for d in discovered if any(
            x in d["url"] for x in [".env", ".git", "phpinfo", "backup"]
        )]
        for s in sensitive:
            if s["status"] == 200:
                findings.append({
                    "name":           f"Sensitive File Exposed: {s['url'].split('/')[-1]}",
                    "severity":       "critical",
                    "detail":         f"File accessible: {s['url']}",
                    "recommendation": "Remove or restrict access immediately",
                    "source":         "endpoint_discovery",
                })

        # â”€â”€ Exposed admin panels â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        admin = [d for d in discovered if any(
            x in d["url"] for x in ["admin", "wp-admin", "cpanel", "phpmyadmin"]
        )]
        for a in admin:
            findings.append({
                "name":           "Exposed Admin Interface",
                "severity":       "high",
                "detail":         f"Admin accessible: {a['url']} (HTTP {a['status']})",
                "recommendation": "Restrict by IP, enable 2FA, use non-default path",
                "source":         "endpoint_discovery",
            })

        # â”€â”€ Algeria Decree 26-07 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if algeria_info and algeria_info.is_government:
            if not response.get_header("strict-transport-security"):
                findings.append({
                    "name":           "Decree 26-07 Violation: No HSTS",
                    "severity":       "high",
                    "detail":         "Missing Strict-Transport-Security header",
                    "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    "source":         "compliance",
                    "compliance":     "Decree_26_07_Article_12",
                })

        # Ø±ØªÙ‘Ø¨ Ù…Ù† Ø§Ù„Ø£Ø®Ø·Ø±
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda x: sev_order.get(x["severity"], 5))
        return findings

    def _save_report(self, target: str):
        output_dir = Path("./results")
        output_dir.mkdir(exist_ok=True)

        safe = target.replace("/", "_").replace(":", "_")
        base = output_dir / f"{self.session_id}_{safe}"

        # JSON
        with open(f"{base}.json", "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2,
                      ensure_ascii=False, default=str)
        print(f"\n[+] JSON report: {base}.json")

        # TXT
        txt = self._generate_text_report()
        with open(f"{base}.txt", "w", encoding="utf-8") as f:
            f.write(txt)
        print(f"[+] TXT report:  {base}.txt")

    def _generate_text_report(self) -> str:
        lines = [
            f"RECON-DZ v{self.VERSION} Security Assessment",
            "=" * 60,
            f"Session:   {self.session_id}",
            f"Target:    {self.results['target']['input']}",
            f"Generated: {self.results['timestamp']}",
            "",
        ]

        # Algeria context
        ctx = self.results.get("algerian_context")
        if ctx:
            lines += [
                "ALGERIAN CONTEXT",
                "-" * 40,
                f"Sector:      {ctx['sector']}",
                f"Criticality: {ctx['criticality']}",
                f"ISP:         {ctx['isp']}",
                "",
            ]

        # DNS
        dns = self.results.get("dns_intel", {})
        if dns:
            lines += [
                "DNS INTELLIGENCE",
                "-" * 40,
                f"DNS Records: {dns.get('stats', {}).get('total_dns_records', 0)}",
                f"Subdomains:  {dns.get('stats', {}).get('total_subdomains', 0)}",
            ]
            whois = dns.get("whois")
            if whois:
                lines += [
                    f"Registrar:   {whois.get('registrar', '')}",
                    f"Created:     {whois.get('creation_date', '')}",
                    f"Expires:     {whois.get('expiry_date', '')}",
                    f"DNSSEC:      {whois.get('dnssec', '')}",
                ]
            subs = dns.get("subdomains", [])
            if subs:
                lines.append(f"\nSubdomains found ({len(subs)}):")
                for s in subs[:20]:
                    lines.append(f"  {s['subdomain']:<45} {s.get('ip','')}")
            lines.append("")

        # SSL
        ssl_d = self.results.get("ssl_intel", {})
        if ssl_d:
            lines += [
                "SSL/TLS ANALYSIS",
                "-" * 40,
                f"Grade:     {ssl_d.get('grade', '?')}  "
                f"(Score: {ssl_d.get('score', 0)}/100)",
                f"Protocols: {', '.join(ssl_d.get('protocols', {}).get('supported', []))}",
            ]
            cert = ssl_d.get("certificate")
            if cert:
                lines += [
                    f"Cert CN:   {cert.get('subject_cn', '')}",
                    f"Issuer:    {cert.get('issuer_cn', '')}",
                    f"Expires:   {cert.get('not_after', '')} "
                    f"({cert.get('days_remaining', 0)} days)",
                ]
            for v in ssl_d.get("vulnerabilities", []):
                lines.append(f"  [{v['severity']}] {v['vuln']}: {v['description'][:60]}")
            lines.append("")

        # Findings
        findings = self.results.get("findings", [])
        lines += [
            "SECURITY FINDINGS",
            "-" * 40,
            f"Total: {len(findings)}",
            "",
        ]
        for f in findings:
            lines += [
                f"[{f['severity'].upper()}] {f['name']}",
                f"  Detail: {f['detail'][:120]}",
                f"  Fix:    {f.get('recommendation', '')[:120]}",
                "",
            ]

        lines += ["=" * 60, "END OF REPORT", f"RECON-DZ v{self.VERSION}"]
        return "\n".join(lines)

    def _print_summary(self, algeria_info, ssl_result,
                        dns_result, discovered, findings):
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            s = f.get("severity", "low")
            sev[s] = sev.get(s, 0) + 1

        print(f"\n{'='*60}")
        print("  FINAL SUMMARY")
        print(f"{'='*60}")
        print(f"  Target:      {self.results['target']['input']}")
        if algeria_info:
            print(f"  Algerian:    YES â€” {algeria_info.sector} / "
                  f"{algeria_info.criticality}")
        if ssl_result:
            print(f"  SSL Grade:   {ssl_result.grade} "
                  f"({ssl_result.grade_score}/100)")
        if dns_result:
            print(f"  Subdomains:  {len(dns_result.subdomains)}")
            print(f"  DNS Issues:  {len(dns_result.security_issues)}")
        print(f"  Endpoints:   {len(discovered)}")
        print(f"  Findings:    {sum(sev.values())} total")
        for s, n in sev.items():
            if n:
                print(f"    {s.upper():<10} {n}")
        print(f"{'='*60}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  CLI
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def main():
    parser = argparse.ArgumentParser(
        description="RECON-DZ v2.1 - Advanced Security Reconnaissance",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_dz_v2.py -t univ-medea.dz -v
  python recon_dz_v2.py -t allojibli.dz --depth deep
  python recon_dz_v2.py -t example.dz --no-dns
  python recon_dz_v2.py -t example.dz --no-ssl
        """,
    )
    parser.add_argument("-t", "--target",       required=True,
                        help="Target domain")
    parser.add_argument("-v", "--verbose",       action="store_true")
    parser.add_argument("--internal",            action="store_true",
                        help="Internal network mode")
    parser.add_argument("--depth",
                        choices=["quick", "normal", "deep"],
                        default="normal")
    parser.add_argument("--max-concurrent",      type=int, default=30)
    parser.add_argument("--no-dns",              action="store_true",
                        help="Skip DNS intelligence")
    parser.add_argument("--no-ssl",              action="store_true",
                        help="Skip SSL/TLS analysis")

    args = parser.parse_args()

    print("\n[!] WARNING: Authorized security assessment only.\n")

    fw = RECONDZv2(verbose=args.verbose, internal_mode=args.internal)

    try:
        asyncio.run(_run(fw, args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


async def _run(fw, args):
    await fw.initialize(max_concurrent=args.max_concurrent)
    try:
        await fw.scan(
            args.target,
            depth    = args.depth,
            scan_dns = not args.no_dns,
            scan_ssl = not args.no_ssl,
        )
    finally:
        await fw.close()


if __name__ == "__main__":
    main()
