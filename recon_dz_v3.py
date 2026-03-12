#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║          RECON-DZ v3 - Advanced Security Reconnaissance          ║
║          Professional-grade tool for authorized assessment        ║
║                                                                   ║
║  Features:                                                        ║
║  • DNS-over-HTTPS (bypasses censorship / Termux restrictions)     ║
║  • Async engine with stealth mode + rate limiting                 ║
║  • Algeria-specific threat intelligence (sectors, ISPs, laws)     ║
║  • Subdomain enumeration (crt.sh + HackerTarget + bruteforce)     ║
║  • Port scanning with banner grabbing & vuln hints                ║
║  • CMS detection with version extraction (10 platforms)           ║
║  • Server fingerprinting + SSL/TLS analysis                       ║
║  • Vulnerability scanning (headers, files, compliance)            ║
║  • JSON + TXT reports with executive summary                      ║
╚══════════════════════════════════════════════════════════════════╝

Author:  RECON-DZ Team
Version: 3.0.0
License: Authorized Security Assessment Only
"""

import asyncio
import argparse
import json
import sys
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.async_engine import AsyncReconEngine, detect_waf_response
from core.algeria_threats import AlgeriaThreatDatabase
from core.ip_utils import extract_real_ip
from core.ip_enumerator import IPEnumerator
from core.domain_validator import DomainValidator
from core.subdomain_enum import SubdomainEnumerator
from core.cms_detector import CMSDetector
from core.port_scanner import PortScanner
from core.server_fingerprint import ServerFingerprinter
from core.vuln_scanner import VulnScanner

# ──────────────────────────────────────────────────────────────────────
#  ANSI colours (degrade gracefully if terminal doesn't support them)
# ──────────────────────────────────────────────────────────────────────
try:
    import colorama
    colorama.init(autoreset=True)
    R  = colorama.Fore.RED
    G  = colorama.Fore.GREEN
    Y  = colorama.Fore.YELLOW
    C  = colorama.Fore.CYAN
    M  = colorama.Fore.MAGENTA
    B  = colorama.Style.BRIGHT
    RS = colorama.Style.RESET_ALL
except ImportError:
    R = G = Y = C = M = B = RS = ''

_SEV_COLOR = {'critical': R + B, 'high': R, 'medium': Y, 'low': C, 'info': ''}


def _c(sev: str, text: str) -> str:
    """Wrap text in severity colour."""
    return f"{_SEV_COLOR.get(sev, '')}{text}{RS}"


# ══════════════════════════════════════════════════════════════════════
#  Main Framework Class
# ══════════════════════════════════════════════════════════════════════

class RECONDZv3:
    """
    RECON-DZ v3 Main Controller.
    Orchestrates all scanning phases with async concurrency.
    """

    VERSION  = "3.0.0"
    CODENAME = "Djurdjura"
    LICENSE  = "Authorized Security Assessment Only"

    def __init__(self,
                 verbose:              bool = False,
                 internal_mode:        bool = False,
                 enumerate_domains:    bool = False,
                 enumerate_subdomains: bool = False,
                 scan_ports:           bool = False,
                 detect_cms:           bool = False,
                 fingerprint:          bool = False,
                 vuln_scan:            bool = False,
                 output_dir:           str  = './results'):

        self.verbose              = verbose
        self.internal_mode        = internal_mode
        self.enumerate_domains    = enumerate_domains
        self.enumerate_subdomains = enumerate_subdomains
        self.scan_ports           = scan_ports
        self.detect_cms           = detect_cms
        self.fingerprint          = fingerprint
        self.vuln_scan            = vuln_scan
        self.output_dir           = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.engine:     Optional[AsyncReconEngine]    = None
        self.algeria_db: AlgeriaThreatDatabase         = AlgeriaThreatDatabase()
        self.results:    Dict[str, Any]                = {}
        self.session_id: str = datetime.now().strftime("%Y%m%d_%H%M%S")

    # ──────────────────── Lifecycle ───────────────────────────────────

    async def initialize(self, max_concurrent: int = 30):
        """Initialize the async engine."""
        print(f"\n{B}{C}╔{'═'*56}╗")
        print(f"║  RECON-DZ v{self.VERSION} — {self.CODENAME:<40}║")
        print(f"║  {self.LICENSE:<54}║")
        print(f"╚{'═'*56}╝{RS}\n")

        delay = (0.3, 1.2) if not self.internal_mode else (0.05, 0.3)
        self.engine = AsyncReconEngine(
            max_concurrent=max_concurrent,
            enable_stealth=True,
            internal_mode=self.internal_mode,
            delay_range=delay,
        )
        await self.engine.initialize()
        return self

    async def close(self):
        """Clean up connections."""
        if self.engine:
            await self.engine.close()

    # ──────────────────── Main Scan ───────────────────────────────────

    async def scan(self, target: str, depth: str = 'normal') -> Dict:
        """Execute the full reconnaissance pipeline."""

        # Count phases
        phases = self._count_phases()
        pc     = 0  # phase counter

        _hdr = f"{'─'*60}"
        print(f"\n{B}Target  : {Y}{target}")
        print(f"{B}Session : {Y}{self.session_id}")
        print(f"{B}Depth   : {Y}{depth}")
        print(f"{B}Phases  : {Y}{phases}")
        print(f"{_hdr}{RS}\n")

        # ── Phase 1: Intelligence ──────────────────────────────────────
        pc += 1
        _phase(pc, phases, "Algeria Threat Intelligence")
        algeria_info = self.algeria_db.identify_target(target)

        if algeria_info:
            print(f"  {G}[+]{RS} Algerian target detected")
            print(f"      Sector     : {B}{algeria_info.sector.upper()}{RS}")
            print(f"      Criticality: {_c(algeria_info.criticality, algeria_info.criticality.upper())}")
            print(f"      ISP        : {algeria_info.isp}")
            if algeria_info.city:
                print(f"      City       : {algeria_info.city}")
            if algeria_info.compliance_requirements:
                print(f"      Compliance : {', '.join(algeria_info.compliance_requirements)}")
            if algeria_info.threat_actors:
                print(f"      Threat APTs: {', '.join(algeria_info.threat_actors)}")
        else:
            print(f"  {Y}[!]{RS} Non-Algerian target — general scan mode")

        # ── Phase 2: Connectivity ──────────────────────────────────────
        pc += 1
        _phase(pc, phases, "Connectivity & Protocol Assessment")
        response, protocol, actual_target = await self.engine.request_with_fallback(
            target, www_fallback=True
        )

        if response.status == 0:
            print(f"  {R}[-]{RS} Target unreachable: {response.error}")
            return {'error': 'unreachable', 'detail': response.error}

        base_url = f"{protocol}{actual_target}"
        print(f"  {G}[+]{RS} Connected: {B}{base_url}{RS}")
        print(f"      HTTP Status   : {response.status}")
        print(f"      Server        : {response.get_header('server', 'Unknown')}")
        print(f"      Response Time : {response.elapsed:.2f}s")
        if response.redirect_count:
            print(f"      Redirects     : {response.redirect_count}")

        # ── Phase 3: Technology Analysis ──────────────────────────────
        pc += 1
        _phase(pc, phases, "Technology Stack Analysis")
        techs = response.extract_technology_hints()
        if techs:
            print(f"  {G}[+]{RS} Detected technologies:")
            for t in techs:
                print(f"      • {t}")
        else:
            print(f"  {Y}[!]{RS} No clear technology indicators")

        waf = detect_waf_response(response)
        if waf:
            print(f"  {Y}[!]{RS} WAF/Protection detected: {B}{waf}{RS}")
        else:
            print(f"  {G}[+]{RS} No WAF detected")

        # ── Resolve Real IP ───────────────────────────────────────────
        target_ip = await extract_real_ip(actual_target, self.engine)
        if not target_ip:
            target_ip = await self.engine.resolve_hostname(actual_target)
        if target_ip:
            print(f"  {G}[+]{RS} IP address: {target_ip}")

        # ── Phase 4 (optional): Reverse IP Enumeration ────────────────
        ip_enum_data: Optional[Dict] = None
        if self.enumerate_domains:
            pc += 1
            _phase(pc, phases, "Reverse IP Domain Enumeration")
            if target_ip:
                enumerator = IPEnumerator(self.engine)
                raw_domains = await enumerator.enumerate(target_ip)
                print(f"  {G}[+]{RS} Found {len(raw_domains)} domain(s) on same IP")
                if raw_domains:
                    validator = DomainValidator(self.engine, self.algeria_db)
                    validated = await validator.validate_batch(raw_domains, concurrency=10)
                    active    = [d for d in validated if d.get('active')]
                    print(f"  {G}[+]{RS} Active co-hosted domains: {len(active)}")
                    for d in active[:12]:
                        ctx    = d.get('algerian_context') or {}
                        sector = ctx.get('sector', 'unknown')
                        print(f"      • {d['domain']} [{d.get('status','-')}] {sector}")
                    ip_enum_data = {
                        'real_ip':        target_ip,
                        'domains_found':  len(raw_domains),
                        'active_domains': len(active),
                        'domains':        validated,
                    }
            else:
                print(f"  {Y}[-]{RS} Could not determine target IP")

        # ── Phase 5 (optional): Subdomain Enumeration ─────────────────
        subdomain_data: Optional[Dict] = None
        if self.enumerate_subdomains:
            pc += 1
            _phase(pc, phases, "Subdomain Enumeration (CT + Brute-force)")
            sub_enum = SubdomainEnumerator(self.engine, self.algeria_db)
            subs     = await sub_enum.enumerate(actual_target, concurrency=50)
            print(f"  {G}[+]{RS} Active subdomains discovered: {len(subs)}")
            for s in subs[:20]:
                ctx    = s.get('algerian_context') or {}
                sector = ctx.get('sector', 'unknown')
                print(f"      • {s['domain']} [{s.get('status','-')}] {sector}")
            if len(subs) > 20:
                print(f"      ... and {len(subs)-20} more")
            subdomain_data = {'found': len(subs), 'subdomains': subs}

        # ── Phase 6 (optional): Port Scanning ─────────────────────────
        port_data: Optional[Dict] = None
        if self.scan_ports:
            pc += 1
            _phase(pc, phases, "TCP Port Scanning")
            if target_ip:
                scanner    = PortScanner(timeout=2.0, max_concurrent=150)
                open_ports = await scanner.scan(target_ip)
                print(f"  {G}[+]{RS} Open ports: {len(open_ports)}")
                for p in open_ports[:25]:
                    banner_str = f" — {p.banner[:60]}" if p.banner else ''
                    vuln_str   = f" {R}⚠ {p.vulns[0]}{RS}" if p.vulns else ''
                    print(f"      • {p.port:>5}/tcp  {p.service:<12}"
                          f"{banner_str[:60]}{vuln_str}")
                port_data = {
                    'real_ip':    target_ip,
                    'open_ports': [
                        {'port': p.port, 'service': p.service,
                         'banner': p.banner, 'version': p.version,
                         'vulns': p.vulns}
                        for p in open_ports
                    ],
                }
            else:
                print(f"  {Y}[-]{RS} No IP available for port scanning")

        # ── Phase 7 (optional): CMS Detection ─────────────────────────
        cms_data: Optional[List] = None
        if self.detect_cms:
            pc += 1
            _phase(pc, phases, "CMS Detection & Version Extraction")
            detector = CMSDetector()
            cms_list = await detector.detect(base_url, self.engine)
            if cms_list:
                print(f"  {G}[+]{RS} CMS detected:")
                for cms in cms_list:
                    ver  = f" v{cms['version']}" if cms.get('version') else ''
                    meth = ', '.join(cms.get('methods', []))
                    print(f"      • {B}{cms['name']}{ver}{RS}"
                          f" [{cms['confidence']}] via {meth}")
                cms_data = cms_list
            else:
                print(f"  {Y}[!]{RS} No CMS detected")

        # ── Phase 8 (optional): Server Fingerprinting ─────────────────
        fingerprint_data: Optional[Dict] = None
        if self.fingerprint and port_data:
            pc += 1
            _phase(pc, phases, "Server Fingerprinting & SSL/TLS Analysis")
            fp = ServerFingerprinter(self.engine)
            fingerprint_data = await fp.fingerprint(
                target_ip, port_data['open_ports']
            )
            print(f"  {G}[+]{RS} OS Guess : {fingerprint_data.get('os', 'Unknown')}")
            if fingerprint_data.get('technologies'):
                for t in fingerprint_data['technologies'][:5]:
                    print(f"      • {t['type']}: {t['name']}")
            ssl_info = fingerprint_data.get('ssl_info')
            if ssl_info:
                proto  = ssl_info.get('protocol_version', 'unknown')
                cipher = ssl_info.get('cipher_suite', 'unknown')
                print(f"      SSL : {proto} / {cipher}")
                for issue in ssl_info.get('issues', []):
                    print(f"      {R}⚠ {issue}{RS}")

        # ── Phase 9: Endpoint Discovery ───────────────────────────────
        pc += 1
        _phase(pc, phases, "Endpoint & Path Discovery")
        paths   = _get_discovery_paths(algeria_info)
        urls    = [f"{base_url.rstrip('/')}{p}" for p in paths]
        print(f"  {C}[*]{RS} Probing {len(urls)} endpoints...")

        discovered: List[Dict] = []
        for i, url in enumerate(urls, 1):
            resp = await self.engine.request(url)
            if resp.status != 0:
                ep = {
                    'url':         url,
                    'status':      resp.status,
                    'size':        len(resp.body),
                    'title':       _extract_title(resp.body),
                    'server':      resp.get_header('server'),
                    'redirect_to': resp.final_url if resp.final_url != url else '',
                }
                interesting = (
                    resp.is_success or
                    resp.status in (301, 302, 307, 308, 401, 403)
                )
                if interesting:
                    discovered.append(ep)
                    icon   = (f"{G}[+]{RS}" if resp.status == 200 else
                               f"{C}[>]{RS}" if resp.status in (301, 302) else
                               f"{Y}[!]{RS}")
                    title  = f' "{ep["title"][:40]}"' if ep.get('title') else ''
                    redir  = f' → {ep["redirect_to"][:50]}' if ep.get('redirect_to') else ''
                    print(f"      {icon} [{resp.status}] {url}{title}{redir}")
            if i % 15 == 0 and i < len(urls):
                print(f"      Progress: {i}/{len(urls)}")

        # ── Phase 10: Vulnerability Scanning ──────────────────────────
        pc += 1
        vuln_findings: List[Dict] = []
        if self.vuln_scan:
            _phase(pc, phases, "Vulnerability & Compliance Scanning")
            scanner  = VulnScanner(self.engine)
            raw_findings = await scanner.scan(base_url, response, algeria_info)
            vuln_findings = [f.to_dict() for f in raw_findings]
            print(f"  {G}[+]{RS} Findings: {len(vuln_findings)}")
            for f in raw_findings[:8]:
                print(f"      {_c(f.severity, f'[{f.severity.upper()}]')} {f.name}")
        else:
            _phase(pc, phases, "Security Analysis (Basic)")
            # Fallback basic analysis
            raw_findings = _basic_security_analysis(response, discovered, algeria_info)
            vuln_findings = [f.to_dict() for f in raw_findings]
            if vuln_findings:
                for f in raw_findings[:5]:
                    print(f"      {_c(f.severity, f'[{f.severity.upper()}]')} {f.name}")

        # ── Compile Results ────────────────────────────────────────────
        self.results = {
            'framework': {
                'name':    'RECON-DZ',
                'version': self.VERSION,
                'session': self.session_id,
                'license': self.LICENSE,
            },
            'target': {
                'input':    target,
                'resolved': actual_target,
                'base_url': base_url,
                'protocol': protocol,
                'ip':       target_ip,
            },
            'algerian_context': algeria_info.__dict__ if algeria_info else None,
            'connection': {
                'status':          response.status,
                'response_time_s': round(response.elapsed, 3),
                'server':          response.get_header('server'),
                'powered_by':      response.get_header('x-powered-by'),
                'redirects':       response.redirect_count,
            },
            'technologies': techs,
            'protection': {
                'waf':           waf,
                'internal_mode': self.internal_mode,
            },
            'discovery': {
                'paths_tested': len(urls),
                'found':        len(discovered),
                'endpoints':    discovered,
            },
            'findings':   vuln_findings,
            # [FIX] Use get_stats() instead of direct dict reference
            'statistics': self.engine.get_stats(),
            'timestamp':  datetime.now().isoformat(),
        }

        # Attach optional modules
        if ip_enum_data:      self.results['ip_enumeration'] = ip_enum_data
        if subdomain_data:    self.results['subdomains']     = subdomain_data
        if port_data:         self.results['port_scan']      = port_data
        if cms_data:          self.results['cms']            = cms_data
        if fingerprint_data:  self.results['fingerprint']    = fingerprint_data

        self._save_report(actual_target)
        self._print_summary(
            algeria_info, response, discovered, vuln_findings,
            ip_enum_data, subdomain_data, port_data, cms_data,
            fingerprint_data, target_ip
        )
        return self.results

    # ──────────────────── Report Generation ───────────────────────────

    def _save_report(self, target: str):
        """Save JSON and text reports to output_dir."""
        safe   = re.sub(r'[/\\:*?"<>|]', '_', target)
        stem   = f"{self.session_id}_{safe}"

        json_path = self.output_dir / f"{stem}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)
        print(f"\n  {G}[+]{RS} JSON report : {json_path}")

        txt_path = self.output_dir / f"{stem}.txt"
        with open(txt_path, 'w', encoding='utf-8') as f:
            f.write(self._generate_text_report())
        print(f"  {G}[+]{RS} Text report : {txt_path}")

    def _generate_text_report(self) -> str:
        r = self.results
        lines: List[str] = [
            f"RECON-DZ v{self.VERSION} — Security Assessment Report",
            "=" * 68,
            f"Session    : {r['framework']['session']}",
            f"Target     : {r['target']['input']}",
            f"Base URL   : {r['target']['base_url']}",
            f"IP Address : {r['target']['ip'] or 'Unknown'}",
            f"Generated  : {r['timestamp']}",
            "",
        ]

        # Algeria context
        ctx = r.get('algerian_context')
        if ctx:
            lines += [
                "ALGERIAN INFRASTRUCTURE",
                "─" * 40,
                f"Sector      : {ctx['sector']}",
                f"Criticality : {ctx['criticality']}",
                f"ISP         : {ctx['isp']}",
                f"City        : {ctx.get('city') or 'Unknown'}",
                f"Compliance  : {', '.join(ctx.get('compliance_requirements', []))}",
                f"Threat APTs : {', '.join(ctx.get('threat_actors', []))}",
                "",
            ]

        # Connection
        conn = r['connection']
        lines += [
            "CONNECTION SUMMARY",
            "─" * 40,
            f"HTTP Status   : {conn['status']}",
            f"Response Time : {conn['response_time_s']}s",
            f"Server        : {conn.get('server', 'Unknown')}",
            f"WAF           : {r['protection']['waf'] or 'None detected'}",
            "",
        ]

        # Findings
        findings = r.get('findings', [])
        lines += ["SECURITY FINDINGS", "─" * 40]
        if findings:
            for f in findings:
                lines += [
                    f"[{f['severity'].upper()}] {f['name']}",
                    f"  Category : {f['category']}",
                    f"  Detail   : {f['detail']}",
                    f"  Action   : {f['recommendation']}",
                    "",
                ]
        else:
            lines += ["No significant findings.", ""]

        # Endpoints
        lines += [
            "ENDPOINT DISCOVERY",
            "─" * 40,
            f"Tested : {r['discovery']['paths_tested']}",
            f"Found  : {r['discovery']['found']}",
        ]
        for ep in r['discovery']['endpoints'][:30]:
            lines.append(f"  [{ep['status']}] {ep['url']}"
                         + (f" — {ep['title']}" if ep.get('title') else ''))
        lines.append("")

        # Subdomains
        if r.get('subdomains'):
            sd = r['subdomains']
            lines += ["SUBDOMAINS", "─" * 40,
                      f"Total active: {sd['found']}", ""]

        # Port scan
        if r.get('port_scan'):
            lines += ["PORT SCAN", "─" * 40]
            for p in r['port_scan']['open_ports']:
                banner = f" — {p['banner'][:80]}" if p.get('banner') else ''
                lines.append(f"  {p['port']}/tcp  {p['service']}{banner}")
            lines.append("")

        # CMS
        if r.get('cms'):
            lines += ["CMS DETECTION", "─" * 40]
            for c in r['cms']:
                ver = f" v{c['version']}" if c.get('version') else ''
                lines.append(f"  {c['name']}{ver} [{c['confidence']}]")
            lines.append("")

        # SSL
        if r.get('fingerprint', {}).get('ssl_info'):
            ssl = r['fingerprint']['ssl_info']
            lines += [
                "SSL/TLS ANALYSIS", "─" * 40,
                f"  Protocol : {ssl.get('protocol_version')}",
                f"  Cipher   : {ssl.get('cipher_suite')}",
                f"  CN       : {ssl.get('cert_cn')}",
                f"  Expiry   : {ssl.get('cert_expiry')}",
                f"  Issues   : {'; '.join(ssl.get('issues', [])) or 'None'}",
                "",
            ]

        # Stats
        stats = r.get('statistics', {})
        lines += [
            "SCAN STATISTICS", "─" * 40,
            f"  Total requests : {stats.get('requests_total', 0)}",
            f"  Successful     : {stats.get('requests_success', 0)}",
            f"  Failed         : {stats.get('requests_failed', 0)}",
            f"  Success rate   : {stats.get('success_rate_pct', 0)}%",
            "",
            "─" * 68,
            f"RECON-DZ v{self.VERSION} — Authorized Security Assessment Only",
        ]
        return '\n'.join(lines)

    def _print_summary(self, algeria_info, response, discovered,
                       findings, ip_enum_data, subdomain_data,
                       port_data, cms_data, fingerprint_data, target_ip):
        """Print a clean post-scan summary."""
        SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
        sev_counts = {s: sum(1 for f in findings if f.get('severity') == s)
                      for s in SEV_ORDER}

        print(f"\n{'═'*60}")
        print(f"{B}{C}  SCAN SUMMARY — RECON-DZ v{self.VERSION}{RS}")
        print(f"{'═'*60}")
        print(f"  Target    : {self.results['target']['input']}")
        if target_ip:
            print(f"  IP        : {target_ip}")
        if algeria_info:
            crit_color = _c(algeria_info.criticality, algeria_info.criticality.upper())
            print(f"  Algerian  : {G}YES{RS}  [{algeria_info.sector}] "
                  f"Criticality={crit_color}")
        else:
            print(f"  Algerian  : {Y}NO{RS}")

        print(f"  HTTP      : {response.status}  /  WAF: "
              f"{detect_waf_response(response) or 'none'}")
        print(f"  Endpoints : {len(discovered)}/{self.results['discovery']['paths_tested']} found")
        print(f"  Findings  : {len(findings)}", end='')
        parts = [f"{_c(s, f'{c} {s}')}" for s, c in sev_counts.items() if c]
        if parts:
            print(f"  ({', '.join(parts)})")
        else:
            print()

        if ip_enum_data:
            print(f"\n  Reverse IP : {ip_enum_data['domains_found']} domains"
                  f"  ({ip_enum_data['active_domains']} active)")
        if subdomain_data:
            print(f"  Subdomains : {subdomain_data['found']} active")
        if port_data:
            svcs = [p['service'] for p in port_data['open_ports']
                    if p['service'] != 'unknown'][:6]
            print(f"  Open Ports : {len(port_data['open_ports'])}"
                  + (f"  ({', '.join(svcs)})" if svcs else ''))
        if cms_data:
            names = [f"{c['name']}{' v'+c['version'] if c.get('version') else ''}"
                     for c in cms_data]
            print(f"  CMS        : {', '.join(names)}")
        if fingerprint_data:
            print(f"  OS Guess   : {fingerprint_data.get('os', 'Unknown')}")

        stats = self.engine.get_stats()
        print(f"\n  Requests   : {stats['requests_total']} "
              f"({stats['success_rate_pct']}% success)")
        print(f"{'═'*60}\n")

    # ──────────────────── Helpers ──────────────────────────────────────

    def _count_phases(self) -> int:
        """Count total scan phases."""
        base = 5  # intelligence + connectivity + tech + endpoint + security
        return (base
                + self.enumerate_domains
                + self.enumerate_subdomains
                + self.scan_ports
                + self.detect_cms
                + self.fingerprint)


# ══════════════════════════════════════════════════════════════════════
#  Module-Level Helpers
# ══════════════════════════════════════════════════════════════════════

def _phase(current: int, total: int, name: str):
    print(f"\n{B}{C}[Phase {current}/{total}]{RS} {name}")


def _extract_title(body: str) -> Optional[str]:
    if not body:
        return None
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.IGNORECASE)
    if m:
        return re.sub(r'\s+', ' ', m.group(1)).strip()
    return None


def _get_discovery_paths(algeria_info) -> List[str]:
    """Return sector-aware list of paths to probe."""
    base = [
        '/', '/robots.txt', '/.well-known/security.txt', '/sitemap.xml',
        '/favicon.ico', '/crossdomain.xml', '/humans.txt',
    ]
    common = [
        '/admin/', '/administrator/', '/login', '/signin',
        '/api/', '/api/v1/', '/api/v2/', '/graphql',
        '/wp-admin/', '/phpmyadmin/', '/cpanel/', '/webmail/',
        '/swagger.json', '/openapi.json', '/actuator',
        '/.env', '/.git/HEAD', '/server-status',
    ]
    if not algeria_info:
        return base + common

    sector_paths = {
        'government': [
            '/portail/', '/extranet/', '/intranet/',
            '/e-service/', '/formulaire/', '/declaration/',
        ],
        'banking': [
            '/api/mobile/', '/e-banking/', '/ib/',
            '/corporate/', '/swift/', '/auth/',
        ],
        'telecom': [
            '/portal/', '/customer/', '/myaccount/',
            '/recharge/', '/services/4g/', '/services/5g/',
        ],
        'education': [
            '/portal/', '/student/', '/campus/',
            '/moodle/', '/courses/', '/library/',
            '/research/', '/staff/', '/lms/',
        ],
        'health': [
            '/patient/', '/dossier/', '/rdv/',
            '/pharmacie/', '/urgences/',
        ],
    }
    return base + common + sector_paths.get(algeria_info.sector, [])


def _basic_security_analysis(response, discovered, algeria_info) -> list:
    """Quick security analysis when vuln_scan is disabled."""
    from core.vuln_scanner import Finding
    findings: list = []

    # Missing security headers
    for hdr in ('strict-transport-security', 'x-frame-options',
                 'content-security-policy', 'x-content-type-options'):
        if not response.get_header(hdr):
            findings.append(Finding(
                name=f"Missing Header: {hdr}",
                severity='medium',
                category='misconfiguration',
                detail=f"Security header '{hdr}' is absent.",
                recommendation=f"Add the '{hdr}' response header.",
            ))

    # Admin panels exposed
    for ep in discovered:
        if any(x in ep['url'] for x in
               ('admin', 'wp-admin', 'cpanel', 'phpmyadmin', 'webadmin')):
            findings.append(Finding(
                name="Admin Interface Exposed",
                severity='high',
                category='exposure',
                detail=f"Admin URL reachable: {ep['url']}",
                recommendation="Restrict by IP, require 2FA.",
            ))

    # Algeria compliance
    if algeria_info and algeria_info.is_government:
        if not response.get_header('strict-transport-security'):
            findings.append(Finding(
                name="Decree 26-07 Violation: No HSTS",
                severity='critical',
                category='compliance',
                detail="Government sites must enforce HTTPS per Decree 26-07.",
                recommendation="Add HSTS header.",
                compliance=['Decree_26_07_Article_12'],
            ))

    return findings


# ══════════════════════════════════════════════════════════════════════
#  CLI Entry Point
# ══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description='RECON-DZ v3 — Advanced Security Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python recon_dz_v3.py -t example.dz

  # Full enumeration (all modules)
  python recon_dz_v3.py -t ministere.gov.dz -e

  # Selective: subdomains + ports + CMS + vuln scan
  python recon_dz_v3.py -t univ-medea.dz --subdomains --ports --cms --vuln

  # Internal network (fast, no delay)
  python recon_dz_v3.py -t 192.168.1.1 --internal --ports

  # Deep scan with custom output directory
  python recon_dz_v3.py -t target.dz -e --vuln --output-dir /tmp/recon
""",
    )
    p.add_argument('-t', '--target',          required=True,
                   help='Target domain or IP address')
    p.add_argument('-v', '--verbose',         action='store_true',
                   help='Verbose output')
    p.add_argument('--internal',              action='store_true',
                   help='Internal network mode (faster, shorter delays)')
    p.add_argument('--depth',
                   choices=['quick', 'normal', 'deep'], default='normal',
                   help='Scan depth preset (default: normal)')
    p.add_argument('--max-concurrent',        type=int, default=30,
                   help='Max concurrent HTTP requests (default: 30)')
    p.add_argument('--output-dir',            default='./results',
                   help='Output directory for reports (default: ./results)')
    p.add_argument('--version',               action='version',
                   version=f'RECON-DZ v{RECONDZv3.VERSION}')

    # Module flags
    g = p.add_argument_group('Enumeration modules')
    g.add_argument('-e', '--enumerate',       action='store_true',
                   help='Enable ALL enumeration modules')
    g.add_argument('--reverse-ip',            action='store_true',
                   help='Reverse IP lookup (co-hosted domains)')
    g.add_argument('--subdomains',            action='store_true',
                   help='Subdomain enumeration (crt.sh + brute-force)')
    g.add_argument('--ports',                 action='store_true',
                   help='TCP port scanning with banner grabbing')
    g.add_argument('--cms',                   action='store_true',
                   help='CMS detection and version extraction')
    g.add_argument('--fingerprint',           action='store_true',
                   help='Server fingerprinting + SSL/TLS analysis')
    g.add_argument('--vuln',                  action='store_true',
                   help='Full vulnerability and compliance scanning')

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    # -e / --enumerate enables all modules
    if args.enumerate:
        args.reverse_ip = args.subdomains = args.ports = True
        args.cms = args.fingerprint = args.vuln = True

    print(f"\n{Y}[!] WARNING: Authorized security assessment only.{RS}")
    print(f"    Unauthorized use is illegal and prohibited.\n")

    framework = RECONDZv3(
        verbose              = args.verbose,
        internal_mode        = args.internal,
        enumerate_domains    = args.reverse_ip,
        enumerate_subdomains = args.subdomains,
        scan_ports           = args.ports,
        detect_cms           = args.cms,
        fingerprint          = args.fingerprint,
        vuln_scan            = args.vuln,
        output_dir           = args.output_dir,
    )

    try:
        asyncio.run(_run(framework, args))
    except KeyboardInterrupt:
        print(f"\n{Y}[!] Scan interrupted by user{RS}")
        sys.exit(1)
    except Exception as exc:
        print(f"\n{R}[ERROR] {exc}{RS}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


async def _run(framework: RECONDZv3, args):
    await framework.initialize(max_concurrent=args.max_concurrent)
    try:
        await framework.scan(args.target, depth=args.depth)
    finally:
        await framework.close()


if __name__ == '__main__':
    main()
