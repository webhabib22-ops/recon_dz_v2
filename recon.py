#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗    ██████╗ ███████╗   ║
║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║   ██╔══██╗╚════██║   ║
║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║   ██║  ██║    ██╔╝   ║
║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║   ██║  ██║   ██╔╝    ║
║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║   ╚██████╔╝   ██║    ║
║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝    ╚═════╝    ╚═╝    ║
║                                                                      ║
║          الملف الرئيسي الموحد — Unified Command Center               ║
║          RECON-DZ v3.1 · Algeria Edition · All Tools Integrated      ║
╚══════════════════════════════════════════════════════════════════════╝

الأوامر المتاحة:
  python recon.py scan    → استطلاع كامل (recon + vuln + fingerprint)
  python recon.py waf     → تحليل WAF الدفاعي + تقرير HTML
  python recon.py batch   → مسح جماعي من ملف نصي
  python recon.py report  → إعادة توليد HTML من JSON موجود

التوثيق:
  python recon.py --help
  python recon.py scan --help
  python recon.py waf --help
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  IMPORTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
import asyncio
import argparse
import json
import sys
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# ── Core modules ───────────────────────────────────────────────────────
from core.async_engine       import AsyncReconEngine, ResponseData, detect_waf_response
from core.algeria_threats    import AlgeriaThreatDatabase
from core.ip_utils           import extract_real_ip
from core.ip_enumerator      import IPEnumerator
from core.domain_validator   import DomainValidator
from core.subdomain_enum     import SubdomainEnumerator
from core.cms_detector       import CMSDetector
from core.port_scanner       import PortScanner
from core.server_fingerprint import ServerFingerprinter
from core.vuln_scanner       import VulnScanner
from core.waf_analyzer       import (
    WAFAnalyzer, WAF_PROBES, WAFProfile,
    save_waf_report, generate_waf_html_report,
)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CONSTANTS & COLOURS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VERSION  = "3.1.0"
CODENAME = "Djurdjura"

try:
    import colorama; colorama.init(autoreset=True)
    R  = colorama.Fore.RED;    G  = colorama.Fore.GREEN
    Y  = colorama.Fore.YELLOW; C  = colorama.Fore.CYAN
    M  = colorama.Fore.MAGENTA; W = colorama.Fore.WHITE
    B  = colorama.Style.BRIGHT; RS = colorama.Style.RESET_ALL
except ImportError:
    R = G = Y = C = M = W = B = RS = ''

_SEV = {'critical': R+B, 'high': R, 'medium': Y, 'low': C, 'info': W}

def _c(sev: str, txt: str) -> str:
    return f"{_SEV.get(sev,'')}{txt}{RS}"

def _ph(n: int, total: int, name: str):
    print(f"\n{B}{C}╟─ [{n}/{total}] {name}{RS}")

def _sep(char='─', w=64):
    print(f"{C}{char*w}{RS}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def banner(mode: str = ''):
    mode_labels = {
        'scan':   f'{G}SCAN{RS}    ← Full Reconnaissance',
        'waf':    f'{Y}WAF{RS}     ← Defensive WAF Analysis',
        'batch':  f'{C}BATCH{RS}   ← Multi-Target Scan',
        'report': f'{M}REPORT{RS}  ← HTML Report Generator',
    }
    active = mode_labels.get(mode, '')
    print(f"""
{C}{B}╔══════════════════════════════════════════════════════════════╗
║  RECON-DZ v{VERSION} · {CODENAME:<47}║
║  Unified Security Reconnaissance & WAF Analysis Platform    ║
╚══════════════════════════════════════════════════════════════╝{RS}
  Mode : {active or f'{W}(choose: scan | waf | batch | report){RS}'}
  Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ENGINE FACTORY  — shared between all modes
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
async def build_engine(max_concurrent: int = 30,
                        internal: bool = False,
                        stealth: bool = True) -> AsyncReconEngine:
    delay = (0.05, 0.25) if internal else (0.2, 0.9)
    eng = AsyncReconEngine(
        max_concurrent=max_concurrent,
        enable_stealth=stealth,
        internal_mode=internal,
        delay_range=delay,
    )
    await eng.initialize()
    return eng

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SHARED HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _he(s) -> str:
    """HTML-escape a value."""
    return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')

def _title(body: str) -> Optional[str]:
    if not body: return None
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.I)
    return re.sub(r'\s+', ' ', m.group(1)).strip() if m else None

def _discovery_paths(ali) -> List[str]:
    """Return sector-aware URL paths to probe."""
    base = [
        '/', '/robots.txt', '/.well-known/security.txt', '/sitemap.xml',
        '/favicon.ico', '/crossdomain.xml',
    ]
    common = [
        '/admin/', '/administrator/', '/login', '/signin',
        '/api/', '/api/v1/', '/api/v2/', '/graphql',
        '/swagger.json', '/openapi.json', '/api-docs',
        '/wp-admin/', '/phpmyadmin/', '/cpanel/', '/webmail/',
        '/actuator', '/actuator/env', '/server-status',
        '/.env', '/.git/HEAD', '/phpinfo.php',
        '/backup/', '/config.php', '/docker-compose.yml',
        '/error.log', '/access.log',
    ]
    sector_paths: Dict[str, List[str]] = {
        'government': ['/portail/', '/extranet/', '/intranet/',
                       '/e-service/', '/formulaire/', '/declaration/'],
        'banking':    ['/e-banking/', '/ib/', '/corporate/',
                       '/swift/', '/auth/', '/api/mobile/'],
        'education':  ['/moodle/', '/lms/', '/student/', '/library/',
                       '/campus/', '/courses/', '/staff/'],
        'telecom':    ['/portal/', '/myaccount/', '/recharge/',
                       '/services/', '/4g/', '/5g/'],
        'health':     ['/patient/', '/dossier/', '/rdv/',
                       '/pharmacie/', '/urgences/'],
    }
    extra = sector_paths.get(getattr(ali, 'sector', ''), []) if ali else []
    return base + common + extra

def _grade(rate: float) -> Tuple[str, str]:
    """Return (letter, hex_color) for a detection/risk rate."""
    if rate >= 90: return 'A', '#10b981'
    if rate >= 75: return 'B', '#3b82f6'
    if rate >= 60: return 'C', '#f59e0b'
    if rate >= 40: return 'D', '#f97316'
    return 'F', '#ef4444'

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ███████╗ ██████╗ █████╗ ███╗  ██╗
#  ██╔════╝██╔════╝██╔══██╗████╗ ██║
#  ███████╗██║     ███████║██╔██╗██║
#  ╚════██║██║     ██╔══██║██║╚████║
#  ███████║╚██████╗██║  ██║██║ ╚███║
#  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
#  MODE: SCAN
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ScanMode:
    """
    Full reconnaissance pipeline.
    Integrates every core module in order.
    """

    def __init__(self, engine: AsyncReconEngine, args):
        self.e       = engine
        self.args    = args
        self.algeria = AlgeriaThreatDatabase()
        self.ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.out     = Path(getattr(args, 'output_dir', './results'))
        self.out.mkdir(parents=True, exist_ok=True)
        self.results: Dict[str, Any] = {}

    def _on(self, *flags: str) -> bool:
        """True if -e/--all or any of the given flags is set."""
        if getattr(self.args, 'enumerate', False):
            return True
        return any(getattr(self.args, f, False) for f in flags)

    def _phase_count(self) -> int:
        optional = sum([
            self._on('reverse_ip'),
            self._on('enumerate_subdomains'),
            self._on('ports'),
            self._on('cms'),
            self._on('fingerprint'),
            self._on('waf_check'),
        ])
        return 4 + optional  # base phases: intel + conn + endpoint + vuln

    # ── Entry Point ─────────────────────────────────────────────────
    async def run(self, target: str) -> Dict:
        TOTAL = self._phase_count()
        pc    = 0

        print(f"\n  {B}Target  :{RS} {Y}{target}{RS}")
        print(f"  {B}Session :{RS} {self.ts}")
        print(f"  {B}Phases  :{RS} {TOTAL}\n")

        # ── PHASE 1: Algeria Intelligence ─────────────────────────
        pc += 1; _ph(pc, TOTAL, "Algeria Threat Intelligence")
        ali = self.algeria.identify_target(target)
        if ali:
            crit = _c(ali.criticality, ali.criticality.upper())
            print(f"  {G}[+]{RS} Algerian target detected")
            print(f"      Sector      : {B}{ali.sector.upper()}{RS}")
            print(f"      Criticality : {crit}")
            print(f"      ISP         : {ali.isp}")
            if getattr(ali, 'city', None):
                print(f"      City        : {ali.city}")
            if getattr(ali, 'compliance_requirements', []):
                print(f"      Compliance  : {', '.join(ali.compliance_requirements)}")
            if getattr(ali, 'threat_actors', []):
                print(f"      Threat APTs : {R}{', '.join(ali.threat_actors)}{RS}")
        else:
            print(f"  {Y}[!]{RS} Non-Algerian target — general mode")

        # ── PHASE 2: Connectivity ─────────────────────────────────
        pc += 1; _ph(pc, TOTAL, "Connectivity & Protocol Detection")
        resp, proto, host = await self.e.request_with_fallback(
            target, www_fallback=True, path='/'
        )
        if resp.status == 0:
            print(f"  {R}[-] Unreachable:{RS} {resp.error}")
            return {'error': 'unreachable', 'target': target}

        base_url = f"{proto}{host}"
        waf      = detect_waf_response(resp)
        techs    = resp.extract_technology_hints()

        print(f"  {G}[+]{RS} {B}{base_url}{RS}  → HTTP {resp.status}  ({resp.elapsed:.2f}s)")
        print(f"      Server  : {resp.get_header('server','—')}")
        print(f"      WAF     : {(Y+waf+RS) if waf else (G+'None detected'+RS)}")
        if resp.redirect_count:
            print(f"      Redirects: {resp.redirect_count}")
        if techs:
            print(f"      Stack   : {', '.join(techs[:5])}")

        # Resolve real IP (needed by multiple phases)
        target_ip = await extract_real_ip(host, self.e)
        if not target_ip:
            target_ip = await self.e.resolve_hostname(host)
        if target_ip:
            print(f"      IP      : {target_ip}")

        # ── OPTIONAL: Reverse IP ──────────────────────────────────
        ip_data: Optional[Dict] = None
        if self._on('reverse_ip'):
            pc += 1; _ph(pc, TOTAL, "Reverse IP — Co-hosted Domain Enumeration")
            ip_data = await self._run_reverse_ip(host, target_ip)

        # ── OPTIONAL: Subdomains ──────────────────────────────────
        sub_data: Optional[Dict] = None
        if self._on('enumerate_subdomains'):
            pc += 1; _ph(pc, TOTAL, "Subdomain Enumeration (CT + Brute-force)")
            sub_data = await self._run_subdomains(host)

        # ── OPTIONAL: Port Scan ───────────────────────────────────
        port_data: Optional[Dict] = None
        if self._on('ports'):
            pc += 1; _ph(pc, TOTAL, "TCP Port Scanning & Banner Grabbing")
            port_data = await self._run_ports(target_ip)

        # ── OPTIONAL: CMS ─────────────────────────────────────────
        cms_data: Optional[List] = None
        if self._on('cms'):
            pc += 1; _ph(pc, TOTAL, "CMS Detection & Version Extraction")
            cms_data = await self._run_cms(base_url)

        # ── OPTIONAL: Fingerprint ─────────────────────────────────
        fp_data: Optional[Dict] = None
        if self._on('fingerprint'):
            pc += 1; _ph(pc, TOTAL, "Server Fingerprinting & SSL/TLS Analysis")
            fp_data = await self._run_fingerprint(target_ip, port_data)

        # ── PHASE: Endpoint Discovery (always) ────────────────────
        pc += 1; _ph(pc, TOTAL, "Endpoint & Path Discovery")
        discovered = await self._run_endpoints(base_url, ali)

        # ── PHASE: Vulnerability Analysis (always) ────────────────
        pc += 1; _ph(pc, TOTAL, "Vulnerability & Compliance Scan")
        findings = await self._run_vulns(base_url, resp, ali)

        # ── OPTIONAL: WAF Inline Check ────────────────────────────
        waf_data: Optional[Dict] = None
        if self._on('waf_check'):
            pc += 1; _ph(pc, TOTAL, "WAF Defensive Analysis (Inline)")
            waf_data = await self._run_waf_inline(base_url)

        # ── Compile & Save ────────────────────────────────────────
        self.results = {
            'meta': {
                'tool': 'RECON-DZ', 'version': VERSION,
                'session': self.ts, 'timestamp': datetime.now().isoformat(),
            },
            'target': {
                'input': target, 'resolved': host,
                'base_url': base_url, 'ip': target_ip,
            },
            'algerian_context': ali.__dict__ if ali else None,
            'connection': {
                'status': resp.status,
                'server': resp.get_header('server'),
                'waf': waf, 'time_s': round(resp.elapsed, 3),
                'redirects': resp.redirect_count,
            },
            'technologies': techs,
            'discovery': {
                'paths_tested': len(_discovery_paths(ali)),
                'found': len(discovered),
                'endpoints': discovered,
            },
            'findings':   findings,
            'statistics': self.e.get_stats(),
        }
        # Attach optional data
        if ip_data:    self.results['ip_enumeration'] = ip_data
        if sub_data:   self.results['subdomains']     = sub_data
        if port_data:  self.results['port_scan']      = port_data
        if cms_data:   self.results['cms']            = cms_data
        if fp_data:    self.results['fingerprint']    = fp_data
        if waf_data:   self.results['waf_analysis']   = waf_data

        paths = self._save_reports(host)
        self._print_summary(ali, resp, waf, target_ip, discovered,
                             findings, ip_data, sub_data, port_data,
                             cms_data, fp_data, waf_data, paths)
        return self.results

    # ── Phase Runners ────────────────────────────────────────────────
    async def _run_reverse_ip(self, host: str,
                               ip: Optional[str]) -> Optional[Dict]:
        if not ip:
            print(f"  {Y}[-]{RS} No IP resolved — skipping"); return None
        domains   = await IPEnumerator(self.e).enumerate(ip)
        validator = DomainValidator(self.e, self.algeria)
        validated = await validator.validate_batch(domains, concurrency=12)
        active    = [d for d in validated if d.get('active')]
        print(f"  {G}[+]{RS} Found {len(domains)} domain(s) sharing IP → "
              f"{G}{len(active)} active{RS}")
        for d in active[:12]:
            ctx = d.get('algerian_context') or {}
            sec = ctx.get('sector', '—')
            print(f"      • {d['domain']}  [{d.get('status','?')}]  {C}{sec}{RS}")
        if len(active) > 12:
            print(f"      … +{len(active)-12} more")
        return {
            'real_ip': ip,
            'total_domains': len(domains),
            'active_count':  len(active),
            'domains': validated,
        }

    async def _run_subdomains(self, host: str) -> Optional[Dict]:
        enumerator = SubdomainEnumerator(self.e, self.algeria)
        subs       = await enumerator.enumerate(host, concurrency=50)
        print(f"  {G}[+]{RS} {len(subs)} active subdomains discovered")
        for s in subs[:20]:
            ctx = s.get('algerian_context') or {}
            sec = ctx.get('sector', '—')
            srv = s.get('server', '')
            print(f"      • {s['domain']:<40}  [{s.get('status','?')}]  "
                  f"{C}{sec}{RS}  {Y}{srv}{RS}")
        if len(subs) > 20:
            print(f"      … +{len(subs)-20} more")
        return {'found': len(subs), 'subdomains': subs}

    async def _run_ports(self, ip: Optional[str]) -> Optional[Dict]:
        if not ip:
            print(f"  {Y}[-]{RS} No IP — skipping"); return None
        scanner = PortScanner(timeout=2.0, max_concurrent=150)
        ports   = await scanner.scan(ip)
        print(f"  {G}[+]{RS} {len(ports)} open port(s)")
        for p in ports[:25]:
            vuln  = f"  {R}⚠ {p.vulns[0][:55]}{RS}" if p.vulns else ''
            bnr   = f"  {(p.banner or '')[:50]}" if p.banner else ''
            print(f"      {p.port:>5}/tcp  {(p.service or '?'):<14}{bnr}{vuln}")
        return {
            'real_ip': ip,
            'open_ports': [
                {'port': p.port, 'service': p.service,
                 'banner': p.banner, 'version': p.version, 'vulns': p.vulns}
                for p in ports
            ],
        }

    async def _run_cms(self, base_url: str) -> Optional[List]:
        cms_list = await CMSDetector().detect(base_url, self.e)
        if cms_list:
            for c in cms_list:
                ver = f" v{c['version']}" if c.get('version') else ''
                mth = ', '.join(c.get('methods', []))
                print(f"  {G}[+]{RS} {B}{c['name']}{ver}{RS}  "
                      f"confidence={c['confidence']}  via {mth}")
        else:
            print(f"  {Y}[?]{RS} No CMS detected")
        return cms_list or None

    async def _run_fingerprint(self, ip: Optional[str],
                                port_data: Optional[Dict]) -> Optional[Dict]:
        if not ip:
            print(f"  {Y}[-]{RS} No IP — skipping"); return None
        ports = (port_data or {}).get('open_ports', [])
        fp    = await ServerFingerprinter(self.e).fingerprint(ip, ports)
        print(f"  {G}[+]{RS} OS Guess : {fp.get('os','Unknown')}")
        for t in fp.get('technologies', [])[:5]:
            print(f"      • {t.get('type','?')}: {t.get('name','?')}")
        ssl = fp.get('ssl_info')
        if ssl:
            proto  = ssl.get('protocol_version', '?')
            cipher = ssl.get('cipher_suite', '?')
            print(f"      SSL     : {proto} / {cipher}")
            cn  = ssl.get('cert_cn', '')
            exp = ssl.get('cert_expiry', '')
            if cn:  print(f"      Cert CN : {cn}")
            if exp: print(f"      Expiry  : {exp}")
            for iss in ssl.get('issues', []):
                print(f"      {R}⚠ {iss}{RS}")
        return fp

    async def _run_endpoints(self, base_url: str, ali) -> List[Dict]:
        paths = _discovery_paths(ali)
        urls  = [f"{base_url.rstrip('/')}{p}" for p in paths]
        print(f"  {C}[*]{RS} Probing {len(urls)} paths …")
        found: List[Dict] = []
        for url in urls:
            r = await self.e.request(url)
            if r.status == 0:
                continue
            interesting = (r.is_success or
                           r.status in (301, 302, 307, 401, 403))
            if not interesting:
                continue
            ep = {
                'url':    url,
                'status': r.status,
                'size':   len(r.body),
                'title':  _title(r.body),
                'server': r.get_header('server'),
            }
            found.append(ep)
            icon = (f"{G}[200]{RS}" if r.status == 200 else
                    f"{C}[{r.status}]{RS}" if r.status in (301,302,307) else
                    f"{Y}[{r.status}]{RS}")
            ti = f'  "{ep["title"][:40]}"' if ep.get('title') else ''
            print(f"      {icon} {url}{ti}")
        return found

    async def _run_vulns(self, base_url: str,
                          resp: ResponseData, ali) -> List[Dict]:
        scanner = VulnScanner(self.e)
        raw     = await scanner.scan(base_url, resp, ali)
        findings = [f.to_dict() for f in raw]
        if findings:
            for f in raw[:10]:
                print(f"  {_c(f.severity,'['+f.severity.upper()+']')} {f.name}")
            if len(findings) > 10:
                print(f"  … +{len(findings)-10} more findings (see report)")
        else:
            print(f"  {G}[+]{RS} No critical findings detected")
        return findings

    async def _run_waf_inline(self, base_url: str) -> Optional[Dict]:
        print(f"  {C}[*]{RS} Running WAF behavioral probe (66 payloads) …")
        analyzer = WAFAnalyzer(self.e, delay_between_probes=0.15)
        profile  = await analyzer.analyze(
            target_url=base_url,
            categories=None,   # all categories
            test_param='q',
        )
        paths  = save_waf_report(profile, str(self.out))
        grade, gclr = _grade(profile.detection_rate)
        print(f"  {G}[+]{RS} Detection rate : {profile.detection_rate:.1f}%  "
              f"Grade: {gclr}{grade}{RS}")
        print(f"  {'[!]' if profile.blind_spots else '[+]'} "
              f"Blind spots : {len(profile.blind_spots)}")
        for bs in profile.blind_spots[:3]:
            print(f"      {Y}⚠ {bs}{RS}")
        print(f"  {G}[+]{RS} WAF report : {paths['html']}")
        return {
            'waf_name':       profile.waf_detected,
            'detection_rate': profile.detection_rate,
            'grade':          grade,
            'blind_spots':    profile.blind_spots,
            'strong':         profile.strong_categories,
            'weak':           profile.weak_categories,
            'reports':        paths,
        }

    # ── Report Generation ────────────────────────────────────────────
    def _save_reports(self, host: str) -> Dict[str, str]:
        safe = re.sub(r'[^\w]', '_', host)[:40]
        stem = f"{self.ts}_{safe}"
        paths: Dict[str, str] = {}

        # JSON
        jp = self.out / f"{stem}.json"
        jp.write_text(
            json.dumps(self.results, indent=2,
                       ensure_ascii=False, default=str),
            encoding='utf-8'
        )
        paths['json'] = str(jp)

        # HTML
        hp = self.out / f"{stem}.html"
        hp.write_text(_build_scan_html(self.results), encoding='utf-8')
        paths['html'] = str(hp)

        # TXT
        tp = self.out / f"{stem}.txt"
        tp.write_text(_build_scan_txt(self.results), encoding='utf-8')
        paths['txt'] = str(tp)

        _sep()
        print(f"  {G}[+]{RS} JSON : {jp}")
        print(f"  {G}[+]{RS} HTML : {hp}")
        print(f"  {G}[+]{RS} TXT  : {tp}")
        return paths

    def _print_summary(self, ali, resp, waf, ip, disc, findings,
                        ip_data, sub_data, port_data, cms_data,
                        fp_data, waf_data, paths):
        sev = {s: sum(1 for f in findings if f.get('severity') == s)
               for s in ('critical','high','medium','low')}
        f_parts = [f"{_c(s, str(n)+' '+s)}" for s, n in sev.items() if n]
        stats = self.e.get_stats()

        print(f"\n{B}{C}{'═'*64}{RS}")
        print(f"  {B}SCAN COMPLETE  —  RECON-DZ v{VERSION}{RS}")
        print(f"{B}{C}{'═'*64}{RS}")
        print(f"  Target     : {self.results['target']['input']}")
        if ip: print(f"  IP         : {ip}")
        if ali:
            print(f"  Algerian   : {G}YES{RS}  [{ali.sector}]  "
                  f"Risk={_c(ali.criticality, ali.criticality.upper())}")
        print(f"  HTTP       : {resp.status}  │  WAF: "
              f"{(Y+waf+RS) if waf else (G+'none'+RS)}")
        print(f"  Endpoints  : {len(disc)} interesting paths found")
        print(f"  Findings   : {len(findings)}"
              + (f"  ({', '.join(f_parts)})" if f_parts else ''))
        if ip_data:
            print(f"  Rev IP     : {ip_data['active_count']} co-hosted domains")
        if sub_data:
            print(f"  Subdomains : {sub_data['found']} active")
        if port_data:
            svclist = [p['service'] for p in port_data['open_ports']
                       if p.get('service') and p['service'] != 'unknown'][:6]
            print(f"  Ports      : {len(port_data['open_ports'])} open"
                  + (f"  ({', '.join(svclist)})" if svclist else ''))
        if cms_data:
            print(f"  CMS        : "
                  f"{', '.join(c['name'] for c in cms_data)}")
        if waf_data:
            print(f"  WAF Grade  : {waf_data['grade']}  "
                  f"({waf_data['detection_rate']:.1f}% detection)")
        print(f"  Requests   : {stats['requests_total']} "
              f"({stats['success_rate_pct']}% success)")
        print(f"  Reports    : {paths['html']}")
        print(f"{B}{C}{'═'*64}{RS}\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ██╗    ██╗ █████╗ ███████╗
#  ██║    ██║██╔══██╗██╔════╝
#  ██║ █╗ ██║███████║█████╗
#  ██║███╗██║██╔══██║██╔══╝
#  ╚███╔███╔╝██║  ██║██║
#   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝
#  MODE: WAF
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class WAFMode:
    """
    Standalone defensive WAF analysis.
    Sends 66 known attack probes to your own WAF,
    measures detection rate, finds blind spots,
    generates interactive HTML + JSON reports.
    """

    def __init__(self, engine: AsyncReconEngine, args):
        self.e   = engine
        self.args = args
        self.out = Path(getattr(args, 'output_dir', './results'))
        self.out.mkdir(parents=True, exist_ok=True)

    async def run(self) -> WAFProfile:
        target = self.args.target
        param  = getattr(self.args, 'param', 'q')
        cats   = getattr(self.args, 'categories', None)
        delay  = getattr(self.args, 'delay', 0.3)

        _sep('═')
        total_probes = sum(len(v) for v in WAF_PROBES.items()
                           if not cats or any(c in v[0] for c in cats)) \
                       if cats else sum(len(v) for v in WAF_PROBES.values())
        print(f"  Target      : {Y}{target}{RS}")
        print(f"  Param       : ?{param}=<payload>")
        print(f"  Categories  : {cats or 'ALL'}")
        print(f"  Probes      : {total_probes}")
        print(f"  Delay       : {delay}s between probes")
        _sep('═')

        if not getattr(self.args, 'yes', False):
            ans = input(f"\n  {Y}[!]{RS} Confirm authorization to test this target [y/N]: ")
            if ans.strip().lower() != 'y':
                print(f"\n  {R}[-]{RS} Aborted."); return None
            print()

        analyzer = WAFAnalyzer(self.e, delay_between_probes=delay)
        profile  = await analyzer.analyze(
            target_url=target,
            categories=cats or None,
            test_param=param,
        )
        paths = save_waf_report(profile, str(self.out))

        # ── Console Summary ─────────────────────────────────────────
        grade, gclr = _grade(profile.detection_rate)
        behavior = profile.response_behavior
        total_b  = behavior.get('total_blocked', 0)
        total_p  = behavior.get('total_probes', 0)
        bypassed = total_p - total_b

        print(f"\n{B}{C}{'═'*64}{RS}")
        print(f"  {B}WAF ANALYSIS COMPLETE{RS}")
        print(f"{B}{C}{'═'*64}{RS}")
        print(f"  Target         : {target}")
        print(f"  WAF Identified : {profile.waf_detected or Y+'Not identified'+RS}")
        print(f"  Grade          : {gclr}{B}{grade}{RS}  "
              f"({profile.detection_rate:.1f}% detection rate)")
        print(f"  Blocked        : {G}{total_b}{RS}  /  "
              f"Bypassed: {R}{bypassed}{RS}  /  Total: {total_p}")

        if profile.strong_categories:
            print(f"\n  {G}Strong (≥80%):{RS}")
            for s in profile.strong_categories:
                rate = behavior.get('category_detection_rates',{}).get(s, 0)
                print(f"      {G}✓{RS} {s:<28} {rate:.0f}%")

        if profile.weak_categories:
            print(f"\n  {R}Weak (<50%):{RS}")
            for w in profile.weak_categories:
                rate = behavior.get('category_detection_rates',{}).get(w, 0)
                print(f"      {R}✗{RS} {w:<28} {rate:.0f}%")

        if profile.blind_spots:
            print(f"\n  {Y}Blind Spots:{RS}")
            for bs in profile.blind_spots:
                print(f"      {Y}⚠{RS} {bs}")

        # Evasion analysis
        ev = behavior.get('evasion_analysis', {})
        if ev:
            print(f"\n  Evasion Technique Analysis:")
            for atype, data in ev.items():
                concern = data.get('concern', False)
                icon    = f"{R}⚠{RS}" if concern else f"{G}✓{RS}"
                print(f"      {icon} {atype:<12}  "
                      f"Basic:{data['basic_detection_rate']:.0f}%  "
                      f"Evasion:{data['evasion_detection_rate']:.0f}%  "
                      f"Drop:{data['evasion_effectiveness']}")

        print(f"\n  {B}Top Recommendations:{RS}")
        for rec in profile.recommendations[:5]:
            pclr = (R if rec['priority']=='CRITICAL' else
                    Y if rec['priority']=='HIGH' else C)
            print(f"  {pclr}[{rec['priority']}]{RS} {rec['title']}")
            print(f"    → {rec['action']}")

        _sep()
        print(f"  {G}[+]{RS} HTML Report : {paths['html']}")
        print(f"  {G}[+]{RS} JSON Report : {paths['json']}")
        print(f"{B}{C}{'═'*64}{RS}\n")
        return profile


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ██████╗  █████╗ ████████╗ ██████╗██╗  ██╗
#  ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║  ██║
#  ██████╔╝███████║   ██║   ██║     ███████║
#  ██╔══██╗██╔══██║   ██║   ██║     ██╔══██║
#  ██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║
#  ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
#  MODE: BATCH
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BatchMode:
    """Scan multiple targets from a text file, one per line."""

    def __init__(self, engine: AsyncReconEngine, args):
        self.e    = engine
        self.args = args
        self.out  = Path(getattr(args, 'output_dir', './results'))
        self.out.mkdir(parents=True, exist_ok=True)

    async def run(self, filepath: str):
        fpath   = Path(filepath)
        targets = [l.strip() for l in fpath.read_text().splitlines()
                   if l.strip() and not l.startswith('#')]
        print(f"  {G}[+]{RS} Loaded {len(targets)} targets from {fpath.name}\n")

        rows: List[Dict] = []
        t0 = time.perf_counter()

        for i, target in enumerate(targets, 1):
            _sep()
            print(f"  [{i}/{len(targets)}]  {B}{target}{RS}")
            _sep()

            scanner = ScanMode(self.e, self.args)
            scanner.out = self.out

            try:
                res      = await scanner.run(target)
                findings = res.get('findings', [])
                rows.append({
                    'target':   target,
                    'ok':       True,
                    'status':   res.get('connection', {}).get('status', '?'),
                    'findings': len(findings),
                    'critical': sum(1 for f in findings if f.get('severity')=='critical'),
                    'high':     sum(1 for f in findings if f.get('severity')=='high'),
                    'waf':      res.get('connection', {}).get('waf') or 'none',
                    'ip':       res.get('target', {}).get('ip', '?'),
                })
            except Exception as exc:
                rows.append({'target': target, 'ok': False, 'error': str(exc)})
                print(f"  {R}[ERROR]{RS} {exc}")

        elapsed = time.perf_counter() - t0
        self._summary(rows, elapsed)

    def _summary(self, rows: List[Dict], elapsed: float):
        ok      = [r for r in rows if r.get('ok')]
        failed  = [r for r in rows if not r.get('ok')]
        n_crit  = sum(r.get('critical', 0) for r in ok)
        n_finds = sum(r.get('findings', 0) for r in ok)

        print(f"\n{B}{C}{'═'*64}{RS}")
        print(f"  {B}BATCH SCAN COMPLETE{RS}")
        print(f"{B}{C}{'═'*64}{RS}")
        print(f"  Targets   : {len(rows)}  ({G}{len(ok)} ok{RS} / "
              f"{R}{len(failed)} failed{RS})")
        print(f"  Time      : {elapsed:.1f}s  "
              f"({elapsed/max(len(rows),1):.1f}s avg)")
        print(f"  Findings  : {n_finds} total  ({R}{n_crit} critical{RS})")
        print()
        print(f"  {'TARGET':<35}  {'ST':>4}  {'FINDS':>5}  {'CRIT':>4}  WAF")
        print(f"  {'─'*35}  {'─'*4}  {'─'*5}  {'─'*4}  ─────────────")
        for r in rows:
            if r.get('ok'):
                crit_clr = R if r.get('critical') else ''
                print(f"  {r['target']:<35}  "
                      f"{str(r.get('status','?')):>4}  "
                      f"{str(r.get('findings',0)):>5}  "
                      f"{crit_clr}{str(r.get('critical',0)):>4}{RS}  "
                      f"{r.get('waf','none')}")
            else:
                print(f"  {r['target']:<35}  "
                      f"{R}FAIL{RS}  {r.get('error','')[:30]}")

        # Save batch JSON
        bpath = self.out / f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        bpath.write_text(
            json.dumps({'rows': rows, 'elapsed_s': elapsed,
                        'timestamp': datetime.now().isoformat()},
                       indent=2, ensure_ascii=False),
            encoding='utf-8'
        )
        print(f"\n  Reports : {self.out}")
        print(f"  Summary : {bpath}")
        print(f"{B}{C}{'═'*64}{RS}\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HTML & TXT REPORT BUILDERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _sev_color(sev: str) -> str:
    return {'critical':'#ef4444','high':'#f59e0b',
            'medium':'#3b82f6','low':'#10b981','info':'#64748b'}.get(sev,'#64748b')

def _build_scan_html(data: Dict) -> str:
    tgt   = data.get('target', {})
    conn  = data.get('connection', {})
    ali   = data.get('algerian_context') or {}
    fndgs = data.get('findings', [])
    disc  = data.get('discovery', {}).get('endpoints', [])
    ports = data.get('port_scan', {}).get('open_ports', [])
    subs  = data.get('subdomains', {})
    cms   = data.get('cms') or []
    waf_a = data.get('waf_analysis') or {}
    stats = data.get('statistics', {})
    fp    = data.get('fingerprint') or {}
    ssl   = fp.get('ssl_info') or {}

    n_c = sum(1 for f in fndgs if f.get('severity')=='critical')
    n_h = sum(1 for f in fndgs if f.get('severity')=='high')
    n_m = sum(1 for f in fndgs if f.get('severity')=='medium')
    n_l = sum(1 for f in fndgs if f.get('severity')=='low')

    risk  = min(100, n_c*30 + n_h*10 + n_m*3 + n_l)
    grade, gclr = _grade(100 - risk)   # invert: lower risk = better grade

    # Finding rows
    f_rows = ''.join(f"""
    <tr>
      <td><span class="badge" style="background:{_sev_color(f.get('severity','info'))}22;
          color:{_sev_color(f.get('severity','info'))};
          border:1px solid {_sev_color(f.get('severity','info'))}44">
          {_he(f.get('severity','?')).upper()}</span></td>
      <td><strong>{_he(f.get('name',''))}</strong><br>
          <span class="muted">{_he(f.get('category',''))}</span></td>
      <td class="muted small">{_he(f.get('detail','')[:120])}</td>
      <td class="small mono action">{_he(f.get('recommendation','')[:100])}</td>
    </tr>""" for f in fndgs)

    # Endpoint rows
    ep_rows = ''.join(f"""
    <tr>
      <td><span style="color:{'#10b981' if ep.get('status')==200 else '#f59e0b' if ep.get('status') in (401,403) else '#3b82f6'};font-weight:700">
          {ep.get('status','?')}</span></td>
      <td class="mono small">{_he(ep.get('url',''))}</td>
      <td class="small muted">{_he(ep.get('title','') or '')}</td>
      <td class="small muted right">{ep.get('size',0):,}B</td>
    </tr>""" for ep in disc[:50])

    # Port rows
    pt_rows = ''.join(f"""
    <tr>
      <td class="mono" style="color:#00d4ff;font-weight:700">{p.get('port')}/tcp</td>
      <td>{_he(p.get('service','?'))}</td>
      <td class="mono small muted">{_he((p.get('banner') or '')[:70])}</td>
      <td class="small" style="color:#ef4444">{_he(p['vulns'][0][:60]) if p.get('vulns') else ''}</td>
    </tr>""" for p in ports[:30])

    # Subdomain pills
    sub_pills = ' '.join(
        f'<span class="pill">{_he(s["domain"])}</span>'
        for s in subs.get('subdomains', [])[:30]
    ) if subs else ''

    # WAF grade block
    waf_block = ''
    if waf_a:
        wg, wgc = _grade(waf_a.get('detection_rate', 0))
        waf_block = f"""
        <div class="card">
          <div class="card-t">WAF Analysis</div>
          <div style="display:flex;align-items:center;gap:24px">
            <div class="grade-box" style="border-color:{wgc}">
              <div class="grade-num" style="color:{wgc}">{wg}</div>
              <div class="muted small">WAF Grade</div>
            </div>
            <div style="flex:1">
              <p><strong>Detection Rate:</strong> {waf_a.get('detection_rate',0):.1f}%</p>
              <p><strong>WAF:</strong> {_he(waf_a.get('waf_name') or 'Not identified')}</p>
              {'<p style="color:#ef4444"><strong>Blind Spots:</strong> '+'; '.join(_he(b) for b in waf_a.get('blind_spots',[])[:3])+'</p>' if waf_a.get('blind_spots') else ''}
            </div>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RECON-DZ · {_he(tgt.get('input',''))}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;700&family=Syne:wght@400;600;800&display=swap');
:root{{
  --bg:#060d1a; --s1:#0c1726; --s2:#111f33; --border:#1a3050;
  --accent:#00d4ff; --a2:#7c3aed; --text:#dde8f5; --muted:#4e6a8a;
  --green:#10b981; --yellow:#f59e0b; --red:#ef4444; --blue:#3b82f6;
  --mono:'IBM Plex Mono',monospace; --sans:'Syne',sans-serif;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;line-height:1.7}}

/* Header */
.hdr{{
  background:linear-gradient(150deg,#050c19 0%,#0a1830 55%,#060e1c 100%);
  border-bottom:1px solid var(--border); padding:36px 56px;
  display:flex; justify-content:space-between; align-items:center;
  position:relative; overflow:hidden;
}}
.hdr::before{{
  content:''; position:absolute; inset:0; pointer-events:none;
  background:
    repeating-linear-gradient(90deg,transparent,transparent 120px,rgba(0,212,255,.025) 120px,rgba(0,212,255,.025) 121px),
    repeating-linear-gradient(0deg,transparent,transparent 120px,rgba(0,212,255,.012) 120px,rgba(0,212,255,.012) 121px);
}}
.hdr-l .eyebrow{{font-family:var(--mono);font-size:10px;color:var(--accent);letter-spacing:3px;text-transform:uppercase;margin-bottom:10px}}
.hdr-l h1{{font-size:30px;font-weight:800;letter-spacing:-1px}}
.hdr-l h1 em{{color:var(--accent);font-style:normal}}
.hdr-l .meta{{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:8px;line-height:2.2}}

/* Grade box */
.grade-box{{
  text-align:center; background:rgba(0,0,0,.5);
  border:2px solid var(--border); border-radius:16px;
  padding:22px 34px; min-width:130px; flex-shrink:0;
}}
.grade-num{{font-size:64px;font-weight:800;color:{gclr};line-height:1;font-family:var(--mono)}}
.grade-sub{{font-size:10px;color:var(--muted);margin-top:6px;letter-spacing:2px;text-transform:uppercase}}

/* Stats bar */
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}}
.stat{{
  background:var(--s1); border:1px solid var(--border); border-radius:10px;
  padding:18px; text-align:center; position:relative; overflow:hidden;
}}
.stat::before{{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--accent),var(--a2))}}
.stat .v{{font-size:36px;font-weight:800;font-family:var(--mono);color:var(--accent)}}
.stat .l{{font-size:10px;color:var(--muted);margin-top:4px;letter-spacing:1px;text-transform:uppercase}}

/* Layout */
.wrap{{max-width:1440px;margin:0 auto;padding:36px 56px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px}}

/* Cards */
.card{{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:22px;margin-bottom:20px}}
.card-t{{font-family:var(--mono);font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--accent);margin-bottom:14px;padding-bottom:12px;border-bottom:1px solid var(--border)}}

/* Table */
.tbl-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:var(--s2);color:var(--muted);font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:9px 13px;text-align:left;border-bottom:1px solid var(--border)}}
td{{padding:9px 13px;border-bottom:1px solid rgba(26,48,80,.4);vertical-align:top}}
tr:hover td{{background:rgba(0,212,255,.025)}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:var(--mono)}}
.mono{{font-family:var(--mono)}}
.small{{font-size:12px}}
.muted{{color:var(--muted)}}
.right{{text-align:right}}
.action{{color:#fbbf24}}

/* Info grid */
.info-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:8px}}
.info-row{{display:flex;justify-content:space-between;padding:7px 0;border-bottom:1px solid rgba(26,48,80,.4)}}
.info-row .k{{color:var(--muted);font-family:var(--mono);font-size:11px}}
.info-row .v{{font-weight:600;font-size:13px;text-align:right}}

/* Algeria */
.ali-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}}
.ali-card{{background:var(--s2);border:1px solid var(--border);border-radius:8px;padding:14px}}
.ali-card .k{{font-family:var(--mono);font-size:9px;color:var(--muted);letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}}
.ali-card .v{{font-weight:700;font-size:15px}}

/* Subdomain pills */
.pill{{display:inline-block;background:var(--s2);border:1px solid var(--border);border-radius:4px;padding:3px 10px;font-family:var(--mono);font-size:11px;margin:3px;color:var(--accent)}}

/* Section headers */
.sec{{font-size:18px;font-weight:800;margin:32px 0 16px;display:flex;align-items:center;gap:12px}}
.sec::after{{content:'';flex:1;height:1px;background:linear-gradient(90deg,var(--border),transparent)}}

/* Footer */
footer{{text-align:center;padding:28px;color:var(--muted);font-family:var(--mono);font-size:11px;border-top:1px solid var(--border);margin-top:50px}}

@media(max-width:900px){{
  .stats{{grid-template-columns:1fr 1fr}}
  .grid2,.ali-grid{{grid-template-columns:1fr}}
  .hdr{{flex-direction:column;gap:20px;padding:24px}}
}}
</style>
</head>
<body>

<!-- HEADER -->
<div class="hdr">
  <div class="hdr-l">
    <div class="eyebrow">RECON-DZ v{VERSION} · Security Assessment Report</div>
    <h1><em>RECON</em>-DZ Scan Report</h1>
    <div class="meta">
      Target : {_he(tgt.get('input','?'))} &nbsp;│&nbsp;
      IP : {tgt.get('ip','?')} &nbsp;│&nbsp;
      {data.get('meta',{}).get('timestamp','?')}
    </div>
  </div>
  <div class="grade-box">
    <div class="grade-num">{grade}</div>
    <div class="grade-sub">Risk Grade</div>
  </div>
</div>

<div class="wrap">

<!-- STATS BAR -->
<div class="stats">
  <div class="stat"><div class="v" style="color:#ef4444">{n_c}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="v" style="color:#f59e0b">{n_h}</div><div class="l">High</div></div>
  <div class="stat"><div class="v">{len(disc)}</div><div class="l">Endpoints</div></div>
  <div class="stat"><div class="v">{len(ports)}</div><div class="l">Open Ports</div></div>
</div>

<!-- ALGERIA CONTEXT -->
{'<h2 class="sec">Algeria Intelligence</h2><div class="ali-grid"><div class="ali-card"><div class="k">Sector</div><div class="v">'+ali.get("sector","?").upper()+'</div></div><div class="ali-card"><div class="k">Criticality</div><div class="v" style="color:#f59e0b">'+ali.get("criticality","?").upper()+'</div></div><div class="ali-card"><div class="k">ISP</div><div class="v">'+_he(ali.get("isp","?"))+'</div></div></div>' if ali else ''}

<!-- TOP ROW -->
<div class="grid2">
  <div class="card">
    <div class="card-t">Connection & Stack</div>
    <div class="info-grid">
      <div class="info-row"><span class="k">HTTP Status</span><span class="v">{conn.get('status','?')}</span></div>
      <div class="info-row"><span class="k">Response Time</span><span class="v">{conn.get('time_s','?')}s</span></div>
      <div class="info-row"><span class="k">Server</span><span class="v">{_he(conn.get('server','?') or '?')}</span></div>
      <div class="info-row"><span class="k">WAF</span><span class="v" style="color:{'#f59e0b' if conn.get('waf') else '#10b981'}">{_he(conn.get('waf') or 'None')}</span></div>
      <div class="info-row"><span class="k">Redirects</span><span class="v">{conn.get('redirects',0)}</span></div>
      <div class="info-row"><span class="k">CMS</span><span class="v">{', '.join(_he(c['name']) for c in cms) if cms else '—'}</span></div>
      {'<div class="info-row"><span class="k">SSL Protocol</span><span class="v">'+_he(ssl.get('protocol_version','?'))+'</span></div>' if ssl else ''}
      {'<div class="info-row"><span class="k">Cert Expiry</span><span class="v">'+_he(str(ssl.get('cert_expiry','?')))+'</span></div>' if ssl else ''}
      <div class="info-row"><span class="k">Requests</span><span class="v">{stats.get('requests_total',0)}</span></div>
      <div class="info-row"><span class="k">Success Rate</span><span class="v">{stats.get('success_rate_pct',0)}%</span></div>
    </div>
  </div>
  <div class="card">
    <div class="card-t">Finding Distribution</div>
    <canvas id="riskChart" height="180"></canvas>
  </div>
</div>

{waf_block}

<!-- FINDINGS -->
<h2 class="sec">Security Findings ({len(fndgs)})</h2>
<div class="card">
  <div class="tbl-wrap">
    <table>
      <thead><tr><th>Severity</th><th>Finding</th><th>Detail</th><th>Recommended Action</th></tr></thead>
      <tbody>{f_rows or '<tr><td colspan=4 style="text-align:center;padding:30px;color:var(--muted)">No significant findings detected</td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- ENDPOINTS -->
{'<h2 class="sec">Discovered Endpoints ('+str(len(disc))+')</h2><div class="card"><div class="tbl-wrap"><table><thead><tr><th>Status</th><th>URL</th><th>Title</th><th>Size</th></tr></thead><tbody>'+ep_rows+'</tbody></table></div></div>' if disc else ''}

<!-- PORTS -->
{'<h2 class="sec">Open Ports ('+str(len(ports))+')</h2><div class="card"><div class="tbl-wrap"><table><thead><tr><th>Port</th><th>Service</th><th>Banner</th><th>Vuln Hint</th></tr></thead><tbody>'+pt_rows+'</tbody></table></div></div>' if ports else ''}

<!-- SUBDOMAINS -->
{'<h2 class="sec">Subdomains ('+str(subs.get("found",0))+')</h2><div class="card">'+sub_pills+'</div>' if subs else ''}

</div><!-- /wrap -->

<footer>
  RECON-DZ v{VERSION} · {data.get('meta',{}).get('timestamp','')} · Authorized Security Assessment Only
</footer>

<script>
new Chart(document.getElementById('riskChart'),{{
  type:'doughnut',
  data:{{
    labels:['Critical','High','Medium','Low','None'],
    datasets:[{{
      data:[{n_c},{n_h},{n_m},{n_l},{max(1 if not (n_c+n_h+n_m+n_l) else 0,0)}],
      backgroundColor:['#ef4444','#f59e0b','#3b82f6','#10b981','#1a3050'],
      borderWidth:0, hoverOffset:6
    }}]
  }},
  options:{{
    responsive:true, cutout:'68%',
    plugins:{{
      legend:{{position:'right',labels:{{color:'#4e6a8a',font:{{size:11,family:"'IBM Plex Mono'"}}}}}}
    }}
  }}
}});
</script>
</body>
</html>"""


def _build_scan_txt(data: Dict) -> str:
    tgt   = data.get('target', {})
    conn  = data.get('connection', {})
    fndgs = data.get('findings', [])
    stats = data.get('statistics', {})
    ts    = data.get('meta', {}).get('timestamp', '?')
    lines = [
        f"RECON-DZ v{VERSION} — Security Assessment Report",
        '=' * 68,
        f"Target    : {tgt.get('input','?')}",
        f"IP        : {tgt.get('ip','?')}",
        f"Timestamp : {ts}",
        '',
        'CONNECTION',
        '─' * 40,
        f"Status  : {conn.get('status','?')}",
        f"Server  : {conn.get('server','?')}",
        f"WAF     : {conn.get('waf') or 'None'}",
        f"Time    : {conn.get('time_s','?')}s",
        '',
        'SECURITY FINDINGS',
        '─' * 40,
    ]
    for f in fndgs:
        lines += [
            f"[{f.get('severity','?').upper()}] {f.get('name','')}",
            f"  Category : {f.get('category','')}",
            f"  Detail   : {f.get('detail','')}",
            f"  Action   : {f.get('recommendation','')}",
            '',
        ]
    if not fndgs:
        lines += ['No significant findings.', '']

    ports = data.get('port_scan', {}).get('open_ports', [])
    if ports:
        lines += ['OPEN PORTS', '─' * 40]
        for p in ports:
            lines.append(f"  {p['port']}/tcp  {p.get('service','?')}"
                         + (f"  {p.get('banner','')[:60]}" if p.get('banner') else ''))
        lines.append('')

    subs = data.get('subdomains', {})
    if subs.get('found'):
        lines += [f"SUBDOMAINS  ({subs['found']} active)", '─' * 40]
        for s in subs.get('subdomains', [])[:20]:
            lines.append(f"  {s['domain']}")
        lines.append('')

    waf = data.get('waf_analysis', {})
    if waf:
        lines += [
            'WAF ANALYSIS', '─' * 40,
            f"Grade          : {waf.get('grade','?')}",
            f"Detection Rate : {waf.get('detection_rate',0):.1f}%",
            f"Blind Spots    : {len(waf.get('blind_spots',[]))}",
            '',
        ]

    lines += [
        '─' * 68,
        f"Requests : {stats.get('requests_total',0)} total  "
        f"({stats.get('success_rate_pct',0)}% success)",
        f"RECON-DZ v{VERSION} · Authorized Use Only",
    ]
    return '\n'.join(lines)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI PARSER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='recon.py',
        description='RECON-DZ v3 — Unified Security Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{'━'*64}
EXAMPLES
  # Basic recon scan
  python recon.py scan -t ministere.gov.dz

  # Full recon (all modules) + inline WAF check
  python recon.py scan -t target.dz -e --waf-check

  # Recon with specific modules
  python recon.py scan -t target.dz --subdomains --ports --cms --vuln

  # WAF defensive analysis only
  python recon.py waf -t https://yoursite.dz/search

  # WAF with specific attack categories
  python recon.py waf -t https://yoursite.dz/search --categories SQLi XSS SSRF

  # Batch scan from file (one domain per line)
  python recon.py batch -f targets.txt -e

  # Regenerate HTML from existing JSON
  python recon.py report --json results/20260312_scan.json
{'━'*64}
WAF CATEGORIES
  {' '.join(WAF_PROBES.keys())}
{'━'*64}
""",
    )

    sub = p.add_subparsers(dest='mode', metavar='MODE')

    # ── SCAN ──────────────────────────────────────────────────────────
    s = sub.add_parser('scan', help='Full reconnaissance scan',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument('-t','--target',       required=True, help='Target domain or IP')
    s.add_argument('--depth', choices=['quick','normal','deep'], default='normal')
    s.add_argument('--max-concurrent',    type=int, default=30)
    s.add_argument('--output-dir',        default='./results')
    s.add_argument('--internal',          action='store_true',
                   help='Internal network (faster, no stealth delays)')
    s.add_argument('-v','--verbose',      action='store_true')
    g = s.add_argument_group('Modules  (-e enables ALL)')
    g.add_argument('-e','--enumerate',    action='store_true', help='Enable ALL modules')
    g.add_argument('--reverse-ip',        action='store_true', dest='reverse_ip')
    g.add_argument('--subdomains',        action='store_true', dest='enumerate_subdomains')
    g.add_argument('--ports',             action='store_true')
    g.add_argument('--cms',               action='store_true')
    g.add_argument('--fingerprint',       action='store_true')
    g.add_argument('--vuln',             action='store_true')
    g.add_argument('--waf-check',         action='store_true', dest='waf_check',
                   help='Add inline WAF analysis phase to scan')

    # ── WAF ───────────────────────────────────────────────────────────
    w = sub.add_parser('waf', help='Defensive WAF analysis',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    w.add_argument('-t','--target',       required=True,
                   help='Full URL  e.g. https://yoursite.dz/search')
    w.add_argument('--param',             default='q',
                   help='GET parameter to inject into (default: q)')
    w.add_argument('--categories',        nargs='+', metavar='CAT')
    w.add_argument('--delay',             type=float, default=0.3)
    w.add_argument('--max-concurrent',    type=int, default=15)
    w.add_argument('--output-dir',        default='./results')
    w.add_argument('--internal',          action='store_true')
    w.add_argument('-y','--yes',          action='store_true',
                   help='Skip authorization prompt')

    # ── BATCH ─────────────────────────────────────────────────────────
    b = sub.add_parser('batch', help='Scan multiple targets from file',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    b.add_argument('-f','--file',         required=True,
                   help='Text file, one domain/IP per line')
    b.add_argument('--depth', choices=['quick','normal','deep'], default='normal')
    b.add_argument('--max-concurrent',    type=int, default=20)
    b.add_argument('--output-dir',        default='./results')
    b.add_argument('--internal',          action='store_true')
    g2 = b.add_argument_group('Modules  (-e enables ALL)')
    g2.add_argument('-e','--enumerate',   action='store_true')
    g2.add_argument('--subdomains',       action='store_true', dest='enumerate_subdomains')
    g2.add_argument('--ports',            action='store_true')
    g2.add_argument('--cms',              action='store_true')
    g2.add_argument('--vuln',            action='store_true')
    g2.add_argument('--waf-check',        action='store_true', dest='waf_check')

    # ── REPORT ────────────────────────────────────────────────────────
    r = sub.add_parser('report', help='Rebuild HTML from existing JSON',
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    r.add_argument('--json',              required=True, dest='json_file',
                   help='Path to .json report')

    p.add_argument('--version', action='version', version=f'RECON-DZ v{VERSION}')
    return p


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ASYNC DISPATCHER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

async def _dispatch(args):
    mode = getattr(args, 'mode', None)

    # ── No mode → print help ─────────────────────────────────────────
    if not mode:
        banner()
        print(f"  Usage:  python recon.py  [scan | waf | batch | report]  --help\n")
        print(f"  {C}scan{RS}    Full reconnaissance — DNS · ports · CMS · vulns · fingerprint")
        print(f"  {Y}waf{RS}     Defensive WAF analysis — 66 probes · blind-spot detection")
        print(f"  {M}batch{RS}   Multi-target scan from a text file")
        print(f"  {G}report{RS}  Regenerate HTML from an existing JSON report\n")
        return

    # ── SCAN mode ────────────────────────────────────────────────────
    if mode == 'scan':
        banner('scan')
        print(f"  {Y}[!]{RS} For authorized security assessment only.\n")
        engine  = await build_engine(
            max_concurrent=getattr(args,'max_concurrent',30),
            internal=getattr(args,'internal',False),
        )
        try:
            scanner = ScanMode(engine, args)
            await scanner.run(args.target)
        finally:
            await engine.close()

    # ── WAF mode ─────────────────────────────────────────────────────
    elif mode == 'waf':
        banner('waf')
        engine = await build_engine(
            max_concurrent=getattr(args,'max_concurrent',15),
            internal=getattr(args,'internal',False),
        )
        try:
            waf_mode = WAFMode(engine, args)
            await waf_mode.run()
        finally:
            await engine.close()

    # ── BATCH mode ───────────────────────────────────────────────────
    elif mode == 'batch':
        banner('batch')
        print(f"  {Y}[!]{RS} Batch mode — authorized use only.\n")
        engine = await build_engine(
            max_concurrent=getattr(args,'max_concurrent',20),
            internal=getattr(args,'internal',False),
        )
        try:
            batch = BatchMode(engine, args)
            await batch.run(args.file)
        finally:
            await engine.close()

    # ── REPORT mode ──────────────────────────────────────────────────
    elif mode == 'report':
        banner('report')
        jp = Path(args.json_file)
        if not jp.exists():
            print(f"  {R}[ERROR]{RS} File not found: {jp}"); return
        data = json.loads(jp.read_text(encoding='utf-8'))
        hp   = jp.with_suffix('.html')
        # Detect WAF report vs scan report
        if 'detection_rate' in data and 'probe_results' in data:
            profile = WAFProfile(
                target           = data.get('target','?'),
                waf_detected     = data.get('waf_detected'),
                detection_rate   = data.get('detection_rate', 0),
                blind_spots      = data.get('blind_spots', []),
                strong_categories= data.get('strong_categories', []),
                weak_categories  = data.get('weak_categories', []),
                response_behavior= data.get('response_behavior', {}),
                recommendations  = data.get('recommendations', []),
            )
            html = generate_waf_html_report(profile)
        else:
            html = _build_scan_html(data)
        hp.write_text(html, encoding='utf-8')
        print(f"  {G}[+]{RS} HTML report written : {hp}\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def main():
    parser = _parser()
    args   = parser.parse_args()

    try:
        asyncio.run(_dispatch(args))
    except KeyboardInterrupt:
        print(f"\n  {Y}[!]{RS} Interrupted")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  {R}[ERROR]{RS} {exc}")
        import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
