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
import random          # NEW
import string          # NEW
import hashlib         # NEW
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# ── Core modules ───────────────────────────────────────────────────────
from core.async_engine       import AsyncReconEngine, ResponseData, detect_waf_response
from core.algeria_threats    import AlgeriaThreatDatabase
from core.ip_utils           import extract_real_ip
from core.ip_enumerator      import IPEnumerator
from core.host_profiler      import HostProfiler, generate_host_profile_html
from core.stealth_engine     import (
    StealthScanner, CDNBypass, BlockDetector,
    GhostRequester, RateLimitEvader
)
from core.domain_validator   import DomainValidator
from core.subdomain_enum     import SubdomainEnumerator
from core.cms_detector       import CMSDetector
from core.port_scanner       import PortScanner
from core.server_fingerprint import ServerFingerprinter
from core.vuln_scanner       import VulnScanner
from core.intelligence_engine import IntelligenceEngine
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
            self._on('intel'),
        ])
        return 4 + optional  # base phases: intel + conn + endpoint + vuln

    # ── NEW: Smart Validation Functions ───────────────────────────────
    def get_smart_baseline(self, target_url: str) -> Optional[Dict]:
        """
        توليد بصمة مرجعية لصفحة غير موجودة للتعرف على الـ Soft 404
        """
        # توليد اسم ملف عشوائي مستحيل الوجود
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15)) + ".html"
        test_url = f"{target_url.rstrip('/')}/{random_path}"
        
        try:
            # استخدام self.e.request بدلاً من requests.get للتوافق
            resp = asyncio.run_coroutine_threadsafe(
                self.e.request(test_url, follow_redirects=False),
                asyncio.get_event_loop()
            ).result(timeout=15)
            
            if resp.status == 0:
                return None
            
            # حفظ البصمة المرجعية
            baseline = {
                "status_code": resp.status,
                "content_length": len(resp.body),
                "hash": hashlib.md5(resp.body.encode('utf-8', errors='ignore')).hexdigest(),
                "title": "Not Found" if "not found" in resp.body.lower() else "Unknown"
            }
            return baseline
        except Exception as e:
            return None

    def validate_path(self, target_url: str, path: str, baseline: Dict) -> Tuple[bool, str]:
        """
        التحقق من المسار المكتشف ومقارنته بالبصمة المرجعية
        """
        full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            res = asyncio.run_coroutine_threadsafe(
                self.e.request(full_url, follow_redirects=False),
                asyncio.get_event_loop()
            ).result(timeout=15)
            
            if res.status == 0:
                return False, "Connection Error"

            # 1. إذا كان الكود ليس 200، فهو غالباً غير موجود
            if res.status != 200:
                return False, f"HTTP {res.status}"

            # 2. مقارنة الحجم (Content Length) مع المرجع
            size_diff = abs(len(res.body) - baseline["content_length"])
            if size_diff < (baseline["content_length"] * 0.05):
                return False, "Soft 404 (Size Match)"

            # 3. مقارنة البصمة الرقمية (Hash)
            current_hash = hashlib.md5(res.body.encode('utf-8', errors='ignore')).hexdigest()
            if current_hash == baseline["hash"]:
                return False, "Soft 404 (Hash Match)"

            # 4. إذا تجاوز كل الاختبارات، المسار حقيقي!
            return True, "Valid Path Detected"
        except Exception as e:
            return False, f"Error: {str(e)}"

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

        # ── OPTIONAL: Intelligence Engine (Behavioral) ────────────
        intel_data: Optional[Dict] = None
        if self._on('intel'):
            pc += 1; _ph(pc, TOTAL, "Behavioral Fingerprinting & Attack Surface Map")
            intel_data = await self._run_intelligence(
                base_url   = base_url,
                cms_info   = cms_data or [],
                vuln_data  = findings or [],
                server_fp  = fp_data or {},
                open_ports = (port_data or {}).get('open_ports', []),
                subdomains = (sub_data or {}).get('subdomains', []),
            )

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
        if intel_data: self.results['intelligence']   = intel_data

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

    # ── MODIFIED: Endpoint Discovery with Smart Validation ───────────
    async def _run_endpoints(self, base_url: str, ali) -> List[Dict]:
        # الحصول على البصمة المرجعية للمسارات غير الموجودة
        print(f"  {C}[*]{RS} Generating smart baseline for soft-404 detection...")
        baseline = self.get_smart_baseline(base_url)
        if baseline:
            print(f"      Baseline: status={baseline['status_code']}, size={baseline['content_length']}, hash={baseline['hash'][:8]}")
        else:
            print(f"      {Y}[!]{RS} Could not generate baseline, proceeding without validation.")

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

            # إذا توفرت البصمة، نستخدم التحقق الذكي
            if baseline:
                # استخراج المسار من url
                path_part = url.replace(base_url.rstrip('/'), '')
                valid, reason = self.validate_path(base_url, path_part, baseline)
                if not valid:
                    # تجاهل المسار وطباعة سبب الرفض (اختياري)
                    print(f"      {Y}[!]{RS} Rejected {url} — {reason}")
                    continue
                # إذا كان صحيحاً، نضيفه مع ملاحظة
                ep['validated'] = True
                print(f"      {G}[✓]{RS} Validated {url} — {reason}")
            else:
                # بدون تحقق، نظهره كالمعتاد
                icon = (f"{G}[200]{RS}" if r.status == 200 else
                        f"{C}[{r.status}]{RS}" if r.status in (301,302,307) else
                        f"{Y}[{r.status}]{RS}")
                ti = f'  "{ep["title"][:40]}"' if ep.get('title') else ''
                print(f"      {icon} {url}{ti}")

            found.append(ep)

        print(f"  {G}[+]{RS} Found {len(found)} valid endpoints.")
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

    async def _run_intelligence(self, base_url: str,
                                 cms_info:   list,
                                 vuln_data:  list,
                                 server_fp:  dict,
                                 open_ports: list,
                                 subdomains: list) -> Dict:
        """
        Behavioral fingerprinting + Attack surface mapping.
        يشغّل 10 probes ذكية ويولّد خريطة الثغرات الكاملة.
        """
        ie = IntelligenceEngine(self.e)
        result = await ie.analyze(
            base_url      = base_url,
            cms_info      = cms_info,
            vuln_findings = vuln_data,
            server_fp     = server_fp,
            open_ports    = open_ports,
            subdomains    = subdomains,
        )

        # Print summary
        grade = result.get('risk_grade', '?')
        score = result.get('risk_score', 0)
        grade_colors = {
            'CRITICAL': R, 'HIGH': Y, 'MEDIUM': C, 'LOW': G, 'MINIMAL': G}
        gc = grade_colors.get(grade, W)

        print(f"  {G}[+]{RS} Risk Score : {gc}{score}/100  [{grade}]{RS}")
        print(f"  {R}[!]{RS} Critical   : {result.get('critical',0)}"
              f"  {Y}High: {result.get('high',0)}{RS}"
              f"  Medium: {result.get('medium',0)}"
              f"  Low: {result.get('low',0)}")

        vectors = result.get('attack_vectors', [])
        if vectors:
            print(f"\n  {C}Attack Vectors ({len(vectors)}):{RS}")
            for v in vectors[:8]:
                sev = v.get('severity','?')
                sc  = (R if sev=='critical' else Y if sev=='high'
                       else C if sev=='medium' else W)
                print(f"    {sc}[{sev.upper():<8}]{RS} {v.get('name','')}")
                if v.get('bypass_hint'):
                    print(f"              {M}→ {v['bypass_hint']}{RS}")
            if len(vectors) > 8:
                print(f"    … +{len(vectors)-8} more (see HTML report)")

        chains = result.get('attack_chains', [])
        if chains:
            print(f"\n  {Y}Attack Chains:{RS}")
            for ch in chains:
                print(f"    [{ch.get('likelihood','?')}] {ch.get('name','')}")

        return result

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
#  باقي الملف (WAFMode, BatchMode, HTML builders, CLI parser, dispatch, main)
#  يبقى كما هو دون تغيير.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ... (كل الكود من بعد هذا السطر يبقى كما هو في الملف الأصلي) ...