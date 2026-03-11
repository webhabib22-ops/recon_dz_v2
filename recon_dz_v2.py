# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
RECON-DZ v2 - Advanced Security Reconnaissance Framework
Professional-grade tool for authorized security assessment
Educational and defensive purposes only

Author: RECON-DZ Team
License: Authorized Use Only - Government & Educational
Version: 2.0.0 (Enhanced with IP/domain enumeration)
"""

import asyncio
import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from core.async_engine import AsyncReconEngine, detect_waf_response
from core.algeria_threats import AlgeriaThreatDatabase
from core.ip_utils import extract_real_ip
from core.ip_enumerator import IPEnumerator
from core.domain_validator import DomainValidator


class RECONDZv2:
    """
    Main controller for RECON-DZ v2
    Professional security assessment framework
    """

    VERSION = "2.0.0"
    CODENAME = "Intelligent Recon"
    LICENSE = "Authorized Security Assessment Only"

    def __init__(self, verbose: bool = False, internal_mode: bool = False,
                 enumerate_domains: bool = False):
        self.verbose = verbose
        self.internal_mode = internal_mode
        self.enumerate_domains = enumerate_domains
        self.engine: Optional[AsyncReconEngine] = None
        self.algeria_db = AlgeriaThreatDatabase()
        self.results: Dict = {}
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

    async def initialize(self, max_concurrent: int = 30):
        """Initialize framework"""
        print(f"\n[RECON-DZ v{self.VERSION}] Initializing...")
        print(f"[*] License: {self.LICENSE}")

        self.engine = AsyncReconEngine(
            max_concurrent=max_concurrent,
            enable_stealth=True,
            internal_mode=self.internal_mode,
            delay_range=(0.3, 1.5) if not self.internal_mode else (0.1, 0.5)
        )

        await self.engine.initialize()
        print("[+] Engine ready\n")
        return self

    async def close(self):
        """Cleanup"""
        if self.engine:
            await self.engine.close()

    def _print(self, msg: str, force: bool = False):
        """Controlled output"""
        if self.verbose or force:
            print(msg)

    async def scan(self, target: str, depth: str = 'normal') -> Dict:
        """
        Execute comprehensive security scan
        """
        print(f"{'='*60}")
        print(f"RECON-DZ v{self.VERSION} - {self.CODENAME}")
        print(f"Target: {target}")
        print(f"Session: {self.session_id}")
        print(f"{'='*60}\n")

        # Phase 1: Intelligence
        print("[Phase 1/6] Intelligence Gathering")
        algeria_info = self.algeria_db.identify_target(target)

        if algeria_info:
            print(f"[+] Algerian infrastructure detected")
            print(f"    Sector: {algeria_info.sector.upper()}")
            print(f"    Criticality: {algeria_info.criticality.upper()}")
            print(f"    ISP: {algeria_info.isp}")
            if algeria_info.city:
                print(f"    City: {algeria_info.city}")
            if algeria_info.compliance_requirements:
                print(f"    Compliance: {', '.join(algeria_info.compliance_requirements)}")

            # Print threat context
            if algeria_info.threat_actors:
                print(f"    Threat Actors: {', '.join(algeria_info.threat_actors)}")
        else:
            print("[!] Non-Algerian target (general scan mode)")

        # Phase 2: Connectivity
        print("\n[Phase 2/6] Connectivity Assessment")

        response, protocol, actual_target = await self.engine.request_with_fallback(
            target, www_fallback=True
        )

        if response.status == 0:
            print(f"[-] Target unreachable")
            print(f"    Error: {response.error}")
            return {'error': 'unreachable', 'details': response.error}

        base_url = f"{protocol}{actual_target}"
        print(f"[+] Connected: {base_url}")
        print(f"    Status: {response.status}")
        print(f"    Server: {response.get_header('server', 'Unknown')}")
        print(f"    Response Time: {response.elapsed:.2f}s")

        # Phase 3: Technology Analysis
        print("\n[Phase 3/6] Technology Analysis")

        techs = response.extract_technology_hints()
        if techs:
            print("[+] Detected technologies:")
            for tech in techs:
                print(f"    * {tech}")
        else:
            print("[!] No clear technology indicators")

        # WAF Detection
        waf = detect_waf_response(response)
        if waf:
            print(f"[!] WAF/Protection: {waf}")
            if self.internal_mode:
                print("[*] Internal mode active - WAF evasion enabled")
        else:
            print("[+] No WAF detected")

        # Phase 4: IP & Domain Enumeration (if requested)
        ip_enum_data = None
        if self.enumerate_domains:
            print("\n[Phase 4/6] IP & Domain Enumeration")

            # Get real IP
            real_ip = await extract_real_ip(actual_target, self.engine)
            if real_ip:
                print(f"[+] Real server IP: {real_ip}")

                # Enumerate domains on that IP
                enumerator = IPEnumerator(self.engine)
                domains = await enumerator.enumerate(real_ip)
                print(f"[+] Found {len(domains)} domains on same IP")

                if domains:
                    # Validate discovered domains
                    validator = DomainValidator(self.engine, self.algeria_db)
                    validated = await validator.validate_batch(domains, concurrency=10)

                    active_domains = [d for d in validated if d.get('active')]
                    print(f"[+] Active domains: {len(active_domains)}")

                    # Show first few
                    for d in active_domains[:10]:
                        ctx = d.get('algerian_context', {})
                        sector = ctx.get('sector', 'unknown') if ctx else 'unknown'
                        print(f"    * {d['domain']} [{d['status']}] {sector}")

                    ip_enum_data = {
                        'real_ip': real_ip,
                        'domains_found': len(domains),
                        'active_domains': len(active_domains),
                        'domains': validated
                    }
                else:
                    print("[!] No domains found via enumeration")
            else:
                print("[-] Could not determine real IP")

        # Phase 5: Endpoint Discovery
        print("\n[Phase 5/6] Endpoint Discovery")

        paths = self._get_discovery_paths(algeria_info)
        urls = [f"{base_url.rstrip('/')}{path}" for path in paths]

        print(f"[*] Testing {len(urls)} endpoints...")

        discovered = []
        for i, url in enumerate(urls, 1):
            resp = await self.engine.request(url)

            if resp.status != 0:
                endpoint = {
                    'url': url,
                    'status': resp.status,
                    'size': len(resp.body),
                    'title': self._extract_title(resp.body),
                    'server': resp.get_header('server'),
                    'redirect_to': resp.final_url if resp.final_url != url else '',
                }

                interesting = (
                    resp.is_success or
                    resp.status in (301, 302, 307, 308) or
                    resp.status in (401, 403) or
                    (resp.status == 404 and len(resp.body) > 500)
                )

                if interesting:
                    discovered.append(endpoint)

                # Print interesting responses immediately
                if resp.status in (200, 201, 301, 302, 401, 403):
                    if resp.status == 200:
                        icon = "[+]"
                    elif resp.status in (301, 302):
                        icon = "[>]"
                    elif resp.status in (401, 403):
                        icon = "[!]"
                    else:
                        icon = "[*]"

                    title_str = f" \"{endpoint['title'][:35]}\"" if endpoint.get('title') else ""
                    redir_str = f" -> {endpoint['redirect_to'][:40]}" if endpoint.get('redirect_to') else ""
                    print(f"    {icon} [{resp.status}] {url}{title_str}{redir_str}")

            if i % 10 == 0 and i < len(urls):
                print(f"    Progress: {i}/{len(urls)}")

        # Phase 6: Security Analysis
        print("\n[Phase 6/6] Security Analysis")

        findings = self._analyze_findings(response, discovered, algeria_info)

        if findings:
            print(f"[+] {len(findings)} security observations")
            for finding in findings[:5]:
                print(f"    * [{finding['severity']}] {finding['name']}")
        else:
            print("[*] No immediate security concerns")

        # Compile results
        self.results = {
            'framework': {
                'version': self.VERSION,
                'session': self.session_id,
                'license': self.LICENSE,
            },
            'target': {
                'input': target,
                'resolved': actual_target,
                'protocol': protocol,
            },
            'algerian_context': algeria_info.__dict__ if algeria_info else None,
            'connection': {
                'status': response.status,
                'time': response.elapsed,
                'server': response.get_header('server'),
                'powered_by': response.get_header('x-powered-by'),
            },
            'technologies': techs,
            'protection': {
                'waf': waf,
                'internal_mode': self.internal_mode,
            },
            'discovery': {
                'tested': len(urls),
                'found': len(discovered),
                'endpoints': discovered,
            },
            'findings': findings,
            'statistics': self.engine.stats,
            'timestamp': datetime.now().isoformat(),
        }

        # Add IP enumeration data if available
        if ip_enum_data:
            self.results['ip_enumeration'] = ip_enum_data

        # Save report
        self._save_report(target)

        # Summary
        self._print_summary(algeria_info, response, discovered, findings, ip_enum_data)

        return self.results

    def _get_discovery_paths(self, algeria_info) -> List[str]:
        """Get paths based on target context"""
        base = [
            '/',
            '/robots.txt',
            '/.well-known/security.txt',
            '/sitemap.xml',
            '/favicon.ico',
        ]

        if not algeria_info:
            return base + ['/admin', '/login', '/api/', '/wp-admin']

        sector_paths = {
            'government': [
                '/admin', '/administrator', '/wp-admin', '/cpanel',
                '/webmail', '/mail', '/intranet', '/portal',
            ],
            'banking': [
                '/api', '/mobile', '/auth', '/login', '/ib',
                '/e-banking', '/corporate', '/swift',
            ],
            'telecom': [
                '/portal', '/customer', '/api', '/myaccount',
                '/recharge', '/services', '/4g', '/5g',
            ],
            'education': [
                '/portal', '/student', '/campus', '/moodle',
                '/courses', '/library', '/research', '/staff',
            ],
        }

        return base + sector_paths.get(algeria_info.sector, ['/admin', '/login'])

    def _extract_title(self, body: str) -> Optional[str]:
        """Extract HTML title"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
        return match.group(1).strip() if match else None

    def _analyze_findings(self, response, discovered, algeria_info) -> List[Dict]:
        """Analyze security findings"""
        findings = []

        # Check for information disclosure
        server = response.get_header('server')
        if server and any(x in server.lower() for x in ['apache/2.2', 'nginx/1.6', 'iis/7']):
            findings.append({
                'name': 'Outdated Server Software',
                'severity': 'medium',
                'detail': f'Server: {server}',
                'recommendation': 'Upgrade to latest stable version',
            })

        # Check for missing security headers
        security_headers = ['x-frame-options', 'x-content-type-options',
                          'content-security-policy', 'strict-transport-security']
        missing = [h for h in security_headers if not response.get_header(h)]
        if missing:
            findings.append({
                'name': 'Missing Security Headers',
                'severity': 'medium',
                'detail': f'Missing: {", ".join(missing)}',
                'recommendation': 'Implement security headers',
            })

        # Check for exposed admin panels
        admin_paths = [d for d in discovered if any(x in d['url'] for x in
                      ['admin', 'wp-admin', 'cpanel', 'phpmyadmin'])]
        for admin in admin_paths:
            findings.append({
                'name': 'Potentially Exposed Admin Interface',
                'severity': 'high',
                'detail': f'Found: {admin["url"]}',
                'recommendation': 'Restrict access by IP, enable 2FA',
            })

        # Algeria-specific checks
        if algeria_info and algeria_info.is_government:
            if not response.get_header('strict-transport-security'):
                findings.append({
                    'name': 'Decree 26-07 Violation: No HSTS',
                    'severity': 'high',
                    'detail': 'Missing HTTPS enforcement (Strict-Transport-Security header)',
                    'compliance': 'Decree_26_07_Article_12',
                    'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                })

        return findings

    def _save_report(self, target: str):
        """Save comprehensive report"""
        output_dir = Path('./results')
        output_dir.mkdir(exist_ok=True)

        filename = f"{self.session_id}_{target.replace('/', '_').replace(':', '_')}.json"
        filepath = output_dir / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n[+] Report saved: {filepath}")

        # Also save text summary
        txt_file = filepath.with_suffix('.txt')
        with open(txt_file, 'w', encoding='utf-8') as f:
            f.write(self._generate_text_report())
        print(f"[+] Summary saved: {txt_file}")

    def _generate_text_report(self) -> str:
        """Generate text report"""
        lines = [
            f"RECON-DZ v{self.VERSION} Security Assessment",
            f"{'='*60}",
            f"Session: {self.session_id}",
            f"Target: {self.results['target']['input']}",
            f"Generated: {self.results['timestamp']}",
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
        ]

        if self.results.get('algerian_context'):
            ctx = self.results['algerian_context']
            lines.extend([
                f"Algerian Infrastructure: YES",
                f"Sector: {ctx['sector']}",
                f"Criticality: {ctx['criticality']}",
                f"ISP: {ctx['isp']}",
                "",
            ])

        lines.extend([
            f"Connection Status: {self.results['connection']['status']}",
            f"Endpoints Discovered: {self.results['discovery']['found']}",
            f"Security Findings: {len(self.results['findings'])}",
            "",
            "SECURITY FINDINGS",
            "-" * 40,
        ])

        for finding in self.results['findings']:
            lines.append(f"[{finding['severity'].upper()}] {finding['name']}")
            lines.append(f"  Detail: {finding['detail']}")
            lines.append(f"  Recommendation: {finding['recommendation']}")
            lines.append("")

        # Add IP enumeration summary if present
        if self.results.get('ip_enumeration'):
            ip_data = self.results['ip_enumeration']
            lines.extend([
                "IP ENUMERATION SUMMARY",
                "-" * 40,
                f"Real IP: {ip_data.get('real_ip', 'N/A')}",
                f"Domains found: {ip_data.get('domains_found', 0)}",
                f"Active domains: {ip_data.get('active_domains', 0)}",
                ""
            ])

        lines.extend([
            "END OF REPORT",
            f"Framework: RECON-DZ v{self.VERSION}",
            f"Purpose: Authorized Security Assessment",
        ])

        return '\n'.join(lines)

    def _print_summary(self, algeria_info, response, discovered, findings, ip_enum_data=None):
        """Print final summary"""
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {self.results['target']['input']}")

        if algeria_info:
            print(f"Algerian: [+] YES")
            print(f"  Sector: {algeria_info.sector}")
            print(f"  Criticality: {algeria_info.criticality}")
        else:
            print(f"Algerian: [-] NO")

        print(f"Status: {response.status}")
        print(f"Endpoints: {len(discovered)}")
        print(f"Findings: {len(findings)}")

        # Severity breakdown
        critical = len([f for f in findings if f['severity'] == 'critical'])
        high = len([f for f in findings if f['severity'] == 'high'])
        medium = len([f for f in findings if f['severity'] == 'medium'])

        if critical:
            print(f"  Critical: {critical}")
        if high:
            print(f"  High: {high}")
        if medium:
            print(f"  Medium: {medium}")

        # IP enumeration summary
        if ip_enum_data:
            print(f"\nIP Enumeration:")
            print(f"  Real IP: {ip_enum_data.get('real_ip', 'N/A')}")
            print(f"  Domains on same IP: {ip_enum_data.get('domains_found', 0)}")
            print(f"  Active domains: {ip_enum_data.get('active_domains', 0)}")

        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description='RECON-DZ v2 - Advanced Security Reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Authorized Use Only - Educational and Defensive Purposes

Examples:
  # Basic scan
  python recon_dz_v2.py -t example.com

  # Algerian target with full details
  python recon_dz_v2.py -t www.univ-medea.dz -v

  # Internal network mode (authorized testing)
  python recon_dz_v2.py -t 10.0.0.1 --internal

  # Deep scan with domain enumeration
  python recon_dz_v2.py -t ministere.gov.dz -v -e

  # Deep scan with maximum detail
  python recon_dz_v2.py -t ministere.gov.dz -v --depth deep
        """
    )

    parser.add_argument('-t', '--target', required=True,
                       help='Target domain or IP')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--internal', action='store_true',
                       help='Internal network mode (stealth + speed)')
    parser.add_argument('--depth', choices=['quick', 'normal', 'deep'],
                       default='normal', help='Scan depth')
    parser.add_argument('--max-concurrent', type=int, default=30,
                       help='Maximum concurrent requests')
    parser.add_argument('-e', '--enumerate', action='store_true',
                       help='Enable IP/domain enumeration (reverse IP lookup)')

    args = parser.parse_args()

    # Validate authorized use
    print(f"\n[!] WARNING: This tool is for authorized security assessment only.")
    print(f"    Unauthorized use is prohibited by law.\n")

    # Run scan
    framework = RECONDZv2(
        verbose=args.verbose,
        internal_mode=args.internal,
        enumerate_domains=args.enumerate
    )

    try:
        asyncio.run(run_scan(framework, args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


async def run_scan(framework, args):
    """Async scan wrapper"""
    await framework.initialize(max_concurrent=args.max_concurrent)
    try:
        await framework.scan(args.target, depth=args.depth)
    finally:
        await framework.close()


if __name__ == '__main__':
    main()
