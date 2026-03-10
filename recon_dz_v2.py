#!/usr/bin/env python3
"""
RECON-DZ v2 - Advanced Reconnaissance & Security Assessment Framework
Main entry point with intelligent scanning
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


class RECONDZv2:
    VERSION = "2.0.0"
    CODENAME = "Intelligent Recon"
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.engine: Optional[AsyncReconEngine] = None
        self.algeria_db = AlgeriaThreatDatabase()
        self.results: Dict = {}
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    async def initialize(self, max_concurrent: int = 50):
        """Initialize all components"""
        self.engine = AsyncReconEngine(
            max_concurrent=max_concurrent,
            enable_stealth=True
        )
        await self.engine.initialize()
        self._print("[✓] Engine initialized successfully")
        return self
    
    async def close(self):
        """Cleanup"""
        if self.engine:
            await self.engine.close()
    
    def _print(self, msg: str, force: bool = False):
        """Print with verbosity control"""
        if self.verbose or force:
            print(msg)
    
    async def scan(self, target: str, depth: str = 'normal') -> Dict:
        """
        Execute full security scan
        """
        print(f"\n{'='*60}")
        print(f"RECON-DZ v{self.VERSION} - {self.CODENAME}")
        print(f"Target: {target}")
        print(f"Session: {self.session_id}")
        print(f"{'='*60}\n")
        
        # Phase 1: Algeria Intelligence
        self._print("[Phase 1/4] Algeria Intelligence Gathering")
        algeria_info = self.algeria_db.identify_target(target)
        
        if algeria_info:
            print(f"[✓] Algerian target detected!")
            print(f"    Sector: {algeria_info.sector.upper()}")
            print(f"    Criticality: {algeria_info.criticality.upper()}")
            print(f"    ISP: {algeria_info.isp}")
            if algeria_info.compliance_requirements:
                print(f"    Compliance: {', '.join(algeria_info.compliance_requirements)}")
        else:
            self._print("[!] Not identified as Algerian target")
        
        # Phase 2: Protocol Detection
        self._print("\n[Phase 2/4] Protocol Detection & Initial Probe")
        
        response, protocol = await self.engine.request_with_fallback(target)
        
        if response.status == 0:
            print(f"[✗] Target unreachable on both HTTP and HTTPS")
            print(f"    Error: {response.error}")
            return {'error': 'unreachable', 'details': response.error}
        
        base_url = f"{protocol}{target.replace('https://', '').replace('http://', '')}"
        print(f"[✓] Connected via {protocol.upper()}")
        print(f"    Status: {response.status}")
        print(f"    Time: {response.elapsed:.2f}s")
        print(f"    Server: {response.get_header('server', 'Unknown')}")
        
        # Phase 3: Technology & WAF Detection
        self._print("\n[Phase 3/4] Technology & Security Analysis")
        
        # Technology detection
        techs = response.extract_technology_hints()
        if techs:
            print(f"[✓] Technologies detected:")
            for tech in techs:
                print(f"    - {tech}")
        else:
            self._print("[!] No clear technology indicators")
        
        # WAF Detection
        waf = await detect_waf_response(response)
        if waf:
            print(f"[⚠] WAF Detected: {waf}")
        else:
            self._print("[✓] No WAF detected")
        
        # Phase 4: Endpoint Discovery
        self._print("\n[Phase 4/4] Endpoint Discovery")
        
        common_paths = self._get_paths_for_context(algeria_info)
        urls = [f"{base_url.rstrip('/')}{path}" for path in common_paths]
        
        print(f"[*] Testing {len(urls)} common endpoints...")
        
        responses = await self.engine.mass_request(urls)
        
        found = []
        for resp in responses:
            if isinstance(resp, Exception):
                continue
            if resp.is_success:
                found.append({
                    'url': resp.url,
                    'status': resp.status,
                    'size': len(resp.body),
                    'title': self._extract_title(resp.body),
                })
            elif resp.status == 403:
                found.append({
                    'url': resp.url,
                    'status': resp.status,
                    'note': 'forbidden',
                })
        
        if found:
            print(f"[✓] Found {len(found)} endpoints:")
            for endpoint in found[:10]:
                status = endpoint['status']
                url = endpoint['url']
                if 'title' in endpoint:
                    print(f"    [{status}] {url} - {endpoint['title'][:40]}")
                elif 'note' in endpoint:
                    print(f"    [{status}] {url} (forbidden)")
                else:
                    print(f"    [{status}] {url}")
        else:
            print("[!] No common endpoints discovered")
        
        # Compile results
        self.results = {
            'session_id': self.session_id,
            'version': self.VERSION,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'algerian_context': algeria_info.__dict__ if algeria_info else None,
            'connection': {
                'protocol': protocol,
                'base_url': base_url,
                'initial_status': response.status,
                'server': response.get_header('server'),
                'powered_by': response.get_header('x-powered-by'),
            },
            'technologies': techs,
            'waf': waf,
            'endpoints': found,
            'statistics': self.engine.stats,
        }
        
        # Save report
        self._save_report(target)
        
        # Final summary
        self._print_summary(algeria_info, response, found)
        
        return self.results
    
    def _get_paths_for_context(self, algeria_info) -> List[str]:
        """Get relevant paths based on context"""
        base_paths = [
            '/robots.txt',
            '/.well-known/security.txt',
            '/sitemap.xml',
        ]
        
        if not algeria_info:
            return base_paths + ['/admin', '/login', '/api/']
        
        sector_paths = {
            'government': ['/admin', '/wp-login.php', '/administrator/', '/cpanel'],
            'banking': ['/api/', '/mobile/', '/auth/', '/login'],
            'telecom': ['/api/', '/portal/', '/customer/'],
            'education': ['/portal/', '/student/', '/campus/', '/moodle'],
        }
        
        return base_paths + sector_paths.get(algeria_info.sector, ['/admin', '/login'])
    
    def _extract_title(self, body: str) -> str:
        """Extract page title"""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
        return match.group(1).strip() if match else 'No Title'
    
    def _save_report(self, target: str):
        """Save JSON report"""
        output_dir = Path('./results')
        output_dir.mkdir(exist_ok=True)
        
        filename = f"{self.session_id}_{target.replace('/', '_').replace(':', '_')}.json"
        filepath = output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False)
        
        print(f"\n[✓] Report saved: {filepath}")
    
    def _print_summary(self, algeria_info, response, found):
        """Print final summary"""
        print(f"\n{'='*60}")
        print("SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {self.results['target']}")
        print(f"Algerian: {'YES ✓' if algeria_info else 'NO'}")
        if algeria_info:
            print(f"  Sector: {algeria_info.sector}")
            print(f"  Criticality: {algeria_info.criticality}")
        print(f"Status: {response.status}")
        print(f"Endpoints: {len(found)}")
        print(f"Requests: {self.engine.stats['requests_total']}")
        print(f"Success: {self.engine.stats['requests_success']}")
        print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description='RECON-DZ v2 - Advanced Security Reconnaissance',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon_dz_v2.py -t example.com
  python recon_dz_v2.py -t univ-medea.dz -v
  python recon_dz_v2.py -t ministere.gov.dz --depth deep
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target domain')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--depth', choices=['quick', 'normal', 'deep'], 
                       default='normal', help='Scan depth')
    parser.add_argument('--max-concurrent', type=int, default=50,
                       help='Max concurrent requests')
    
    args = parser.parse_args()
    
    # Run scan
    framework = RECONDZv2(verbose=args.verbose)
    
    try:
        asyncio.run(run_scan(framework, args))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)


async def run_scan(framework, args):
    """Async wrapper for scan"""
    await framework.initialize(max_concurrent=args.max_concurrent)
    try:
        await framework.scan(args.target, depth=args.depth)
    finally:
        await framework.close()


if __name__ == '__main__':
    main()
