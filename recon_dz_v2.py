#!/usr/bin/env python3
"""
RECON-DZ v2 - Main entry point
"""

import asyncio
import argparse
import json
from datetime import datetime
from pathlib import Path

from core.async_engine import AsyncReconEngine, detect_waf_response
from core.algeria_threats import AlgeriaThreatDatabase


class RECONDZv2:
    VERSION = "2.0.0"
    
    def __init__(self):
        self.engine = None
        self.algeria_db = AlgeriaThreatDatabase()
        self.results = {}
    
    async def initialize(self):
        self.engine = AsyncReconEngine(enable_stealth=True)
        await self.engine.initialize()
        return self
    
    async def close(self):
        await self.engine.close()
    
    async def scan(self, target: str) -> dict:
        print(f"\n[RECON-DZ v{self.VERSION}] Scanning: {target}\n")
        
        # Check Algeria
        algeria_info = self.algeria_db.identify_target(target)
        if algeria_info:
            print(f"[Algeria] Sector: {algeria_info.sector}, ISP: {algeria_info.isp}")
        
        # Basic probe
        base_url = f"https://{target}" if not target.startswith('http') else target
        response = await self.engine.request(base_url)
        
        print(f"[Probe] Status: {response.status}, Time: {response.elapsed:.2f}s")
        
        # Detect WAF
        waf = await detect_waf_response(response)
        if waf:
            print(f"[WAF] Detected: {waf}")
        
        # Technology detection
        techs = response.extract_technology_hints()
        if techs:
            print(f"[Tech] Found: {', '.join(techs)}")
        
        # Common paths
        paths = ['/robots.txt', '/.well-known/security.txt', '/admin', '/api/']
        urls = [f"{base_url}{p}" for p in paths]
        responses = await self.engine.mass_request(urls)
        
        found = []
        for resp in responses:
            if isinstance(resp, Exception):
                continue
            if resp.is_success:
                found.append(f"{resp.url} [{resp.status}]")
        
        if found:
            print(f"\n[Discovery] {len(found)} endpoints found:")
            for f in found[:5]:
                print(f"  - {f}")
        
        # Compile results
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'algerian_context': {
                'sector': algeria_info.sector,
                'isp': algeria_info.isp,
                'criticality': algeria_info.criticality,
            } if algeria_info else None,
            'probe': {
                'status': response.status,
                'server': response.get_header('server'),
                'technologies': techs,
            },
            'waf': waf,
            'endpoints': found,
            'stats': self.engine.stats,
        }
        
        # Save report
        self._save_report(target)
        
        return self.results
    
    def _save_report(self, target: str):
        output_dir = Path('./results')
        output_dir.mkdir(exist_ok=True)
        
        filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{target.replace('/', '_')}.json"
        filepath = output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n[Report] Saved: {filepath}")


async def main():
    parser = argparse.ArgumentParser(description='RECON-DZ v2')
    parser.add_argument('-t', '--target', required=True, help='Target domain')
    args = parser.parse_args()
    
    framework = RECONDZv2()
    
    try:
        await framework.initialize()
        await framework.scan(args.target)
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    finally:
        await framework.close()


if __name__ == '__main__':
    asyncio.run(main())
