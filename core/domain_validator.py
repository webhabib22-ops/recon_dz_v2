#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Domain Validator
Validate and enrich discovered domains with:
- Liveness check via DoH + HTTP
- Algerian sector classification
- Server/title extraction
- Redirect chain tracking
"""

import asyncio
import re
from typing import List, Dict, Optional

from core.async_engine import AsyncReconEngine
from core.algeria_threats import AlgeriaThreatDatabase


class DomainValidator:
    """
    Check a list of domain names for liveness and extract basic metadata.
    """

    def __init__(self, engine: AsyncReconEngine,
                 threat_db: AlgeriaThreatDatabase):
        self.engine    = engine
        self.threat_db = threat_db

    async def validate_batch(self, domains: List[str],
                              concurrency: int = 15) -> List[Dict]:
        """
        Validate multiple domains concurrently.
        Returns list of result dicts (both active and inactive).
        """
        sem   = asyncio.Semaphore(concurrency)
        tasks = [self._validate_one(d, sem) for d in domains]
        raw   = await asyncio.gather(*tasks, return_exceptions=True)

        results: List[Dict] = []
        for item in raw:
            if isinstance(item, dict):
                results.append(item)
            # silently skip exceptions so one failure doesn't break the batch

        return results

    async def _validate_one(self, domain: str,
                             sem: asyncio.Semaphore) -> Dict:
        """Validate a single domain name."""
        async with sem:
            # Try to connect (HTTPS → HTTP → www.)
            response, protocol, final_host = await self.engine.request_with_fallback(
                domain, www_fallback=True, path='/'
            )

            if response.status == 0:
                return {
                    'domain': domain,
                    'active': False,
                    'error':  response.error,
                }

            # Resolve IP separately (may already be in engine cache)
            ip = await self.engine.resolve_hostname(final_host)

            result: Dict = {
                'domain':           final_host,
                'active':           True,
                'status':           response.status,
                'server':           response.get_header('server') or None,
                'title':            _extract_title(response.body),
                'ip':               ip,
                'protocol':         protocol.rstrip('://'),
                'redirect_count':   response.redirect_count,
                'algerian_context': None,
            }

            # Algerian sector classification
            target_info = self.threat_db.identify_target(final_host, ip=ip)
            if target_info:
                result['algerian_context'] = {
                    'sector':      target_info.sector,
                    'criticality': target_info.criticality,
                    'isp':         target_info.isp,
                }

            return result


# ─────────────────────── Helpers ──────────────────────────────────────

def _extract_title(body: str) -> Optional[str]:
    """Extract the HTML <title> from a page body."""
    if not body:
        return None
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.IGNORECASE)
    if m:
        # Normalize whitespace
        return re.sub(r'\s+', ' ', m.group(1)).strip()
    return None
