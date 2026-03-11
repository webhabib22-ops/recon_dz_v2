# -*- coding: utf-8 -*-
"""
domain_validator.py - Validate and classify discovered domains
Part of RECON-DZ v2
"""

import asyncio
import re
from typing import List, Dict, Optional
from core.async_engine import AsyncReconEngine
from core.algeria_threats import AlgeriaThreatDatabase


class DomainValidator:
    """
    Check discovered domains for liveness and extract basic information.
    """

    def __init__(self, engine: AsyncReconEngine, threat_db: AlgeriaThreatDatabase):
        self.engine = engine
        self.threat_db = threat_db

    async def validate_batch(self, domains: List[str], concurrency: int = 10) -> List[Dict]:
        """
        Validate multiple domains concurrently.
        """
        semaphore = asyncio.Semaphore(concurrency)
        tasks = [self._validate_one(domain, semaphore) for domain in domains]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_results = []
        for res in results:
            if isinstance(res, dict):
                valid_results.append(res)
        return valid_results

    async def _validate_one(self, domain: str, semaphore) -> Optional[Dict]:
        """
        Validate a single domain.
        """
        async with semaphore:
            # Attempt to connect to the domain
            response, protocol, final_host = await self.engine.request_with_fallback(
                domain, www_fallback=True, path='/'
            )

            if response.status == 0:
                return {
                    'domain': domain,
                    'active': False,
                    'error': response.error
                }

            # Try to resolve IP
            ip = await self.engine.resolve_hostname(final_host)

            # Extract page title
            title = self._extract_title(response.body)

            info = {
                'domain': final_host,
                'active': True,
                'status': response.status,
                'server': response.get_header('server'),
                'title': title,
                'ip': ip,
                'algerian_context': None
            }

            # Check if it's Algerian infrastructure
            target_info = self.threat_db.identify_target(final_host, ip=ip)
            if target_info:
                info['algerian_context'] = {
                    'sector': target_info.sector,
                    'criticality': target_info.criticality,
                    'isp': target_info.isp
                }

            return info

    def _extract_title(self, body: str) -> Optional[str]:
        """Extract HTML title from page body."""
        match = re.search(r'<title[^>]*>([^<]+)</title>', body, re.IGNORECASE)
        return match.group(1).strip() if match else None
