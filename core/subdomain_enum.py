# -*- coding: utf-8 -*-
import asyncio
from typing import List, Set
from core.async_engine import AsyncReconEngine

class SubdomainEnumerator:
    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine

    async def enumerate(self, domain: str) -> List[str]:
        """استخراج النطاقات الفرعية عبر تقنيات صامتة (CRT.sh + DoH Brute Force)"""
        found_subs = set()
        
        # 1. الاستعلام من سجلات الشهادات (Passive)
        crt_subs = await self._from_crtsh(domain)
        found_subs.update(crt_subs)
        
        # 2. فحص ذكي وسريع للنطاقات الشائعة (Active Stealth)
        common_list = ["api", "dev", "staging", "vpn", "mail", "internal", "cloud", "portal", "db"]
        semaphore = asyncio.Semaphore(5) # تقليل الضغط لعدم كشف الـ IP
        
        tasks = [self._check_sub(sub, domain, semaphore) for sub in common_list]
        results = await asyncio.gather(*tasks)
        found_subs.update([r for r in results if r])
        
        return list(found_subs)

    async def _check_sub(self, sub: str, domain: str, sem) -> Optional[str]:
        async with sem:
            full = f"{sub}.{domain}"
            ip = await self.engine.resolve_hostname(full)
            return full if ip else None

    async def _from_crtsh(self, domain: str) -> List[str]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        res = await self.engine.request(url)
        if res and res['status'] == 200:
            try:
                import json
                data = json.loads(res['body'])
                return list(set(item['name_value'].lower() for item in data))
            except: pass
        return []

