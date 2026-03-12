# -*- coding: utf-8 -*-
import asyncio
import aiohttp
import ssl
import random
from typing import Dict, Optional, Any

class AsyncReconEngine:
    """محرك الاستطلاع المتطور - نسخة التخفي القصوى"""
    def __init__(self, timeout: int = 20):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        # قاعدة بيانات رؤوس حقيقية متغيرة
        self.browsers = [
            ("Chrome", "Windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"),
            ("Firefox", "Linux", "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0"),
            ("Safari", "Mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15")
        ]

    def _generate_stealth_headers(self, host: str) -> Dict[str, str]:
        browser_name, os_name, ua = random.choice(self.browsers)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Host": host
        }
        return headers

    async def request(self, url: str, retry: int = 3) -> Optional[Dict[str, Any]]:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        
        # إنشاء سياق SSL مشفر يحاكي المتصفحات الحديثة ويتخطى القيود
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20')

        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            for attempt in range(retry):
                try:
                    # تأخير عشوائي لكسر بصمة البوت الجراحية
                    await asyncio.sleep(random.uniform(1.2, 3.5))
                    
                    async with session.get(url, headers=self._generate_stealth_headers(domain), ssl=context, allow_redirects=True) as resp:
                        return {
                            "status": resp.status,
                            "headers": dict(resp.headers),
                            "body": await resp.text(errors='ignore'),
                            "final_url": str(resp.url)
                        }
                except Exception:
                    if attempt == retry - 1: return None
                    await asyncio.sleep(5) # انتظار أطول عند الفشل
        return None

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """استخدام DoH (DNS Over HTTPS) لمنع كشف الاستطلاع من قبل ISP"""
        doh_providers = ["https://1.1.1.1/dns-query", "https://8.8.8.8/resolve"]
        target_doh = random.choice(doh_providers)
        params = {"name": hostname, "type": "A"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(target_doh, params=params, headers={"Accept": "application/dns-json"}) as r:
                    if r.status == 200:
                        data = await r.json()
                        return data["Answer"][0]["data"] if "Answer" in data else None
            except: return None

