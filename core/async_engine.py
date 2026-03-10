"""
High-performance async HTTP engine for RECON-DZ v2
"""

import asyncio
import aiohttp
import aiodns
import ssl
import time
import random
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
import json
import hashlib
from urllib.parse import urlparse


@dataclass
class ResponseData:
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    body_bytes: bytes
    content_type: str
    charset: str
    elapsed: float
    final_url: str
    redirect_count: int
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300 and self.error is None
    
    def get_header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)
    
    def extract_technology_hints(self) -> List[str]:
        hints = []
        server = self.get_header('server')
        if server:
            hints.append(f"server:{server}")
        body_lower = self.body.lower()
        if 'wp-content' in body_lower:
            hints.append("cms:wordpress")
        if 'laravel' in body_lower:
            hints.append("framework:laravel")
        return hints


class AsyncReconEngine:
    def __init__(self, max_concurrent: int = 100, enable_stealth: bool = True):
        self.max_concurrent = max_concurrent
        self.enable_stealth = enable_stealth
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._cache: Dict[str, ResponseData] = {}
        self.stats = {'requests_total': 0, 'requests_success': 0}
        self._fingerprints = self._generate_fingerprints()
        self._fp_idx = 0
        
    def _generate_fingerprints(self) -> List[Dict]:
        return [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
            },
            {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            }
        ]
    
    async def initialize(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=20,
            enable_cleanup_closed=True,
            ssl=ssl_context,
        )
        
        headers = self._fingerprints[0] if self.enable_stealth else {
            'User-Agent': 'RECON-DZ/2.0'
        }
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=10),
            headers=headers,
        )
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        return self
    
    async def close(self):
        if self.session:
            await self.session.close()
    
    async def request(self, url: str, method: str = 'GET') -> ResponseData:
        async with self.semaphore:
            start = time.perf_counter()
            try:
                async with self.session.request(method, url) as resp:
                    body_bytes = await resp.read()
                    elapsed = time.perf_counter() - start
                    
                    try:
                        body = body_bytes.decode('utf-8')
                        charset = 'utf-8'
                    except:
                        body = body_bytes.decode('latin-1', errors='ignore')
                        charset = 'latin-1'
                    
                    self.stats['requests_total'] += 1
                    if resp.status < 400:
                        self.stats['requests_success'] += 1
                    
                    return ResponseData(
                        url=url,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:50000],
                        body_bytes=body_bytes,
                        content_type=resp.headers.get('Content-Type', ''),
                        charset=charset,
                        elapsed=elapsed,
                        final_url=str(resp.url),
                        redirect_count=len(resp.history),
                    )
            except Exception as e:
                return ResponseData(
                    url=url, status=0, headers={}, body='', body_bytes=b'',
                    content_type='', charset='', elapsed=0, final_url=url,
                    redirect_count=0, error=str(e)
                )
    
    async def mass_request(self, urls: List[str]) -> List[ResponseData]:
        tasks = [self.request(url) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=True)


async def detect_waf_response(response: ResponseData) -> Optional[str]:
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.body.lower()
    
    if 'cf-ray' in headers:
        return 'cloudflare'
    if 'x-amzn-requestid' in headers:
        return 'aws_waf'
    if response.status == 406 or 'mod_security' in body:
        return 'mod_security'
    if 'incap_ses' in str(headers):
        return 'incapsula'
    if response.status in [403, 406] and len(response.body) < 200:
        return 'generic'
    return None
