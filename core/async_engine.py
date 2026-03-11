"""
RECON-DZ v2 - Advanced Async Engine with DNS Over HTTPS
For Termux and restricted network environments
"""

import asyncio
import aiohttp
import ssl
import time
import random
import socket
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field


@dataclass
class ResponseData:
    """Structured response data"""
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
    protocol: str = "https"
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300 and self.error is None
    
    def get_header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)
    
    def extract_technology_hints(self) -> List[str]:
        """Extract technology indicators"""
        hints = []
        server = self.get_header('server')
        if server:
            hints.append(f"server:{server}")
        body_lower = self.body.lower()[:5000]
        if 'wp-content' in body_lower:
            hints.append("cms:wordpress")
        if 'laravel' in body_lower:
            hints.append("framework:laravel")
        if 'react' in body_lower:
            hints.append("frontend:react")
        return hints


class DNSResolver:
    """
    DNS Over HTTPS resolver for restricted environments
    Uses Cloudflare and Google DoH
    """
    
    DOH_SERVERS = [
        'https://cloudflare-dns.com/dns-query',
        'https://dns.google/resolve',
        'https://dns.quad9.net:5053/dns-query',
    ]
    
    def __init__(self):
        self.cache: Dict[str, str] = {}
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def initialize(self):
        """Initialize DoH session"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=10,
            ssl=ssl_context,
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=10),
        )
    
    async def resolve(self, hostname: str) -> Optional[str]:
        """Resolve hostname using DoH"""
        if hostname in self.cache:
            return self.cache[hostname]
        
        # Try each DoH server
        for doh_url in self.DOH_SERVERS:
            try:
                ip = await self._query_doh(doh_url, hostname)
                if ip:
                    self.cache[hostname] = ip
                    return ip
            except Exception as e:
                continue
        
        # Fallback: try system socket (may work in some cases)
        try:
            ip = socket.gethostbyname(hostname)
            self.cache[hostname] = ip
            return ip
        except:
            pass
        
        return None
    
    async def _query_doh(self, doh_url: str, hostname: str) -> Optional[str]:
        """Query DNS over HTTPS"""
        params = {'name': hostname, 'type': 'A'}
        headers = {
            'Accept': 'application/dns-json',
        }
        
        try:
            async with self.session.get(
                doh_url,
                params=params,
                headers=headers,
                ssl=False
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    answers = data.get('Answer', [])
                    for answer in answers:
                        if answer.get('type') == 1:  # A record
                            return answer.get('data')
        except:
            pass
        
        return None
    
    async def close(self):
        """Cleanup"""
        if self.session:
            await self.session.close()


class AsyncReconEngine:
    """Professional async engine with DoH support"""
    
    def __init__(self, max_concurrent: int = 20):
        self.max_concurrent = max_concurrent
        self.session: Optional[aiohttp.ClientSession] = None
        self.dns_resolver: Optional[DNSResolver] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.stats = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
        }
    
    async def initialize(self):
        """Initialize with DoH support"""
        print("[*] Initializing DNS Over HTTPS...")
        
        # Initialize DNS resolver
        self.dns_resolver = DNSResolver()
        await self.dns_resolver.initialize()
        
        # SSL context
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=5,
            enable_cleanup_closed=True,
            ssl=ssl_context,
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=15, connect=5),
        )
        
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        print("[✓] Engine ready with DoH support")
        return self
    
    async def close(self):
        """Cleanup"""
        if self.dns_resolver:
            await self.dns_resolver.close()
        if self.session:
            await self.session.close()
    
    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve using DoH"""
        return await self.dns_resolver.resolve(hostname)
    
    async def request(self, url: str, method: str = 'GET') -> ResponseData:
        """Make HTTP request with full handling"""
        async with self.semaphore:
            start = time.perf_counter()
            
            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.9',
                    },
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    
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
                    else:
                        self.stats['requests_failed'] += 1
                    
                    return ResponseData(
                        url=url,
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body[:100000],
                        body_bytes=body_bytes,
                        content_type=resp.headers.get('Content-Type', ''),
                        charset=charset,
                        elapsed=elapsed,
                        final_url=str(resp.url),
                        redirect_count=len(resp.history),
                        protocol='https' if url.startswith('https') else 'http',
                    )
                    
            except Exception as e:
                self.stats['requests_failed'] += 1
                return ResponseData(
                    url=url, status=0, headers={}, body='', body_bytes=b'',
                    content_type='', charset='', elapsed=time.perf_counter() - start,
                    final_url=url, redirect_count=0,
                    error=str(e), protocol='https' if url.startswith('https') else 'http'
                )
    
    async def request_with_resolution(self, hostname: str, path: str = '/') -> ResponseData:
        """
        Resolve hostname with DoH then make request
        """
        # Resolve IP
        ip = await self.resolve_hostname(hostname)
        
        if not ip:
            return ResponseData(
                url=f"http://{hostname}{path}",
                status=0, headers={}, body='', body_bytes=b'',
                content_type='', charset='', elapsed=0,
                final_url=f"http://{hostname}{path}", redirect_count=0,
                error="DNS resolution failed (DoH and fallback failed)",
                protocol='http'
            )
        
        print(f"[*] Resolved {hostname} -> {ip}")
        
        # Try HTTPS first with IP and Host header
        url = f"https://{ip}{path}"
        headers = {'Host': hostname}
        
        response = await self._request_with_host(url, headers)
        
        if response.status == 0 or response.status >= 500:
            # Try HTTP
            url = f"http://{ip}{path}"
            response = await self._request_with_host(url, headers)
        
        # Update URL in response to show original hostname
        if response.status != 0:
            response.final_url = f"{'https' if url.startswith
