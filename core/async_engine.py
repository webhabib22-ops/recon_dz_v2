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
    
    def __init__(self, max_concurrent: int = 20,
                 enable_stealth: bool = False,
                 internal_mode: bool = False,
                 delay_range: tuple = (0.0, 0.0)):
        self.max_concurrent = max_concurrent
        self.enable_stealth = enable_stealth
        self.internal_mode  = internal_mode
        self.delay_range    = delay_range          # (min, max) seconds between requests
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
        
        print("[âœ“] Engine ready with DoH support")
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
            # ØªØ·Ø¨ÙŠÙ‚ Ø§Ù„ØªØ£Ø®ÙŠØ± Ø¥Ø°Ø§ ÙƒØ§Ù† stealth mode Ù…ÙØ¹Ù‘Ù„Ø§Ù‹
            if self.delay_range and self.delay_range[1] > 0:
                delay = random.uniform(self.delay_range[0], self.delay_range[1])
                await asyncio.sleep(delay)

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
            proto = 'https' if url.startswith('https') else 'http'
            response.final_url = f"{proto}://{hostname}{path}"
            response.protocol  = proto

        return response

    async def _request_with_host(self, url: str,
                                  extra_headers: Dict[str, str]) -> ResponseData:
        """Make request with custom Host header (for IP-based requests)"""
        async with self.semaphore:
            start = time.perf_counter()
            try:
                merged_headers = {
                    'User-Agent':      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                                       'AppleWebKit/537.36 (KHTML, like Gecko) '
                                       'Chrome/124.0.0.0 Safari/537.36',
                    'Accept':          'text/html,application/xhtml+xml,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Connection':      'keep-alive',
                }
                merged_headers.update(extra_headers)

                async with self.session.request(
                    method='GET',
                    url=url,
                    headers=merged_headers,
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    body_bytes = await resp.read()
                    elapsed    = time.perf_counter() - start

                    try:
                        body    = body_bytes.decode('utf-8')
                        charset = 'utf-8'
                    except Exception:
                        body    = body_bytes.decode('latin-1', errors='ignore')
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
                        body=body[:100_000],
                        body_bytes=body_bytes,
                        content_type=resp.headers.get('Content-Type', ''),
                        charset=charset,
                        elapsed=elapsed,
                        final_url=str(resp.url),
                        redirect_count=len(resp.history),
                        protocol='https' if url.startswith('https') else 'http',
                    )

            except Exception as exc:
                self.stats['requests_failed'] += 1
                return ResponseData(
                    url=url, status=0, headers={}, body='', body_bytes=b'',
                    content_type='', charset='',
                    elapsed=time.perf_counter() - start,
                    final_url=url, redirect_count=0,
                    error=str(exc),
                    protocol='https' if url.startswith('https') else 'http',
                )

    async def request_with_fallback(self, hostname: str,
                                     www_fallback: bool = True,
                                     path: str = '/') -> tuple:
        """
        ÙŠØ­Ø§ÙˆÙ„ Ø§Ù„Ø§ØªØµØ§Ù„ Ø¨Ø§Ù„Ù‡Ø¯Ù Ø¨ÙƒÙ„ Ø§Ù„Ø·Ø±Ù‚ Ø§Ù„Ù…Ù…ÙƒÙ†Ø© Ù…Ø¹ DoH resolution:
        1. ÙŠØ­Ù„ DNS Ø¹Ø¨Ø± DoH Ø£ÙˆÙ„Ø§Ù‹ (ÙŠØªØ¬Ø§ÙˆØ² Ø­Ø¬Ø¨ DNS)
        2. ÙŠØ¬Ø±Ø¨ https â†’ http â†’ www.https â†’ www.http
        ÙŠØ±Ø¬Ø¹: (ResponseData, protocol_str, actual_hostname)
        """
        # Ø¨Ù†Ø§Ø¡ Ù‚Ø§Ø¦Ù…Ø© Ø§Ù„Ù…Ø¶ÙŠÙÙŠÙ† Ù„Ù„ØªØ¬Ø±Ø¨Ø©
        hostnames_to_try = [hostname]
        if www_fallback and not hostname.startswith('www.'):
            hostnames_to_try.append(f'www.{hostname}')

        last_response = None

        for host in hostnames_to_try:
            # â”€â”€ Ø§Ù„Ø®Ø·ÙˆØ© 1: Ø­Ù„ DNS Ø¹Ø¨Ø± DoH (ÙŠØªØ¬Ø§ÙˆØ² Ø­Ø¬Ø¨ Termux/DZ) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            ip = await self.resolve_hostname(host)

            for proto in ['https://', 'http://']:
                if ip:
                    # Ø§ØªØµÙ„ Ø¨Ø§Ù„Ù€ IP Ù…Ø¨Ø§Ø´Ø±Ø© Ù…Ø¹ Host header â†’ ÙŠØªØ¬Ø§ÙˆØ² DNS ØªÙ…Ø§Ù…Ø§Ù‹
                    port = '443' if proto == 'https://' else '80'
                    url  = f"{proto}{ip}{path}"
                    resp = await self._request_with_host(
                        url, extra_headers={'Host': host}
                    )
                else:
                    # DoH ÙØ´Ù„ â€” Ø¬Ø±Ù‘Ø¨ URL Ù…Ø¨Ø§Ø´Ø±Ø© ÙƒÙ…Ù„Ø§Ø° Ø£Ø®ÙŠØ±
                    url  = f"{proto}{host}{path}"
                    resp = await self.request(url)

                last_response = resp

                if resp.status != 0 and resp.status < 500:
                    # ØµØ­Ù‘Ø­ Ø§Ù„Ù€ URL Ù„ÙŠØ¸Ù‡Ø± hostname Ø¨Ø¯Ù„ IP
                    resp.final_url = f"{proto}{host}{path}"
                    return (resp, proto, host)

        # ÙƒÙ„ Ø§Ù„Ù…Ø­Ø§ÙˆÙ„Ø§Øª ÙØ´Ù„Øª
        error_resp = last_response or ResponseData(
            url=f"https://{hostname}{path}",
            status=0, headers={}, body='', body_bytes=b'',
            content_type='', charset='', elapsed=0.0,
            final_url=f"https://{hostname}{path}", redirect_count=0,
            error="All connection attempts failed (DNS + DoH + direct)",
            protocol='https',
        )
        return (error_resp, 'https://', hostname)

    async def batch_request(self, urls: List[str],
                             method: str = 'GET') -> List[ResponseData]:
        """
        ÙŠØ±Ø³Ù„ Ø¹Ø¯Ø© Ø·Ù„Ø¨Ø§Øª Ø¨Ø´ÙƒÙ„ Ù…ØªÙˆØ§Ø²Ù ÙˆÙŠØ±Ø¬Ø¹ Ø§Ù„Ù†ØªØ§Ø¦Ø¬ Ù…Ø±ØªØ¨Ø© Ø¨Ù†ÙØ³ Ø§Ù„ØªØ±ØªÙŠØ¨.
        """
        tasks = [self.request(url, method) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)

    def get_stats(self) -> Dict[str, Any]:
        """Ø¥Ø±Ø¬Ø§Ø¹ Ø¥Ø­ØµØ§Ø¡Ø§Øª Ø§Ù„Ø¬Ù„Ø³Ø©"""
        total = self.stats['requests_total']
        if total:
            success_rate = round(
                self.stats['requests_success'] / total * 100, 1
            )
        else:
            success_rate = 0.0
        return {**self.stats, 'success_rate_pct': success_rate}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Ø¯Ø§Ù„Ø© Ù…Ø³Ø§Ø¹Ø¯Ø©: ØªØ´ØºÙŠÙ„ async Ù…Ù† ÙƒÙˆØ¯ Ø¹Ø§Ø¯ÙŠ (sync)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def run_async(coro):
    """
    ØªØ´ØºÙŠÙ„ coroutine Ù…Ù† ÙƒÙˆØ¯ synchronous.
    Ù…ÙÙŠØ¯ Ù„ØªØ¬Ø±Ø¨Ø© Ø§Ù„Ù…Ø­Ø±Ùƒ Ø¨Ø´ÙƒÙ„ Ù…Ø¨Ø§Ø´Ø±.
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  WAF Detection Helper (Ù…Ø³ØªØ®Ø¯Ù… Ù…Ù† recon_dz_v2.py)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def detect_waf_response(response: ResponseData) -> Optional[str]:
    """
    ÙŠÙƒØ´Ù ÙˆØ¬ÙˆØ¯ WAF Ù…Ù† Ø§Ù„Ø±Ø¯.
    ÙŠØ±Ø¬Ø¹ Ø§Ø³Ù… Ø§Ù„Ù€ WAF Ø£Ùˆ None.
    """
    if not response or response.status == 0:
        return None

    body_lower  = response.body.lower()
    headers     = {k.lower(): v.lower() for k, v in response.headers.items()}

    waf_signatures = {
        'Cloudflare':  ['cloudflare', '__cfduid', 'cf-ray'],
        'AWS WAF':     ['awswaf', 'aws-waf'],
        'Imperva':     ['incapsula', 'visid_incap', 'incap_ses'],
        'Akamai':      ['akamai', 'akamaierror'],
        'F5 BIG-IP':   ['bigip', 'f5-'],
        'Sucuri':      ['sucuri', 'x-sucuri-id'],
        'ModSecurity': ['mod_security', 'modsecurity'],
        'Fortinet':    ['fortigate', 'fortiwan'],
        'Barracuda':   ['barracuda'],
        'Nginx WAF':   ['naxsi'],
    }

    # ÙØ­Øµ headers
    for waf_name, sigs in waf_signatures.items():
        for sig in sigs:
            for hdr_val in headers.values():
                if sig in hdr_val:
                    return waf_name
            if sig in body_lower:
                return waf_name

    # ÙØ­Øµ status 403 Ù…Ø¹ Ø±Ø³Ø§Ø¦Ù„ Ø®Ø§ØµØ©
    if response.status in (403, 406, 429, 503):
        for waf_name, sigs in waf_signatures.items():
            for sig in sigs:
                if sig in body_lower:
                    return waf_name

    return None
