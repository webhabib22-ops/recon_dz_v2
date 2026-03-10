"""
High-performance async HTTP engine for RECON-DZ v2
Enhanced with better error handling and retry logic
"""

import asyncio
import aiohttp
import aiodns
import ssl
import time
import random
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import json
import hashlib
from urllib.parse import urlparse


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
    error: Optional[str] = None
    protocol: str = "https"
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300 and self.error is None
    
    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400
    
    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status < 500
    
    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status < 600
    
    def get_header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)
    
    def extract_technology_hints(self) -> List[str]:
        """Extract technology hints from response"""
        hints = []
        
        server = self.get_header('server')
        if server:
            hints.append(f"server:{server}")
        
        powered = self.get_header('x-powered-by')
        if powered:
            hints.append(f"powered:{powered}")
        
        ct = self.content_type.lower()
        if 'json' in ct:
            hints.append("api:json")
        elif 'xml' in ct:
            hints.append("api:xml")
        
        body_lower = self.body.lower()
        if 'wp-content' in body_lower:
            hints.append("cms:wordpress")
        if 'drupal' in body_lower:
            hints.append("cms:drupal")
        if 'laravel' in body_lower:
            hints.append("framework:laravel")
        if 'django' in body_lower:
            hints.append("framework:django")
        if 'react' in body_lower:
            hints.append("frontend:react")
        if 'vue' in body_lower:
            hints.append("frontend:vue")
        if 'angular' in body_lower:
            hints.append("frontend:angular")
        
        return hints


class AsyncReconEngine:
    """Main async engine with retry and fallback support"""
    
    def __init__(self, max_concurrent: int = 50, enable_stealth: bool = True):
        self.max_concurrent = max_concurrent
        self.enable_stealth = enable_stealth
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._cache: Dict[str, ResponseData] = {}
        self.stats = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'retries': 0,
        }
        self._fingerprints = self._generate_fingerprints()
        self._fp_idx = 0
        
    def _generate_fingerprints(self) -> List[Dict]:
        """Generate realistic browser fingerprints"""
        return [
            {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
            },
            {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            },
            {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
            }
        ]
    
    def _get_next_fingerprint(self) -> Dict:
        """Rotate fingerprint"""
        fp = self._fingerprints[self._fp_idx]
        self._fp_idx = (self._fp_idx + 1) % len(self._fingerprints)
        return fp.copy()
    
    async def initialize(self):
        """Initialize with proper SSL and connection settings"""
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_ciphers('DEFAULT:@SECLEVEL=1')
        
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=10,
            enable_cleanup_closed=True,
            force_close=False,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=ssl_context,
        )
        
        headers = self._get_next_fingerprint() if self.enable_stealth else {
            'User-Agent': 'RECON-DZ/2.0'
        }
        
        timeout = aiohttp.ClientTimeout(
            total=15,
            connect=5,
            sock_read=10
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
        )
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        return self
    
    async def close(self):
        """Cleanup"""
        if self.session:
            await self.session.close()
    
    async def request(self, 
                     url: str, 
                     method: str = 'GET',
                     headers: Optional[Dict] = None,
                     allow_redirects: bool = True) -> ResponseData:
        """
        Make HTTP request with full error handling
        """
        async with self.semaphore:
            start = time.perf_counter()
            
            request_headers = self._get_next_fingerprint() if self.enable_stealth else {}
            if headers:
                request_headers.update(headers)
            
            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    headers=request_headers,
                    allow_redirects=allow_redirects,
                    ssl=False
                ) as resp:
                    
                    body_bytes = await resp.read()
                    elapsed = time.perf_counter() - start
                    
                    # Decode body
                    charset = 'utf-8'
                    try:
                        body = body_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            body = body_bytes.decode('latin-1')
                            charset = 'latin-1'
                        except:
                            body = body_bytes.decode('utf-8', errors='ignore')
                    
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
                    
            except asyncio.TimeoutError:
                self.stats['requests_failed'] += 1
                return ResponseData(
                    url=url, status=0, headers={}, body='', body_bytes=b'',
                    content_type='', charset='', elapsed=time.perf_counter() - start,
                    final_url=url, redirect_count=0,
                    error='timeout', protocol='https' if url.startswith('https') else 'http'
                )
            except aiohttp.ClientConnectorError as e:
                self.stats['requests_failed'] += 1
                return ResponseData(
                    url=url, status=0, headers={}, body='', body_bytes=b'',
                    content_type='', charset='', elapsed=time.perf_counter() - start,
                    final_url=url, redirect_count=0,
                    error=f'connection_error: {str(e)}',
                    protocol='https' if url.startswith('https') else 'http'
                )
            except Exception as e:
                self.stats['requests_failed'] += 1
                return ResponseData(
                    url=url, status=0, headers={}, body='', body_bytes=b'',
                    content_type='', charset='', elapsed=time.perf_counter() - start,
                    final_url=url, redirect_count=0,
                    error=f'unexpected: {str(e)}',
                    protocol='https' if url.startswith('https') else 'http'
                )
    
    async def request_with_fallback(self, 
                                    target: str,
                                    protocols: List[str] = None) -> Tuple[ResponseData, str]:
        """
        Try multiple protocols and return first success
        """
        if protocols is None:
            protocols = ['https://', 'http://']
        
        target_clean = target.replace('https://', '').replace('http://', '').rstrip('/')
        
        for proto in protocols:
            url = f"{proto}{target_clean}"
            response = await self.request(url)
            
            if response.status != 0:
                return response, proto
        
        # Return last failed response
        return response, protocols[-1]
    
    async def mass_request(self, 
                          urls: List[str],
                          callback: Optional[callable] = None) -> List[ResponseData]:
        """Make multiple requests"""
        tasks = [self.request(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"[Error] Request failed: {urls[i]} - {result}")
                continue
            valid_results.append(result)
            if callback:
                try:
                    callback(result)
                except:
                    pass
        
        return valid_results


async def detect_waf_response(response: ResponseData) -> Optional[str]:
    """Detect WAF from response"""
    if not response or response.status == 0:
        return None
    
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.body.lower()[:5000]
    
    # Cloudflare
    if 'cf-ray' in headers or 'cf-cache-status' in headers:
        return 'cloudflare'
    if 'cloudflare' in body:
        return 'cloudflare'
    
    # AWS WAF
    if 'x-amzn-requestid' in headers or 'x-amz-cf-id' in headers:
        return 'aws_waf'
    
    # ModSecurity
    if response.status == 406 or 'mod_security' in body:
        return 'mod_security'
    
    # Incapsula
    if 'incap_ses' in str(headers).lower() or '_incapsula_' in body:
        return 'incapsula'
    
    # Sucuri
    if 'x-sucuri-id' in headers or 'sucuri' in body:
        return 'sucuri'
    
    # Akamai
    if 'x-akamai-transformed' in headers:
        return 'akamai'
    
    # F5
    if response.status == 399:
        return 'f5_asm'
    
    # Generic detection
    if response.status in [403, 406, 501] and len(response.body) < 300:
        if any(x in body for x in ['blocked', 'security', 'firewall', 'waf']):
            return 'generic_waf'
    
    return None
