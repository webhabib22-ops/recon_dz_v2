"""
RECON-DZ v2 - Advanced Async Engine
Professional-grade reconnaissance with stealth capabilities
Educational and authorized security testing framework
"""

import asyncio
import aiohttp
import aiodns
import ssl
import time
import random
import socket
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from pathlib import Path
import json
import hashlib
from urllib.parse import urlparse, urljoin


@dataclass
class ResponseData:
    """Structured response with full metadata"""
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
    fingerprint: Dict[str, Any] = field(default_factory=dict)
    
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
        """Extract technology indicators"""
        hints = []
        
        # Server header
        server = self.get_header('server')
        if server:
            hints.append(f"server:{server}")
            if 'apache' in server.lower():
                hints.append("webserver:apache")
            elif 'nginx' in server.lower():
                hints.append("webserver:nginx")
            elif 'iis' in server.lower():
                hints.append("webserver:iis")
        
        # X-Powered-By
        powered = self.get_header('x-powered-by')
        if powered:
            hints.append(f"powered:{powered}")
            if 'php' in powered.lower():
                hints.append("lang:php")
            elif 'asp' in powered.lower():
                hints.append("lang:aspnet")
        
        # Content-Type analysis
        ct = self.content_type.lower()
        if 'json' in ct:
            hints.append("api:json")
        elif 'xml' in ct:
            hints.append("api:xml")
        elif 'graphql' in ct:
            hints.append("api:graphql")
        
        # Body analysis
        body_lower = self.body.lower()[:5000]
        
        # CMS detection
        if 'wp-content' in body_lower or 'wp-includes' in body_lower:
            hints.append("cms:wordpress")
        if 'drupal' in body_lower:
            hints.append("cms:drupal")
        if 'joomla' in body_lower:
            hints.append("cms:joomla")
        
        # Framework detection
        if 'laravel' in body_lower:
            hints.append("framework:laravel")
        if 'django' in body_lower:
            hints.append("framework:django")
        if 'spring' in body_lower:
            hints.append("framework:spring")
        if 'react' in body_lower:
            hints.append("frontend:react")
        if 'vue' in body_lower:
            hints.append("frontend:vue")
        if 'angular' in body_lower:
            hints.append("frontend:angular")
        
        # Admin panels
        if 'phpmyadmin' in body_lower:
            hints.append("admin:phpmyadmin")
        if 'cpanel' in body_lower:
            hints.append("admin:cpanel")
        
        return hints


class StealthProfile:
    """
    Advanced stealth profiles for evasion
    Mimics legitimate Algerian network traffic
    """
    
    # Algerian ISP User-Agents (common devices in DZ)
    ALGERIAN_PROFILES = [
        {
            'name': 'Algerie_Telecom_Android',
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-A205F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Mobile Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'ar-DZ,ar;q=0.9,fr-DZ;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'X-Requested-With': 'com.android.chrome',
            },
            'signature': 'mobile_algerian'
        },
        {
            'name': 'Ooredoo_4G_iPhone',
            'headers': {
                'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Mobile/15E148 Safari/604.1',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'ar-dz',
                'Accept-Encoding': 'gzip, deflate, br',
            },
            'signature': 'mobile_ios_algerian'
        },
        {
            'name': 'Djezzy_Opera_Mini',
            'headers': {
                'User-Agent': 'Opera/9.80 (Android; Opera Mini/7.5.33361/31.1540; U; fr) Presto/2.8.119 Version/11.1010',
                'Accept': 'text/html,application/xml;q=0.9,application/xhtml+xml,image/png,image/webp,*/*;q=0.8',
                'Accept-Language': 'fr-DZ,fr;q=0.9',
            },
            'signature': 'legacy_mobile'
        },
        {
            'name': 'Mobilis_Windows_10',
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'Accept-Language': 'fr-FR,fr;q=0.9,ar-DZ;q=0.8,ar;q=0.7,en-US;q=0.6,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
            },
            'signature': 'desktop_algerian'
        },
        {
            'name': 'Legacy_IE_Corporate',
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
                'Accept': 'text/html, application/xhtml+xml, image/jxr, */*',
                'Accept-Language': 'fr-FR',
                'Accept-Encoding': 'gzip, deflate',
            },
            'signature': 'legacy_corporate'
        },
    ]
    
    # Internal network simulation (for authorized testing)
    INTERNAL_PROFILES = [
        {
            'name': 'Internal_Scanner',
            'headers': {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'X-Forwarded-For': '10.0.0.1',
                'X-Real-IP': '10.0.0.1',
                'X-Originating-IP': '10.0.0.1',
                'X-Remote-IP': '10.0.0.1',
                'X-Remote-Addr': '10.0.0.1',
                'X-Client-IP': '10.0.0.1',
                'CF-Connecting-IP': '10.0.0.1',
                'True-Client-IP': '10.0.0.1',
            },
            'signature': 'internal_network'
        },
    ]
    
    @classmethod
    def get_random_profile(cls, internal: bool = False) -> Dict:
        """Get random stealth profile"""
        if internal:
            return random.choice(cls.INTERNAL_PROFILES)
        return random.choice(cls.ALGERIAN_PROFILES)
    
    @classmethod
    def get_profile_by_isp(cls, isp: str) -> Dict:
        """Get profile matching specific Algerian ISP"""
        isp_lower = isp.lower()
        
        for profile in cls.ALGERIAN_PROFILES:
            if isp_lower in profile['name'].lower():
                return profile
        
        return cls.ALGERIAN_PROFILES[0]  # Default


class AsyncReconEngine:
    """
    Professional async engine with advanced stealth
    For authorized security assessment only
    """
    
    def __init__(self, 
                 max_concurrent: int = 30,
                 enable_stealth: bool = True,
                 internal_mode: bool = False,
                 delay_range: Tuple[float, float] = (0.5, 2.0)):
        self.max_concurrent = max_concurrent
        self.enable_stealth = enable_stealth
        self.internal_mode = internal_mode
        self.delay_range = delay_range
        
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self._cache: Dict[str, ResponseData] = {}
        self.stats = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'retries': 0,
        }
        self._profile_rotation = 0
        
    async def initialize(self):
        """Initialize with stealth configuration"""
        # SSL context that accepts all (for testing misconfigured servers)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.set_ciphers('DEFAULT:@SECLEVEL=1')
        
        # Connection pooling
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=5,  # Conservative to avoid detection
            enable_cleanup_closed=True,
            force_close=False,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=ssl_context,
        )
        
        # Initial headers (will rotate per request)
        headers = self._get_stealth_headers()
        
        timeout = aiohttp.ClientTimeout(
            total=20,
            connect=8,
            sock_read=12
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=headers,
        )
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        
        return self
    
    def _get_stealth_headers(self) -> Dict[str, str]:
        """Get rotated stealth headers"""
        profile = StealthProfile.get_random_profile(self.internal_mode)
        headers = profile['headers'].copy()
        
        # Add randomization
        headers['Accept-Language'] = random.choice([
            'ar-DZ,ar;q=0.9',
            'fr-DZ,fr;q=0.9,ar-DZ;q=0.8',
            'ar,fr;q=0.8,en;q=0.5',
        ])
        
        return headers
    
    async def close(self):
        """Cleanup resources"""
        if self.session:
            await self.session.close()
    
    async def _apply_delay(self):
        """Random delay for stealth"""
        if self.enable_stealth:
            delay = random.uniform(*self.delay_range)
            await asyncio.sleep(delay)
    
    async def request(self, 
                     url: str, 
                     method: str = 'GET',
                     headers: Optional[Dict] = None,
                     allow_redirects: bool = True,
                     use_stealth: bool = True) -> ResponseData:
        """
        Make stealth HTTP request
        """
        await self._apply_delay()
        
        async with self.semaphore:
            start = time.perf_counter()
            
            # Rotate headers for each request
            request_headers = self._get_stealth_headers() if use_stealth and self.enable_stealth else {}
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
                    
                    # Decode with fallback
                    charset = 'utf-8'
                    try:
                        body = body_bytes.decode('utf-8')
                    except UnicodeDecodeError:
                        try:
                            body = body_bytes.decode('latin-1')
                            charset = 'latin-1'
                        except:
                            body = body_bytes.decode('utf-8', errors='ignore')
                    
                    # Update stats
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
                                    protocols: List[str] = None,
                                    www_fallback: bool = True) -> Tuple[ResponseData, str, str]:
        """
        Try multiple protocols and www fallback
        Returns: (response, protocol, actual_target)
        """
        if protocols is None:
            protocols = ['https://', 'http://']
        
        target_clean = target.replace('https://', '').replace('http://', '').rstrip('/')
        
        # Try original target
        for proto in protocols:
            url = f"{proto}{target_clean}"
            response = await self.request(url)
            
            if response.status != 0:
                return response, proto, target_clean
        
        # Try with www prefix if enabled and not already tried
        if www_fallback and not target_clean.startswith('www.'):
            www_target = f"www.{target_clean}"
            print(f"[!] Trying www fallback: {www_target}")
            
            for proto in protocols:
                url = f"{proto}{www_target}"
                response = await self.request(url)
                
                if response.status != 0:
                    return response, proto, www_target
        
        # Return last failed response
        return response, protocols[-1], target_clean
    
    async def mass_request(self, 
                          urls: List[str],
                          callback: Optional[Callable] = None,
                          show_progress: bool = True) -> List[ResponseData]:
        """Make multiple requests with progress"""
        results = []
        total = len(urls)
        
        for i, url in enumerate(urls):
            result = await self.request(url)
            results.append(result)
            
            if callback:
                try:
                    callback(result)
                except:
                    pass
            
            if show_progress and (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{total} ({(i+1)/total*100:.0f}%)")
        
        return results
    
    def get_stats(self) -> Dict:
        """Get engine statistics"""
        return self.stats.copy()


async def detect_waf_response(response: ResponseData) -> Optional[str]:
    """Detect WAF from response characteristics"""
    if not response or response.status == 0:
        return None
    
    headers = {k.lower(): v for k, v in response.headers.items()}
    body = response.body.lower()[:5000]
    
    # Cloudflare
    if 'cf-ray' in headers or 'cf-cache-status' in headers:
        return 'cloudflare'
    if 'cloudflare' in body:
        return 'cloudflare'
    
    # AWS WAF / CloudFront
    if 'x-amzn-requestid' in headers or 'x-amz-cf-id' in headers:
        return 'aws_waf'
    
    # ModSecurity
    if response.status == 406 or 'mod_security' in body or 'modsecurity' in body:
        return 'mod_security'
    
    # Incapsula / Imperva
    if 'incap_ses' in str(headers).lower() or '_incapsula_' in body:
        return 'incapsula'
    
    # Sucuri
    if 'x-sucuri-id' in headers or 'sucuri' in body:
        return 'sucuri'
    
    # Akamai
    if 'x-akamai-transformed' in headers or 'akamai' in body:
        return 'akamai'
    
    # F5 BIG-IP / ASM
    if response.status == 399 or 'the requested url was rejected' in body:
        return 'f5_asm'
    
    # Barracuda
    if 'barra' in str(headers).lower():
        return 'barracuda'
    
    # Fortinet
    if 'fortigate' in body or 'fortinet' in body:
        return 'fortinet'
    
    # Generic detection
    if response.status in [403, 406, 501, 999]:
        if any(x in body for x in ['blocked', 'security', 'firewall', 'waf', 'access denied']):
            return 'generic_waf'
    
    return None
