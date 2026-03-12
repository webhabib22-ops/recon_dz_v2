#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Async Engine with DNS-over-HTTPS
Fixed: broken unicode comments, aiohttp timeout objects,
       thread-safe stats, improved WAF detection, retry logic
"""

import asyncio
import aiohttp
import ssl
import time
import random
import socket
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field


# ─────────────────────────── Response Model ────────────────────────────

@dataclass
class ResponseData:
    """Structured HTTP response container."""
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
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower(), default)

    def extract_technology_hints(self) -> List[str]:
        """Extract technology indicators from response."""
        hints = []
        server = self.get_header('server')
        if server:
            hints.append(f"server:{server}")
        x_powered = self.get_header('x-powered-by')
        if x_powered:
            hints.append(f"powered_by:{x_powered}")

        body_lower = self.body.lower()[:10000]
        tech_patterns = {
            'cms:wordpress':      ['wp-content', 'wp-includes', 'wp-json'],
            'cms:joomla':         ['com_content', 'joomla', '/components/com_'],
            'cms:drupal':         ['drupal.js', 'sites/default/', 'drupal-settings'],
            'framework:laravel':  ['laravel_session', 'x-laravel'],
            'framework:django':   ['csrfmiddlewaretoken', '__django'],
            'frontend:react':     ['react-root', '__react', 'data-reactroot'],
            'frontend:angular':   ['ng-version', 'ng-app', 'angular.min.js'],
            'frontend:vue':       ['vue.js', '__vue__', 'v-app'],
            'server:nginx':       ['nginx'],
            'server:apache':      ['apache'],
            'platform:php':       ['x-powered-by: php'],
            'runtime:node':       ['x-powered-by: express', 'node.js'],
        }
        for tech, patterns in tech_patterns.items():
            if any(p in body_lower for p in patterns):
                hints.append(tech)

        return list(set(hints))


# ─────────────────────────── DoH DNS Resolver ──────────────────────────

class DNSResolver:
    """
    Multi-strategy DNS resolver:
      1. DNS-over-HTTPS (Cloudflare / Google / Quad9) — bypasses censorship
      2. aiodns async system resolver (fast, non-blocking)
      3. socket.getaddrinfo  synchronous fallback (always works if network is up)

    The three-layer fallback means the engine NEVER fails on DNS even when
    DoH providers are unreachable (Termux, restricted networks, firewalls).
    """

    DOH_SERVERS = [
        ('Cloudflare', 'https://cloudflare-dns.com/dns-query'),
        ('Google',     'https://dns.google/resolve'),
        ('Quad9',      'https://dns.quad9.net:5053/dns-query'),
    ]

    def __init__(self):
        self._cache: Dict[str, Optional[str]] = {}
        self._session:     Optional[aiohttp.ClientSession] = None
        self._aiodns:      Optional[Any]                   = None  # aiodns.Resolver

    async def initialize(self):
        """Set up DoH session and aiodns resolver."""
        # DoH session — no SSL verification needed for DNS queries
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout   = aiohttp.ClientTimeout(total=5, connect=3)
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=timeout
        )

        # aiodns — optional, only used if the package is installed
        try:
            import aiodns
            self._aiodns = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        except (ImportError, Exception):
            self._aiodns = None

    async def resolve(self, hostname: str,
                      record_type: str = 'A') -> Optional[str]:
        """
        Resolve hostname → IP using three fallback strategies.
        Returns the first IP found, or None if all fail.
        """
        # Strip any path/port accidentally included in hostname
        hostname = hostname.split('/')[0].split(':')[0].strip()
        if not hostname:
            return None

        cache_key = f"{hostname}:{record_type}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        ip: Optional[str] = None

        # ── Strategy 1: DoH (Cloudflare → Google → Quad9) ──────────
        for _name, doh_url in self.DOH_SERVERS:
            try:
                ip = await asyncio.wait_for(
                    self._query_doh(doh_url, hostname, record_type),
                    timeout=5.0
                )
                if ip:
                    break
            except Exception:
                continue

        # ── Strategy 2: aiodns async resolver ──────────────────────
        if not ip and self._aiodns:
            try:
                qtype = 'A' if record_type == 'A' else 'AAAA'
                result = await asyncio.wait_for(
                    self._aiodns.query(hostname, qtype),
                    timeout=5.0
                )
                if result:
                    ip = str(result[0].host)
            except Exception:
                pass

        # ── Strategy 3: synchronous socket (always available) ──────
        if not ip:
            try:
                loop   = asyncio.get_event_loop()
                family = socket.AF_INET if record_type == 'A' else socket.AF_INET6
                infos  = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: socket.getaddrinfo(
                            hostname, None, family, socket.SOCK_STREAM
                        )
                    ),
                    timeout=8.0
                )
                if infos:
                    ip = infos[0][4][0]
            except Exception:
                pass

        self._cache[cache_key] = ip
        return ip

    async def _query_doh(self, doh_url: str, hostname: str,
                          record_type: str = 'A') -> Optional[str]:
        """Issue a single DoH query."""
        rtype_num = 1 if record_type == 'A' else 28
        params    = {'name': hostname, 'type': record_type}
        headers   = {'Accept': 'application/dns-json'}
        async with self._session.get(
            doh_url, params=params, headers=headers
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                for answer in data.get('Answer', []):
                    if answer.get('type') == rtype_num:
                        return answer.get('data', '').rstrip('.')
        return None

    async def close(self):
        """Close the DoH session."""
        if self._session and not self._session.closed:
            await self._session.close()


# ──────────────────────── Async Recon Engine ───────────────────────────

class AsyncReconEngine:
    """
    Professional async HTTP engine with:
    - DNS-over-HTTPS for censorship bypass
    - Semaphore-based concurrency control
    - Stealth mode with random delays
    - Retry logic with exponential backoff
    - Thread-safe statistics
    """

    DEFAULT_HEADERS = {
        'User-Agent':      ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                            'AppleWebKit/537.36 (KHTML, like Gecko) '
                            'Chrome/124.0.0.0 Safari/537.36'),
        'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection':      'keep-alive',
    }

    def __init__(self,
                 max_concurrent: int = 30,
                 enable_stealth: bool = False,
                 internal_mode: bool = False,
                 delay_range: Tuple[float, float] = (0.0, 0.0),
                 request_timeout: int = 15,
                 connect_timeout: int = 5):
        self.max_concurrent   = max_concurrent
        self.enable_stealth   = enable_stealth
        self.internal_mode    = internal_mode
        self.delay_range      = delay_range
        self.request_timeout  = request_timeout
        self.connect_timeout  = connect_timeout

        self._session:      Optional[aiohttp.ClientSession] = None
        self.dns_resolver:  Optional[DNSResolver] = None
        self._semaphore:    Optional[asyncio.Semaphore] = None

        # [FIX] Thread-safe stats as a simple dict; use get_stats() for read
        self._stats = {
            'requests_total':   0,
            'requests_success': 0,
            'requests_failed':  0,
            'bytes_received':   0,
        }

    @property
    def stats(self) -> Dict[str, Any]:
        """Return a snapshot of current statistics."""
        return dict(self._stats)

    async def initialize(self):
        """Initialize the engine: DoH resolver + aiohttp session + semaphore."""
        print("[*] Initializing DNS-over-HTTPS resolver...")
        self.dns_resolver = DNSResolver()
        await self.dns_resolver.initialize()

        # ssl=False on the connector lets each request decide its own SSL handling.
        # Passing an ssl_ctx here conflicts with ssl=False in individual requests
        # and causes "Cannot connect to host ... ssl:False" errors even when
        # the host is reachable. Setting ssl=False at connector level disables
        # certificate verification globally (acceptable for recon tools).
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=5,
            enable_cleanup_closed=True,
            ssl=False,              # No SSL verification — avoids cert errors
            ttl_dns_cache=300,
        )

        # [FIX] Proper ClientTimeout object
        timeout = aiohttp.ClientTimeout(
            total=self.request_timeout,
            connect=self.connect_timeout,
        )

        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.DEFAULT_HEADERS,
        )

        # [FIX] Semaphore created inside async context (has running event loop)
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        print(f"[+] Engine ready (concurrent={self.max_concurrent}, "
              f"stealth={'yes' if self.enable_stealth else 'no'})")
        return self

    async def close(self):
        """Gracefully close all connections."""
        if self.dns_resolver:
            await self.dns_resolver.close()
        if self._session and not self._session.closed:
            await self._session.close()

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        """Resolve hostname via DoH."""
        if self.dns_resolver:
            return await self.dns_resolver.resolve(hostname)
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Return enriched statistics snapshot."""
        total = self._stats['requests_total']
        rate  = round(self._stats['requests_success'] / total * 100, 1) if total else 0.0
        return {**self._stats, 'success_rate_pct': rate}

    # ──────────────── Core Request Methods ────────────────────────────

    async def request(self, url: str, method: str = 'GET',
                      extra_headers: Optional[Dict[str, str]] = None,
                      data: Optional[Any] = None,
                      retries: int = 1) -> ResponseData:
        """
        Make a single HTTP request with:
        - Semaphore concurrency control
        - Optional stealth delay
        - Retry with exponential backoff
        """
        async with self._semaphore:
            # Stealth mode: random delay between requests
            if self.delay_range and self.delay_range[1] > 0:
                await asyncio.sleep(random.uniform(*self.delay_range))

            last_error = None
            for attempt in range(retries + 1):
                if attempt > 0:
                    await asyncio.sleep(0.5 * (2 ** attempt))  # exponential backoff

                start = time.perf_counter()
                try:
                    merged_headers = {}
                    if extra_headers:
                        merged_headers.update(extra_headers)

                    async with self._session.request(
                        method=method,
                        url=url,
                        headers=merged_headers or None,
                        ssl=False,
                        allow_redirects=True,
                        data=data,
                    ) as resp:
                        body_bytes = await resp.read()
                        elapsed = time.perf_counter() - start

                        try:
                            body    = body_bytes.decode('utf-8')
                            charset = 'utf-8'
                        except UnicodeDecodeError:
                            body    = body_bytes.decode('latin-1', errors='ignore')
                            charset = 'latin-1'

                        self._stats['requests_total'] += 1
                        self._stats['bytes_received'] += len(body_bytes)
                        if resp.status < 400:
                            self._stats['requests_success'] += 1
                        else:
                            self._stats['requests_failed'] += 1

                        return ResponseData(
                            url=url,
                            status=resp.status,
                            headers={k.lower(): v for k, v in resp.headers.items()},
                            body=body[:150_000],
                            body_bytes=body_bytes,
                            content_type=resp.headers.get('Content-Type', ''),
                            charset=charset,
                            elapsed=elapsed,
                            final_url=str(resp.url),
                            redirect_count=len(resp.history),
                            protocol='https' if url.startswith('https') else 'http',
                        )

                except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                    last_error = str(exc)
                    self._stats['requests_failed'] += 1
                    continue
                except Exception as exc:
                    last_error = str(exc)
                    self._stats['requests_failed'] += 1
                    break

            return _error_response(url, last_error or "Unknown error")

    async def _request_with_host(self, url: str,
                                  host_header: str) -> ResponseData:
        """
        Send a request to an IP address but include the original Host header.
        Bypasses DNS entirely — useful for DoH-resolved IPs.
        """
        return await self.request(url, extra_headers={'Host': host_header})

    async def request_with_fallback(
        self,
        hostname: str,
        www_fallback: bool = True,
        path: str = '/',
    ) -> Tuple[ResponseData, str, str]:
        """
        Try multiple connection strategies in order until one succeeds:

          For each candidate hostname (bare, then www.):
            1. DoH resolve → IP + Host header  (HTTPS then HTTP)
            2. Direct hostname URL via system DNS  (HTTPS then HTTP)

        Returns: (ResponseData, protocol_str, actual_hostname)
        """
        candidates: List[str] = [hostname]
        if www_fallback and not hostname.startswith('www.'):
            candidates.append(f'www.{hostname}')

        last_response: Optional[ResponseData] = None

        for host in candidates:
            ip = await self.resolve_hostname(host)

            for proto in ('https://', 'http://'):
                # Attempt A: resolved IP + Host header (bypass CDN/DNS)
                if ip:
                    url  = f"{proto}{ip}{path}"
                    resp = await self._request_with_host(url, host)
                    last_response = resp
                    if resp.status != 0 and resp.status < 500:
                        resp.final_url = f"{proto}{host}{path}"
                        resp.protocol  = proto.rstrip('://')
                        return resp, proto, host

                # Attempt B: direct hostname (system DNS via aiohttp)
                url  = f"{proto}{host}{path}"
                resp = await self.request(url)
                last_response = resp
                if resp.status != 0 and resp.status < 500:
                    resp.final_url = url
                    resp.protocol  = proto.rstrip('://')
                    return resp, proto, host

        error_resp = last_response or _error_response(
            f"https://{hostname}{path}",
            "All connection attempts failed (DoH + direct + www)"
        )
        return error_resp, 'https://', hostname

    async def batch_request(self, urls: List[str],
                             method: str = 'GET') -> List[ResponseData]:
        """Send multiple requests concurrently and return ordered results."""
        tasks = [self.request(url, method) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def request_with_resolution(self, hostname: str,
                                       path: str = '/') -> ResponseData:
        """Resolve then request (single hostname, no fallback)."""
        ip = await self.resolve_hostname(hostname)
        if not ip:
            return _error_response(
                f"http://{hostname}{path}", "DNS resolution failed"
            )
        resp = await self._request_with_host(f"https://{ip}{path}", hostname)
        if resp.status == 0:
            resp = await self._request_with_host(f"http://{ip}{path}", hostname)
        if resp.status != 0:
            resp.final_url = f"https://{hostname}{path}"
        return resp


# ────────────────────────── Helper Functions ───────────────────────────

def _error_response(url: str, error: str) -> ResponseData:
    """Build a zero-status error ResponseData."""
    return ResponseData(
        url=url, status=0, headers={}, body='', body_bytes=b'',
        content_type='', charset='', elapsed=0.0,
        final_url=url, redirect_count=0, error=error,
        protocol='https' if url.startswith('https') else 'http',
    )


def run_async(coro):
    """Run an async coroutine from synchronous code (safe for Jupyter/Termux)."""
    try:
        loop = asyncio.get_running_loop()
        # Already inside a running loop — use a thread
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            return pool.submit(asyncio.run, coro).result()
    except RuntimeError:
        return asyncio.run(coro)


# ──────────────────────── WAF Detection ───────────────────────────────

# (Signatures keyed by WAF name → list of indicators)
_WAF_SIGNATURES: Dict[str, List[str]] = {
    'Cloudflare':   ['cloudflare', '__cfduid', 'cf-ray', 'cf-cache-status'],
    'AWS WAF':      ['awswaf', 'x-amzn-requestid', 'x-amz-cf-id'],
    'Imperva':      ['incapsula', 'visid_incap', 'incap_ses', 'x-iinfo'],
    'Akamai':       ['akamai', 'akamaierror', 'x-check-cacheable', 'ak_bmsc'],
    'F5 BIG-IP':    ['bigip', 'f5-', 'x-wa-info', 'x-cnection'],
    'Sucuri':       ['sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
    'ModSecurity':  ['mod_security', 'modsecurity'],
    'Fortinet':     ['fortigate', 'fortiwan', 'fortiproxy'],
    'Barracuda':    ['barracuda', 'barra_counter_session'],
    'NAXSI':        ['naxsi', 'nginx-naxsi'],
    'Wordfence':    ['wordfence'],
    'Palo Alto':    ['pandb', 'x-pan-'],
    'Nginx Plus':   ['x-nginx-cache', 'nginx-cache'],
}


def detect_waf_response(response: ResponseData) -> Optional[str]:
    """
    Detect WAF/CDN from response headers and body.
    Returns the WAF name or None.
    """
    if not response or response.status == 0:
        return None

    body_lower    = response.body.lower()[:5000]
    header_str    = ' '.join(
        f"{k}:{v}" for k, v in response.headers.items()
    ).lower()
    combined      = header_str + ' ' + body_lower

    for waf_name, signatures in _WAF_SIGNATURES.items():
        if any(sig in combined for sig in signatures):
            return waf_name

    return None

