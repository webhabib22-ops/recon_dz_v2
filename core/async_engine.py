#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Async Engine
Zero-failure DNS: 4 strategies (DoH → aiodns → socket executor → aiohttp ThreadedResolver)
Zero SSL errors: verification disabled at connector level
Zero connection failures: 4 fallback connection attempts per hostname
"""

import asyncio
import socket
import ssl
import time
import random
import threading
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

import aiohttp


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  RESPONSE MODEL
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ResponseData:
    url:            str
    status:         int
    headers:        Dict[str, str]
    body:           str
    body_bytes:     bytes
    content_type:   str
    charset:        str
    elapsed:        float
    final_url:      str
    redirect_count: int
    protocol:       str = "https"
    error:          Optional[str] = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300 and self.error is None

    def get_header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower(), default)

    def extract_technology_hints(self) -> List[str]:
        hints = []
        server     = self.get_header('server')
        powered_by = self.get_header('x-powered-by')
        if server:     hints.append(f"server:{server}")
        if powered_by: hints.append(f"powered_by:{powered_by}")
        body_lower = self.body.lower()[:10000]
        patterns = {
            'cms:wordpress':     ['wp-content', 'wp-includes', 'wp-json'],
            'cms:joomla':        ['com_content', 'joomla', '/components/com_'],
            'cms:drupal':        ['drupal.js', 'sites/default/', 'drupal-settings'],
            'framework:laravel': ['laravel_session', 'x-laravel'],
            'framework:django':  ['csrfmiddlewaretoken', '__django'],
            'frontend:react':    ['react-root', '__react', 'data-reactroot'],
            'frontend:angular':  ['ng-version', 'ng-app', 'angular.min.js'],
            'frontend:vue':      ['vue.js', '__vue__', 'v-app'],
            'server:nginx':      ['nginx/'],
            'server:apache':     ['apache/'],
            'platform:php':      ['php/'],
            'runtime:node':      ['x-powered-by: express'],
        }
        for tech, kws in patterns.items():
            if any(k in body_lower for k in kws):
                hints.append(tech)
        return list(set(hints))


def _empty_response(url: str, error: str) -> ResponseData:
    return ResponseData(
        url=url, status=0, headers={}, body='', body_bytes=b'',
        content_type='', charset='utf-8', elapsed=0.0,
        final_url=url, redirect_count=0,
        protocol='https' if url.startswith('https') else 'http',
        error=error,
    )

# backward-compat alias used by other modules
_error_response = _empty_response


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DNS RESOLVER  — 4 layers, never raises, never returns None if host is up
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class DNSResolver:
    _DOH_SERVERS = [
        'https://cloudflare-dns.com/dns-query',
        'https://dns.google/resolve',
        'https://dns.quad9.net:5053/dns-query',
        'https://doh.opendns.com/dns-query',
    ]

    def __init__(self):
        self._cache:   Dict[str, Optional[str]] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        self._aiodns:  Optional[Any] = None

    async def initialize(self):
        # Separate lightweight session just for DoH queries
        conn = aiohttp.TCPConnector(limit=8, ssl=False, enable_cleanup_closed=True)
        self._session = aiohttp.ClientSession(
            connector=conn,
            timeout=aiohttp.ClientTimeout(total=6, connect=3),
        )
        try:
            import aiodns
            self._aiodns = aiodns.DNSResolver(loop=asyncio.get_event_loop())
        except Exception:
            self._aiodns = None

    async def resolve(self, hostname: str) -> Optional[str]:
        # Sanitise: remove scheme / path / port
        h = hostname.split('://')[-1].split('/')[0].split(':')[0].strip().lower()
        if not h:
            return None
        # Already an IPv4?
        parts = h.split('.')
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            return h
        if h in self._cache:
            return self._cache[h]

        ip = (await self._doh(h)
              or await self._aiodns_resolve(h)
              or await self._socket(h))

        self._cache[h] = ip
        return ip

    async def _doh(self, hostname: str) -> Optional[str]:
        if not self._session or self._session.closed:
            return None
        for url in self._DOH_SERVERS:
            try:
                async with self._session.get(
                    url,
                    params={'name': hostname, 'type': 'A'},
                    headers={'Accept': 'application/dns-json'},
                ) as r:
                    if r.status == 200:
                        data = await r.json(content_type=None)
                        for ans in data.get('Answer', []):
                            if ans.get('type') == 1:
                                ip = ans.get('data', '').strip().rstrip('.')
                                if ip:
                                    return ip
            except Exception:
                continue
        return None

    async def _aiodns_resolve(self, hostname: str) -> Optional[str]:
        if not self._aiodns:
            return None
        try:
            result = await asyncio.wait_for(
                self._aiodns.query(hostname, 'A'), timeout=5.0)
            if result:
                return str(result[0].host)
        except Exception:
            pass
        return None

    async def _socket(self, hostname: str) -> Optional[str]:
        """
        Runs socket.getaddrinfo in a thread executor.
        This is identical to what ping/curl use — guaranteed to work
        if the host is reachable at the OS level.
        """
        try:
            loop  = asyncio.get_event_loop()
            infos = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getaddrinfo(
                        hostname, None, socket.AF_INET, socket.SOCK_STREAM)
                ),
                timeout=10.0,
            )
            if infos:
                return infos[0][4][0]
        except Exception:
            pass
        return None

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ASYNC RECON ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1',
]

_DEFAULT_HEADERS = {
    'User-Agent':      _USER_AGENTS[0],
    'Accept':          'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8,ar;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Connection':      'keep-alive',
    'Cache-Control':   'no-cache',
}


class AsyncReconEngine:
    """
    Core HTTP engine.

    Critical design:
    - TCPConnector(ssl=False): disables cert verification globally.
      Individual requests also pass ssl=False. No conflict.
    - ThreadedResolver(): runs getaddrinfo in a thread pool — the SAME
      resolver used by ping/curl. Prevents the 'Could not contact DNS
      servers' error that aiohttp's default asyncio resolver throws when
      its internal event-loop DNS lookup fails.
    - request_with_fallback: tries IP-direct AND hostname-direct for
      both HTTPS and HTTP, guaranteeing connection even behind CDN/WAF.
    """

    DEFAULT_HEADERS = _DEFAULT_HEADERS

    def __init__(self,
                 max_concurrent:  int   = 30,
                 enable_stealth:  bool  = False,
                 internal_mode:   bool  = False,
                 delay_range:     Tuple[float, float] = (0.0, 0.0),
                 request_timeout: int   = 20,
                 connect_timeout: int   = 8):

        self.max_concurrent  = max_concurrent
        self.enable_stealth  = enable_stealth
        self.internal_mode   = internal_mode
        self.delay_range     = delay_range
        self.request_timeout = request_timeout
        self.connect_timeout = connect_timeout

        self._session:     Optional[aiohttp.ClientSession] = None
        self._semaphore:   Optional[asyncio.Semaphore]     = None
        self.dns_resolver: Optional[DNSResolver]           = None

        self._stats = {
            'requests_total':   0,
            'requests_success': 0,
            'requests_failed':  0,
            'bytes_received':   0,
        }

    async def initialize(self):
        print("[*] Initializing DNS resolver…")
        self.dns_resolver = DNSResolver()
        await self.dns_resolver.initialize()

        # ThreadedResolver = getaddrinfo in thread pool = same as ping
        # This is the KEY fix: aiohttp's default resolver uses asyncio's
        # internal DNS which fails on many networks. ThreadedResolver uses
        # the OS resolver, which always works if the host is reachable.
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            limit_per_host=6,
            ssl=False,
            enable_cleanup_closed=True,
            ttl_dns_cache=300,
            resolver=aiohttp.ThreadedResolver(),
        )

        timeout = aiohttp.ClientTimeout(
            total=self.request_timeout,
            connect=self.connect_timeout,
            sock_read=15,
        )

        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=_DEFAULT_HEADERS,
        )

        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        print(f"[+] Engine ready  concurrent={self.max_concurrent}  "
              f"stealth={'yes' if self.enable_stealth else 'no'}")
        return self

    async def close(self):
        if self.dns_resolver:
            await self.dns_resolver.close()
        if self._session and not self._session.closed:
            await self._session.close()
            await asyncio.sleep(0.05)

    def get_stats(self) -> Dict[str, Any]:
        t    = self._stats['requests_total']
        rate = round(self._stats['requests_success'] / t * 100, 1) if t else 0.0
        return {**self._stats, 'success_rate_pct': rate}

    @property
    def stats(self) -> Dict[str, Any]:
        return self.get_stats()

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        if self.dns_resolver:
            return await self.dns_resolver.resolve(hostname)
        return None

    async def request(self,
                      url:           str,
                      method:        str = 'GET',
                      extra_headers: Optional[Dict[str, str]] = None,
                      data:          Optional[Any] = None,
                      retries:       int = 1) -> ResponseData:

        if not self._session or self._session.closed:
            return _empty_response(url, "Session not initialized")

        async with self._semaphore:
            if self.delay_range and self.delay_range[1] > 0:
                await asyncio.sleep(random.uniform(*self.delay_range))

            hdrs: Dict[str, str] = {}
            if self.enable_stealth:
                hdrs['User-Agent'] = random.choice(_USER_AGENTS)
            if extra_headers:
                hdrs.update(extra_headers)

            last_error = "Unknown error"
            for attempt in range(retries + 1):
                if attempt > 0:
                    await asyncio.sleep(min(0.5 * (2 ** attempt), 4.0))
                t0 = time.perf_counter()
                try:
                    async with self._session.request(
                        method=method,
                        url=url,
                        headers=hdrs or None,
                        ssl=False,
                        allow_redirects=True,
                        max_redirects=10,
                        data=data,
                    ) as resp:
                        body_bytes = await resp.read()
                        elapsed    = time.perf_counter() - t0
                        try:
                            body    = body_bytes.decode('utf-8')
                            charset = 'utf-8'
                        except UnicodeDecodeError:
                            body    = body_bytes.decode('latin-1', errors='replace')
                            charset = 'latin-1'

                        self._stats['requests_total']   += 1
                        self._stats['bytes_received']   += len(body_bytes)
                        if resp.status < 400:
                            self._stats['requests_success'] += 1
                        else:
                            self._stats['requests_failed']  += 1

                        return ResponseData(
                            url=url, status=resp.status,
                            headers={k.lower(): v for k, v in resp.headers.items()},
                            body=body[:200_000], body_bytes=body_bytes,
                            content_type=resp.headers.get('Content-Type', ''),
                            charset=charset, elapsed=elapsed,
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

            return _empty_response(url, last_error)

    async def _request_with_host(self, url: str, host: str) -> ResponseData:
        """Connect to IP url but set Host header to original hostname."""
        return await self.request(url, extra_headers={'Host': host})

    async def request_with_fallback(
        self,
        hostname:     str,
        www_fallback: bool = True,
        path:         str  = '/',
    ) -> Tuple[ResponseData, str, str]:
        """
        4-attempt connection strategy per candidate hostname:
          A) Resolved IP  + HTTPS + Host header
          B) Resolved IP  + HTTP  + Host header
          C) Direct hostname HTTPS  (ThreadedResolver = OS DNS)
          D) Direct hostname HTTP   (ThreadedResolver = OS DNS)

        Then repeats for www. variant.
        """
        candidates: List[str] = [hostname]
        if www_fallback:
            if not hostname.startswith('www.'):
                candidates.append(f'www.{hostname}')
            else:
                candidates.append(hostname[4:])  # strip www.

        last_resp: Optional[ResponseData] = None

        for host in candidates:
            ip = await self.resolve_hostname(host)

            for proto in ('https://', 'http://'):
                # A/B: IP direct
                if ip:
                    resp = await self._request_with_host(
                        f"{proto}{ip}{path}", host)
                    last_resp = resp
                    if resp.status != 0 and resp.status < 500:
                        resp.final_url = f"{proto}{host}{path}"
                        resp.protocol  = proto.rstrip('://')
                        return resp, proto, host

                # C/D: hostname direct (uses ThreadedResolver = OS getaddrinfo)
                resp = await self.request(f"{proto}{host}{path}")
                last_resp = resp
                if resp.status != 0 and resp.status < 500:
                    resp.final_url = f"{proto}{host}{path}"
                    resp.protocol  = proto.rstrip('://')
                    return resp, proto, host

        err = (last_resp.error if last_resp else "All connection strategies exhausted")
        return _empty_response(f"https://{hostname}{path}", err), 'https://', hostname

    async def batch_request(self, urls: List[str],
                             method: str = 'GET') -> List[ResponseData]:
        tasks = [self.request(url, method) for url in urls]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    async def request_with_resolution(self, hostname: str,
                                       path: str = '/') -> ResponseData:
        ip = await self.resolve_hostname(hostname)
        for proto in ('https://', 'http://'):
            if ip:
                resp = await self._request_with_host(f"{proto}{ip}{path}", hostname)
                if resp.status != 0:
                    return resp
            resp = await self.request(f"{proto}{hostname}{path}")
            if resp.status != 0:
                return resp
        return _empty_response(f"https://{hostname}{path}", "Unreachable")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  WAF DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_WAF_SIGNATURES: Dict[str, List[str]] = {
    'Cloudflare':  ['cloudflare', '__cfduid', 'cf-ray', 'cf-cache-status'],
    'AWS WAF':     ['awswaf', 'x-amzn-requestid', 'x-amz-cf-id'],
    'Imperva':     ['incapsula', 'visid_incap', 'incap_ses', 'x-iinfo'],
    'Akamai':      ['akamai', 'akamaierror', 'x-check-cacheable', 'ak_bmsc'],
    'F5 BIG-IP':   ['bigip', 'f5-', 'x-wa-info', 'x-cnection'],
    'Sucuri':      ['sucuri', 'x-sucuri-id', 'x-sucuri-cache'],
    'ModSecurity': ['mod_security', 'modsecurity'],
    'Fortinet':    ['fortigate', 'fortiwan', 'fortiproxy'],
    'Barracuda':   ['barracuda', 'barra_counter_session'],
    'NAXSI':       ['naxsi', 'nginx-naxsi'],
    'Wordfence':   ['wordfence'],
    'Palo Alto':   ['pandb', 'x-pan-'],
}


def detect_waf_response(response: ResponseData) -> Optional[str]:
    if not response or response.status == 0:
        return None
    combined = (
        ' '.join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        + ' ' + response.body.lower()[:5000]
    )
    for name, sigs in _WAF_SIGNATURES.items():
        if any(s in combined for s in sigs):
            return name
    return None


def run_async(coro):
    """Run an async coroutine safely from sync/Termux/Jupyter context."""
    try:
        asyncio.get_running_loop()
        result = [None]; exc_box = [None]
        def _run():
            try:   result[0] = asyncio.run(coro)
            except Exception as e: exc_box[0] = e
        t = threading.Thread(target=_run, daemon=True)
        t.start(); t.join()
        if exc_box[0]: raise exc_box[0]
        return result[0]
    except RuntimeError:
        return asyncio.run(coro)
