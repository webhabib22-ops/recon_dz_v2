#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Async HTTP Engine
================================
نسخة مستقرة مع إصلاح DNS لبيئة Termux
"""

import asyncio
import aiohttp
import socket
import random
import time
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
from dataclasses import dataclass

try:
    from aiohttp import ClientTimeout, ClientSession, TCPConnector
    from aiohttp.resolver import AsyncResolver
except ImportError:
    print("[!] aiohttp غير مثبت. يرجى تثبيته: pip install aiohttp")
    raise


@dataclass
class ResponseData:
    url: str
    status: int
    headers: Dict[str, str]
    body: str = ""
    elapsed: float = 0.0
    error: str = ""
    redirect_count: int = 0
    protocol: str = "http"
    method: str = "GET"

    def get_header(self, name: str, default: str = "") -> str:
        lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == lower:
                return v
        return default

    def extract_technology_hints(self) -> List[str]:
        hints = []
        server = self.get_header('server')
        if server:
            hints.append(f"server:{server}")
        powered = self.get_header('x-powered-by')
        if powered:
            hints.append(f"powered_by:{powered}")
        via = self.get_header('via')
        if via:
            hints.append(f"via:{via}")
        if self.body:
            lower = self.body.lower()
            if 'wp-content' in lower or 'wp-includes' in lower:
                hints.append("cms:wordpress")
        return hints

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300


def _empty_response(url: str, error: str = "") -> ResponseData:
    return ResponseData(url=url, status=0, headers={}, error=error)


def detect_waf_response(resp: ResponseData) -> Optional[str]:
    if resp.status in (403, 406, 429, 503):
        body_lower = resp.body.lower()[:5000]
        hdr_str = " ".join(resp.headers.values()).lower()
        if 'cf-ray' in hdr_str:
            return "Cloudflare"
        if 'x-amzn-requestid' in hdr_str:
            return "AWS WAF"
        if 'incap_ses' in hdr_str:
            return "Imperva"
        if 'blocked' in body_lower:
            return "Generic WAF"
    return None


class AsyncReconEngine:
    def __init__(self,
                 max_concurrent: int = 30,
                 enable_stealth: bool = True,
                 internal_mode: bool = False,
                 delay_range: Tuple[float, float] = (0.2, 0.9),
                 timeout: int = 10,
                 user_agent_rotation: bool = True):
        self.max_concurrent = max_concurrent
        self.enable_stealth = enable_stealth
        self.internal_mode = internal_mode
        self.delay_range = delay_range
        self.timeout = timeout
        self.user_agent_rotation = user_agent_rotation
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.session: Optional[ClientSession] = None
        self.connector: Optional[TCPConnector] = None
        self.stats = {
            'requests_total': 0,
            'requests_success': 0,
            'requests_failed': 0,
            'total_time': 0.0,
        }
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        ]

    async def initialize(self):
        if self.session:
            return
        # إعداد resolver صريح لـ DNS (Google DNS)
        resolver = AsyncResolver(nameservers=['8.8.8.8', '8.8.4.4'])
        self.connector = TCPConnector(
            limit=self.max_concurrent,
            ttl_dns_cache=300,
            ssl=False,
            use_dns_cache=True,
            resolver=resolver,  # استخدام resolver مخصص
        )
        timeout = ClientTimeout(total=self.timeout, connect=8)
        self.session = ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers=self._base_headers()
        )

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None
        if self.connector:
            await self.connector.close()
            self.connector = None

    def _base_headers(self) -> Dict[str, str]:
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        if self.user_agent_rotation:
            headers['User-Agent'] = random.choice(self.user_agents)
        else:
            headers['User-Agent'] = self.user_agents[0]
        return headers

    def _update_stats(self, elapsed: float, success: bool):
        self.stats['requests_total'] += 1
        self.stats['total_time'] += elapsed
        if success:
            self.stats['requests_success'] += 1
        else:
            self.stats['requests_failed'] += 1

    def get_stats(self) -> Dict[str, Any]:
        total = self.stats['requests_total']
        return {
            'requests_total': total,
            'requests_success': self.stats['requests_success'],
            'requests_failed': self.stats['requests_failed'],
            'total_time_sec': round(self.stats['total_time'], 2),
            'avg_time_sec': round(self.stats['total_time'] / max(total, 1), 3),
            'success_rate_pct': round(self.stats['requests_success'] / max(total, 1) * 100, 1),
        }

    async def _delay(self):
        if self.enable_stealth and not self.internal_mode:
            await asyncio.sleep(random.uniform(*self.delay_range))

    async def request(self,
                      url: str,
                      method: str = 'GET',
                      headers: Optional[Dict] = None,
                      data: Any = None,
                      follow_redirects: bool = True,
                      max_redirects: int = 5) -> ResponseData:
        if not self.session:
            await self.initialize()

        await self._delay()

        async with self.semaphore:
            start = time.perf_counter()
            redirects = 0
            current = url
            final = None

            try:
                while True:
                    req_headers = self._base_headers()
                    if headers:
                        req_headers.update(headers)

                    async with self.session.request(
                        method=method,
                        url=current,
                        headers=req_headers,
                        data=data,
                        allow_redirects=False,
                        ssl=False,
                    ) as resp:
                        body = await resp.text(encoding='utf-8', errors='ignore')
                        headers_dict = dict(resp.headers)

                        response = ResponseData(
                            url=str(resp.url),
                            status=resp.status,
                            headers=headers_dict,
                            body=body,
                            elapsed=time.perf_counter() - start,
                            protocol=str(resp.version),
                            method=method,
                        )

                        if follow_redirects and resp.status in (301, 302, 303, 307, 308):
                            location = headers_dict.get('location')
                            if location and redirects < max_redirects:
                                if location.startswith('http'):
                                    current = location
                                else:
                                    parsed = urlparse(current)
                                    base = f"{parsed.scheme}://{parsed.netloc}"
                                    current = base + location
                                redirects += 1
                                continue
                        final = response
                        break

                if final is None:
                    final = _empty_response(url, "No response")
                else:
                    final.redirect_count = redirects

                success = 200 <= final.status < 400
                self._update_stats(time.perf_counter() - start, success)
                return final

            except asyncio.TimeoutError:
                self._update_stats(time.perf_counter() - start, False)
                return _empty_response(url, "Timeout")
            except aiohttp.ClientConnectorError as e:
                self._update_stats(time.perf_counter() - start, False)
                return _empty_response(url, f"Connection error: {e}")
            except Exception as e:
                self._update_stats(time.perf_counter() - start, False)
                return _empty_response(url, f"Error: {e}")

    async def request_with_fallback(self,
                                     target: str,
                                     www_fallback: bool = True,
                                     path: str = '/') -> Tuple[ResponseData, str, str]:
        if not target.startswith('http'):
            target = 'http://' + target

        parsed = urlparse(target)
        host = parsed.netloc or parsed.path.split('/')[0]
        if host.startswith('www.'):
            host = host[4:]

        protocols = ['https://', 'http://']
        hosts = [host]
        if www_fallback:
            hosts.append(f'www.{host}')

        for proto in protocols:
            for h in hosts:
                url = f"{proto}{h}{path}"
                resp = await self.request(url, follow_redirects=True)
                if resp.status != 0:
                    return resp, proto, h

        return _empty_response(target, "Unreachable"), '', host

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            ips = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            if ips:
                return ips[0][4][0]
        except:
            pass
        return None