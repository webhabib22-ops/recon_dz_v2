#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Async HTTP Engine
================================
محرك الطلبات غير المتزامن مع دعم تقنيات التخفي والمراوغة.
"""

import asyncio
import aiohttp
import socket
import ssl
import random
import time
import re
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import datetime

try:
    import aiohttp
    from aiohttp import ClientTimeout, ClientSession, TCPConnector
except ImportError:
    print("[!] aiohttp غير مثبت. يرجى تثبيته: pip install aiohttp")
    raise


# ─────────────────────────────────────────────────────────────────────
#  ResponseData
# ─────────────────────────────────────────────────────────────────────
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
        lower_name = name.lower()
        for k, v in self.headers.items():
            if k.lower() == lower_name:
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
        cf = self.get_header('cf-ray')
        if cf:
            hints.append("cloudflare")
        akamai = self.get_header('akamai-grn')
        if akamai:
            hints.append("akamai")
        if self.body:
            lower = self.body.lower()
            if 'wp-content' in lower or 'wp-includes' in lower:
                hints.append("cms:wordpress")
            elif 'joomla' in lower:
                hints.append("cms:joomla")
            elif 'drupal' in lower:
                hints.append("cms:drupal")
        return hints

    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300


def _empty_response(url: str, error: str = "") -> ResponseData:
    return ResponseData(
        url=url,
        status=0,
        headers={},
        error=error
    )


def detect_waf_response(resp: ResponseData) -> Optional[str]:
    if resp.status in (403, 406, 429, 503):
        body_lower = resp.body.lower()[:5000]
        hdr_str = " ".join(resp.headers.values()).lower()
        if 'cf-ray' in hdr_str:
            return "Cloudflare"
        if 'x-amzn-requestid' in hdr_str:
            return "AWS WAF"
        if 'incap_ses' in hdr_str or 'x-iinfo' in hdr_str:
            return "Imperva"
        if 'mod_security' in body_lower or 'x-modsecurity' in hdr_str:
            return "ModSecurity"
        if 'sucuri' in body_lower or 'x-sucuri-id' in hdr_str:
            return "Sucuri"
        if 'fortigate' in body_lower:
            return "Fortinet"
        if 'akamai' in body_lower or 'ak_bmsc' in hdr_str:
            return "Akamai"
        if 'blocked' in body_lower or 'security policy' in body_lower:
            return "Generic WAF"
    return None


# ─────────────────────────────────────────────────────────────────────
#  AsyncReconEngine
# ─────────────────────────────────────────────────────────────────────
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
            'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
        ]

    async def initialize(self):
        if self.session is not None:
            return
        self.connector = TCPConnector(
            limit=self.max_concurrent,
            ttl_dns_cache=300,
            ssl=False,
            use_dns_cache=True,
        )
        timeout = ClientTimeout(total=self.timeout, connect=8)
        self.session = ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers=self._get_base_headers()
        )

    async def close(self):
        if self.session:
            await self.session.close()
            self.session = None
        if self.connector:
            await self.connector.close()
            self.connector = None

    def _get_base_headers(self) -> Dict[str, str]:
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,ar;q=0.8',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
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

    async def _apply_stealth_delay(self):
        if self.enable_stealth and not self.internal_mode:
            delay = random.uniform(self.delay_range[0], self.delay_range[1])
            await asyncio.sleep(delay)

    # =============== الطلب العادي مع إعادة محاولة بسيطة ===============
    async def request(self,
                      url: str,
                      method: str = 'GET',
                      headers: Optional[Dict] = None,
                      data: Optional[Any] = None,
                      follow_redirects: bool = True,
                      max_redirects: int = 5) -> ResponseData:
        """
        إرسال طلب HTTP مع محاولة واحدة فقط (بدون إعادة محاولة معقدة لتجنب التأخير).
        """
        if not self.session:
            await self.initialize()

        await self._apply_stealth_delay()

        async with self.semaphore:
            start = time.perf_counter()
            redirect_count = 0
            current_url = url
            final_resp: Optional[ResponseData] = None

            try:
                while True:
                    req_headers = self._get_base_headers()
                    if headers:
                        req_headers.update(headers)

                    if 'Content-Length' in req_headers and data is None:
                        del req_headers['Content-Length']

                    async with self.session.request(
                        method=method,
                        url=current_url,
                        headers=req_headers,
                        data=data,
                        allow_redirects=False,
                        ssl=False,
                    ) as resp:
                        body = await resp.text(encoding='utf-8', errors='ignore')
                        headers_dict = dict(resp.headers)
                        status = resp.status

                        response = ResponseData(
                            url=str(resp.url),
                            status=status,
                            headers=headers_dict,
                            body=body,
                            elapsed=time.perf_counter() - start,
                            protocol=str(resp.version),
                            method=method,
                        )

                        if follow_redirects and status in (301, 302, 303, 307, 308):
                            location = headers_dict.get('location')
                            if location and redirect_count < max_redirects:
                                if location.startswith('http'):
                                    current_url = location
                                else:
                                    parsed = urlparse(current_url)
                                    base = f"{parsed.scheme}://{parsed.netloc}"
                                    current_url = base + location
                                redirect_count += 1
                                continue
                        final_resp = response
                        break

                if final_resp is None:
                    final_resp = _empty_response(url, "No response")
                else:
                    final_resp.redirect_count = redirect_count

                success = 200 <= final_resp.status < 400
                self._update_stats(time.perf_counter() - start, success)
                return final_resp

            except asyncio.TimeoutError:
                self._update_stats(time.perf_counter() - start, False)
                return _empty_response(url, "Timeout")
            except aiohttp.ClientConnectorError as e:
                self._update_stats(time.perf_counter() - start, False)
                return _empty_response(url, f"Connection error: {e}")
            except aiohttp.ClientResponseError as e:
                self._update_stats(time.perf_counter() - start, False)
                return _empty_response(url, f"HTTP error: {e}")
            except Exception as e:
                self._update_stats(time.perf_counter() - start, False)
                return _empty_response(url, f"Unexpected: {e}")

    # =============== الطلب الخام (لـ HTTP Smuggling) ===============
    async def request_raw(self,
                          host: str,
                          port: int,
                          path: str,
                          method: str = 'GET',
                          headers: Optional[Dict] = None,
                          data: Optional[str] = None,
                          use_https: bool = True,
                          timeout: float = 10.0) -> Optional[ResponseData]:
        """
        إرسال طلب HTTP خام عبر TCP (لاختبارات التهريب).
        """
        try:
            reader, writer = await asyncio.open_connection(host, port, ssl=use_https)

            request_line = f"{method} {path} HTTP/1.1\r\n"
            headers_dict = headers or {}
            headers_dict.setdefault('Host', host)
            headers_dict.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            headers_dict.setdefault('Accept', '*/*')
            headers_dict.setdefault('Connection', 'close')

            header_lines = [f"{k}: {v}" for k, v in headers_dict.items()]
            request = request_line + "\r\n".join(header_lines) + "\r\n\r\n"

            if data:
                if isinstance(data, str):
                    data_bytes = data.encode('utf-8')
                else:
                    data_bytes = data
                request_bytes = request.encode('utf-8') + data_bytes
            else:
                request_bytes = request.encode('utf-8')

            start = time.perf_counter()
            writer.write(request_bytes)
            await writer.drain()

            response_data = b''
            try:
                async with asyncio.timeout(timeout):
                    while True:
                        chunk = await reader.read(8192)
                        if not chunk:
                            break
                        response_data += chunk
            except asyncio.TimeoutError:
                pass

            writer.close()
            await writer.wait_closed()
            elapsed = time.perf_counter() - start

            if not response_data:
                return _empty_response(f"{host}:{port}{path}", "Empty response")

            response_text = response_data.decode('utf-8', errors='ignore')
            parts = response_text.split('\r\n\r\n', 1)
            headers_text = parts[0]
            body = parts[1] if len(parts) > 1 else ''

            header_lines = headers_text.split('\r\n')
            status_line = header_lines[0]
            status_code = 0
            if ' ' in status_line:
                try:
                    status_code = int(status_line.split(' ')[1])
                except:
                    pass

            headers_dict = {}
            for line in header_lines[1:]:
                if ': ' in line:
                    k, v = line.split(': ', 1)
                    headers_dict[k.lower()] = v

            return ResponseData(
                url=f"{'https' if use_https else 'http'}://{host}:{port}{path}",
                status=status_code,
                headers=headers_dict,
                body=body,
                elapsed=elapsed,
                method=method,
            )
        except Exception as e:
            return _empty_response(f"{host}:{port}{path}", str(e))

    async def resolve_hostname(self, hostname: str) -> Optional[str]:
        try:
            loop = asyncio.get_event_loop()
            ips = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            if ips:
                return ips[0][4][0]
        except Exception:
            pass
        return None

    async def request_with_fallback(self,
                                     target: str,
                                     www_fallback: bool = True,
                                     path: str = '/') -> Tuple[ResponseData, str, str]:
        """
        محاولة الاتصال بالهدف مع تبديل البروتوكول وإضافة www.
        """
        if not target.startswith('http'):
            target = 'http://' + target

        parsed = urlparse(target)
        host = parsed.netloc or parsed.path.split('/')[0]
        if not host:
            host = target

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

        # فشل كل المحاولات
        return _empty_response(target, "Unreachable after all attempts"), '', host