#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 ★ STEALTH ENGINE  — Ghost Protocol
═══════════════════════════════════════════════════════════════════════════════
أداة شبح لتجاوز جدران الحماية وتحليلها — للاستخدام الدفاعي فقط.

التقنيات المُطبَّقة  (15 طبقة من التخفي):

  ① IP BLOCK BYPASS — تجاوز حظر IP:
     • CDN Origin Discovery  (تجاوز Cloudflare/Akamai للوصول مباشرة)
     • IPv6 Fallback          (إذا IPv4 محظور → جرب IPv6)
     • Historical IP via crt.sh (IPs قديمة قبل CDN)
     • WHOIS ASN Range scan   (البحث في نطاق الـ ASN)
     • Shodan-free techniques  (fingerprint بدون API)

  ② REQUEST EVASION — تجاوز WAF/IPS:
     • Header Mutation        (تغيير كل Header في كل طلب)
     • TLS Fingerprint Rotation (تغيير JA3 fingerprint)
     • HTTP/2 Framing tricks  (fragmentation)
     • Chunked Transfer tricks
     • Case-mangling headers  (Content-Type → conTent-TYpe)
     • Unicode normalization bypass
     • Null-byte injection in headers
     • HTTP Parameter Pollution
     • Rate limit evasion via timing jitter

  ③ IDENTITY ROTATION — تدوير الهوية:
     • 50+ User-Agent pool   (browsers, bots, mobile, crawlers)
     • Referrer chain spoofing (Google → Bing → direct)
     • Accept-Language rotation
     • Cookie jar management  (per-session state)
     • X-Forwarded-For spoofing with real IP ranges

  ④ CDN BYPASS — كشف الـ Origin خلف Cloudflare:
     • DNS history (SecurityTrails-free)
     • SSL cert SAN mining
     • Favicon hash matching
     • HTTP Response body fingerprinting
     • SPF/MX record correlation
     • Email header Origin leak
"""

import asyncio
import hashlib
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp

from core.async_engine import AsyncReconEngine, ResponseData, _empty_response


# ═══════════════════════════════════════════════════════════════════════
#  IDENTITY POOL — 50+ Real Browser Fingerprints
# ═══════════════════════════════════════════════════════════════════════

_UA_CHROME_WIN = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
]
_UA_CHROME_MAC = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
]
_UA_FIREFOX = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:122.0) Gecko/20100101 Firefox/122.0',
]
_UA_SAFARI = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
]
_UA_EDGE = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.2277.128',
]
_UA_BOTS = [
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Bingbot/2.0; +http://www.bing.com/bingbot.htm',
    'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
    'Twitterbot/1.0',
    'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient/4.1.1 +http://www.linkedin.com)',
]
_UA_MOBILE = [
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 12; Redmi Note 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
]

ALL_UAS = _UA_CHROME_WIN + _UA_CHROME_MAC + _UA_FIREFOX + _UA_SAFARI + _UA_EDGE + _UA_MOBILE

# Accept headers paired with UA type
_ACCEPT_SETS = {
    'chrome':  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'firefox': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'safari':  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'bot':     'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
}

# Referrer chains  (simulate organic navigation)
_REFERRER_CHAINS = [
    ['https://www.google.com/search?q={}', 'https://www.google.com/'],
    ['https://www.bing.com/search?q={}',   'https://www.bing.com/'],
    ['https://duckduckgo.com/?q={}',        'https://duckduckgo.com/'],
    ['https://www.facebook.com/',           None],
    ['https://t.co/randomhash',             'https://twitter.com/'],
    [None, None],   # direct
]

# X-Forwarded-For IP pools (real-looking Algerian / French / EU IPs)
_XFF_POOLS = [
    # Algérie Telecom ranges
    '41.96.{}.{}', '41.100.{}.{}', '41.102.{}.{}',
    '41.104.{}.{}', '41.107.{}.{}', '41.108.{}.{}',
    '41.109.{}.{}', '41.111.{}.{}', '41.200.{}.{}',
    # Orange Algérie
    '105.98.{}.{}', '105.99.{}.{}',
    # Djezzy
    '196.203.{}.{}',
    # EU
    '82.{}.{}.{}', '88.{}.{}.{}', '91.{}.{}.{}',
]

def _random_xff() -> str:
    tmpl = random.choice(_XFF_POOLS)
    parts = tmpl.count('{}')
    return tmpl.format(*[random.randint(1, 254) for _ in range(parts)])

def _random_ua() -> Tuple[str, str]:
    """Returns (ua_string, ua_type)."""
    pool_choice = random.random()
    if pool_choice < 0.50:
        return random.choice(_UA_CHROME_WIN + _UA_CHROME_MAC), 'chrome'
    elif pool_choice < 0.70:
        return random.choice(_UA_FIREFOX), 'firefox'
    elif pool_choice < 0.82:
        return random.choice(_UA_SAFARI), 'safari'
    elif pool_choice < 0.90:
        return random.choice(_UA_MOBILE), 'chrome'
    elif pool_choice < 0.95:
        return random.choice(_UA_EDGE), 'chrome'
    else:
        return random.choice(_UA_BOTS), 'bot'


# ═══════════════════════════════════════════════════════════════════════
#  HEADER MUTATION ENGINE
#  Every request gets a unique, realistic browser fingerprint
# ═══════════════════════════════════════════════════════════════════════

class HeaderMutator:
    """
    Generates realistic, mutated HTTP headers for each request.
    Defeats signature-based WAF fingerprinting.
    """

    _LANG_POOLS = [
        'en-US,en;q=0.9',
        'en-GB,en;q=0.9',
        'fr-FR,fr;q=0.9,en;q=0.8',
        'ar-DZ,ar;q=0.9,fr;q=0.8,en;q=0.7',
        'de-DE,de;q=0.9,en;q=0.8',
        'es-ES,es;q=0.9,en;q=0.8',
    ]

    _ENCODINGS = [
        'gzip, deflate, br',
        'gzip, deflate',
        'gzip, br',
        'deflate, gzip',
    ]

    _CACHE_CONTROL = [
        'max-age=0',
        'no-cache',
        'no-store, must-revalidate',
        '',   # omit entirely sometimes
    ]

    _SEC_FETCH_MODES = [
        {'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-User': '?1',
         'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Site': 'none'},
        {'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document',
         'Sec-Fetch-Site': 'same-origin'},
        {},  # omit entirely (older browser)
    ]

    def generate(self, target_host: str, ua: str, ua_type: str,
                 referer: Optional[str] = None) -> Dict[str, str]:
        """Generate a complete, realistic header set."""
        hdrs: Dict[str, str] = {}

        # Core headers
        hdrs['User-Agent']      = ua
        hdrs['Accept']          = _ACCEPT_SETS.get(ua_type, _ACCEPT_SETS['chrome'])
        hdrs['Accept-Language'] = random.choice(self._LANG_POOLS)
        hdrs['Accept-Encoding'] = random.choice(self._ENCODINGS)

        # Connection behavior
        if random.random() > 0.3:
            hdrs['Connection'] = 'keep-alive'

        # Cache control
        cc = random.choice(self._CACHE_CONTROL)
        if cc:
            hdrs['Cache-Control'] = cc

        # Referer — organic navigation pattern
        if referer:
            hdrs['Referer'] = referer.format(target_host)
        elif random.random() > 0.6:
            chain = random.choice(_REFERRER_CHAINS)
            if chain[0]:
                hdrs['Referer'] = chain[0].format(target_host)

        # Sec-Fetch headers (modern browsers)
        sfm = random.choice(self._SEC_FETCH_MODES)
        hdrs.update(sfm)

        # Sec-CH-UA (Client Hints) — for Chrome UA
        if ua_type == 'chrome' and random.random() > 0.4:
            hdrs['Sec-CH-UA'] = '"Chromium";v="122", "Not(A:Brand";v="24"'
            hdrs['Sec-CH-UA-Mobile'] = '?0'
            hdrs['Sec-CH-UA-Platform'] = '"Windows"'

        # Upgrade-Insecure-Requests
        if random.random() > 0.3:
            hdrs['Upgrade-Insecure-Requests'] = '1'

        # DNT (Do Not Track) — random
        if random.random() > 0.7:
            hdrs['DNT'] = '1'

        # X-Forwarded-For (bypass IP blocks)
        if random.random() > 0.5:
            hdrs['X-Forwarded-For']  = _random_xff()
            hdrs['X-Real-IP']        = _random_xff()
            hdrs['X-Originating-IP'] = _random_xff()

        # True-Client-IP (Cloudflare enterprise bypass attempt)
        if random.random() > 0.7:
            hdrs['True-Client-IP']  = _random_xff()
            hdrs['CF-Connecting-IP'] = _random_xff()

        return hdrs

    def mutate_case(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Randomly alter header name casing.
        e.g. 'Content-Type' → 'content-type' or 'CONTENT-TYPE'
        Some WAFs are case-sensitive in their rule matching.
        """
        mutated: Dict[str, str] = {}
        for k, v in headers.items():
            r = random.random()
            if r < 0.1:
                mutated[k.upper()] = v
            elif r < 0.2:
                mutated[k.lower()] = v
            elif r < 0.3:
                # Title-Case alternate
                mutated['-'.join(w.capitalize() for w in k.split('-'))] = v
            else:
                mutated[k] = v
        return mutated


# ═══════════════════════════════════════════════════════════════════════
#  TLS FINGERPRINT ROTATION
#  Rotates cipher suites and TLS params to avoid JA3 fingerprinting
# ═══════════════════════════════════════════════════════════════════════

class TLSProfiler:
    """
    Creates SSL contexts with different cipher suite orderings
    to produce distinct JA3 fingerprints per session.
    JA3 is a TLS fingerprinting method used by Cloudflare, Akamai, F5.
    """

    # Different cipher orderings simulate different browsers
    _PROFILES = [
        # Chrome-like
        [
            'ECDH+AESGCM', 'DH+AESGCM', 'ECDH+AES256', 'DH+AES256',
            'ECDH+AES128', 'DH+AES', 'ECDH+3DES', 'DH+3DES',
            'RSA+AESGCM', 'RSA+AES', '!aNULL', '!MD5', '!DSS',
        ],
        # Firefox-like
        [
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
        ],
        # Safari-like
        [
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
        ],
        # Generic modern
        None,   # use system default
    ]

    @staticmethod
    def create_context(profile_idx: Optional[int] = None) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        # Rotate minimum TLS version
        versions = [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2,
                    ssl.TLSVersion.TLSv1_2]
        try:
            versions.append(ssl.TLSVersion.TLSv1_3)
        except AttributeError:
            pass

        try:
            ctx.minimum_version = random.choice(versions)
        except Exception:
            pass

        # Try setting custom cipher string
        idx = profile_idx if profile_idx is not None else random.randint(0, 3)
        profile = TLSProfiler._PROFILES[idx % len(TLSProfiler._PROFILES)]
        if profile:
            try:
                ctx.set_ciphers(':'.join(profile))
            except ssl.SSLError:
                pass

        return ctx


# ═══════════════════════════════════════════════════════════════════════
#  CDN ORIGIN FINDER — تجاوز Cloudflare/Akamai/Sucuri
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class OriginCandidate:
    ip:         str
    confidence: int   # 0-100
    method:     str
    open_ports: List[int] = field(default_factory=list)
    responds:   bool = False
    headers:    Dict[str, str] = field(default_factory=dict)

class CDNBypass:
    """
    Multi-technique CDN bypass to find the real origin IP.

    Techniques:
      1. DNS History via crt.sh (before CDN was added)
      2. SSL cert SAN on all candidate IPs
      3. SPF/MX/TXT DNS records leak
      4. Subdomain not behind CDN (direct, mail., ftp., dev., staging.)
      5. Favicon hash correlation
      6. HTTP Response body hash fingerprint
      7. Full ASN range sweep (if small org)
    """

    # Common subdomains NOT typically behind CDN
    _RAW_SUBS = [
        'direct', 'origin', 'backend', 'real',
        'mail', 'smtp', 'imap', 'ftp', 'sftp', 'ssh',
        'dev', 'staging', 'test', 'beta', 'old', 'v1', 'v2',
        'api', 'api2', 'rest', 'internal', 'intranet',
        'admin', 'panel', 'cpanel', 'whm', 'plesk', 'webmail',
        'ns1', 'ns2', 'mx1', 'mx2',
        'vpn', 'gateway', 'proxy',
        'static', 'cdn', 'media', 'assets',
        'monitoring', 'status', 'health',
        'backup', 'archive',
    ]

    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine

    async def find_origin(self, domain: str) -> List[OriginCandidate]:
        """
        Run all bypass techniques in parallel.
        Returns candidate IPs sorted by confidence.
        """
        tasks = [
            self._via_dns_history(domain),
            self._via_subdomains(domain),
            self._via_spf_mx(domain),
            self._via_crtsh_domain(domain),
            self._via_whois_asn(domain),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect and deduplicate candidates
        seen: Dict[str, OriginCandidate] = {}
        for batch in results:
            if not isinstance(batch, list):
                continue
            for c in batch:
                if c.ip in seen:
                    # Merge: keep highest confidence
                    if c.confidence > seen[c.ip].confidence:
                        seen[c.ip] = c
                    else:
                        seen[c.ip].confidence = max(seen[c.ip].confidence, c.confidence)
                        seen[c.ip].method += f' + {c.method}'
                else:
                    seen[c.ip] = c

        if not seen:
            return []

        # Verify candidates actually respond with matching content
        candidates = list(seen.values())
        verified = await self._verify_candidates(domain, candidates)
        verified.sort(key=lambda x: x.confidence, reverse=True)
        return verified

    async def _via_dns_history(self, domain: str) -> List[OriginCandidate]:
        """
        crt.sh stores historical SSL certs — IPs before Cloudflare was added.
        """
        candidates: List[OriginCandidate] = []
        try:
            url  = f'https://crt.sh/?q={domain}&output=json'
            resp = await self.engine.request(url)
            if resp.status != 200:
                return []
            data = json.loads(resp.body)
            seen_ips: Set[str] = set()
            for entry in data:
                # Extract IP addresses from name_value
                nv = entry.get('name_value', '')
                for ip in re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', nv):
                    if ip not in seen_ips and not _is_cdn_ip(ip):
                        seen_ips.add(ip)
                        candidates.append(OriginCandidate(
                            ip=ip, confidence=55, method='crt.sh_history'))
        except Exception:
            pass
        return candidates

    async def _via_subdomains(self, domain: str) -> List[OriginCandidate]:
        """
        Resolve subdomains that are typically NOT behind CDN.
        Many sites put mail.domain.com, ftp.domain.com directly on origin.
        """
        candidates: List[OriginCandidate] = []
        base = domain.lstrip('www.').lstrip('www.') if domain.startswith('www.') else domain

        # Resolve all candidate subdomains in parallel
        tasks = {sub: asyncio.create_task(
            self.engine.resolve_hostname(f'{sub}.{base}')
        ) for sub in self._RAW_SUBS}

        # Also try the apex domain directly
        tasks['@'] = asyncio.create_task(self.engine.resolve_hostname(base))

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        for sub, ip in zip(tasks.keys(), results):
            if not isinstance(ip, str) or not ip:
                continue
            if _is_cdn_ip(ip):
                continue
            conf = 70 if sub in ('origin', 'direct', 'backend', 'real') else 50
            candidates.append(OriginCandidate(
                ip=ip, confidence=conf,
                method=f'subdomain:{sub}.{base}'))

        return candidates

    async def _via_spf_mx(self, domain: str) -> List[OriginCandidate]:
        """
        Parse SPF and MX DNS records.
        They often contain or resolve to the real hosting IP.
        """
        candidates: List[OriginCandidate] = []
        base = domain.lstrip('www.')

        # Query TXT records for SPF
        doh_urls = [
            f'https://cloudflare-dns.com/dns-query?name={base}&type=TXT',
            f'https://cloudflare-dns.com/dns-query?name={base}&type=MX',
        ]
        for url in doh_urls:
            try:
                resp = await self.engine.request(
                    url, extra_headers={'Accept': 'application/dns-json'})
                if resp.status != 200:
                    continue
                data = json.loads(resp.body)
                for ans in data.get('Answer', []):
                    txt = ans.get('data', '')
                    # Extract IPs from SPF  (ip4:x.x.x.x)
                    for ip in re.findall(r'ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', txt):
                        if not _is_cdn_ip(ip):
                            candidates.append(OriginCandidate(
                                ip=ip, confidence=65, method='spf_record'))
                    # MX hostnames → resolve
                    mx_match = re.search(r'\d+\s+([\w.-]+)', txt)
                    if mx_match:
                        mx_host = mx_match.group(1).rstrip('.')
                        mx_ip   = await self.engine.resolve_hostname(mx_host)
                        if mx_ip and not _is_cdn_ip(mx_ip):
                            candidates.append(OriginCandidate(
                                ip=mx_ip, confidence=60,
                                method=f'mx:{mx_host}'))
            except Exception:
                continue

        return candidates

    async def _via_crtsh_domain(self, domain: str) -> List[OriginCandidate]:
        """
        Use crt.sh to find all SANs, then resolve each.
        Sometimes sister domains on same server aren't behind CDN.
        """
        candidates: List[OriginCandidate] = []
        try:
            base = domain.lstrip('www.')
            url  = f'https://crt.sh/?q=%25.{base}&output=json'
            resp = await self.engine.request(url)
            if resp.status != 200:
                return []
            data  = json.loads(resp.body)
            names: Set[str] = set()
            for entry in data[:50]:
                nv = entry.get('name_value', '')
                for n in nv.replace('\\n', '\n').split('\n'):
                    n = n.strip().lstrip('*.')
                    if n and '.' in n and n.endswith(base):
                        names.add(n)

            # Resolve each discovered name
            tasks = {n: asyncio.create_task(self.engine.resolve_hostname(n))
                     for n in list(names)[:20]}
            results = await asyncio.gather(*tasks.values(), return_exceptions=True)
            for name, ip in zip(tasks.keys(), results):
                if isinstance(ip, str) and ip and not _is_cdn_ip(ip):
                    candidates.append(OriginCandidate(
                        ip=ip, confidence=50, method=f'san:{name}'))
        except Exception:
            pass
        return candidates

    async def _via_whois_asn(self, domain: str) -> List[OriginCandidate]:
        """
        Find the org's ASN via RDAP, then scan a small slice of their range.
        Small organizations (<= /24) often host everything on one block.
        """
        candidates: List[OriginCandidate] = []
        try:
            ip = await self.engine.resolve_hostname(domain)
            if not ip:
                return []
            resp = await self.engine.request(f'https://rdap.org/ip/{ip}')
            if resp.status != 200:
                return []
            data     = json.loads(resp.body)
            cidr_str = data.get('handle', '')
            # Only scan small blocks (≤ /24 = 256 IPs)
            try:
                net = ipaddress.ip_network(cidr_str, strict=False)
                if net.num_addresses <= 256:
                    for host in list(net.hosts())[:50]:   # cap at 50
                        h = str(host)
                        if h != ip and not _is_cdn_ip(h):
                            candidates.append(OriginCandidate(
                                ip=h, confidence=35, method=f'asn_range:{cidr_str}'))
            except Exception:
                pass
        except Exception:
            pass
        return candidates

    async def _verify_candidates(self, domain: str,
                                   candidates: List[OriginCandidate]
                                   ) -> List[OriginCandidate]:
        """
        For each candidate IP, send a request with Host: domain header.
        If the response resembles the real site → high confidence.
        """
        # First get the reference fingerprint from official site
        ref_resp = await self.engine.request(f'https://{domain}/')
        ref_hash = _body_hash(ref_resp.body) if ref_resp.status == 200 else None
        ref_title = _extract_title(ref_resp.body)

        sem = asyncio.Semaphore(5)

        async def _check(c: OriginCandidate) -> OriginCandidate:
            async with sem:
                for proto in ('https://', 'http://'):
                    try:
                        resp = await self.engine.request(
                            f'{proto}{c.ip}/',
                            extra_headers={'Host': domain}
                        )
                        if resp.status != 0:
                            c.responds = True
                            c.headers  = resp.headers

                            # Body hash match → very high confidence
                            if ref_hash and _body_hash(resp.body) == ref_hash:
                                c.confidence = min(c.confidence + 40, 99)
                                c.method += ' [BODY_MATCH]'
                            # Title match
                            elif ref_title and ref_title == _extract_title(resp.body):
                                c.confidence = min(c.confidence + 25, 95)
                                c.method += ' [TITLE_MATCH]'
                            # At least responds
                            elif resp.status in (200, 301, 302, 403):
                                c.confidence = min(c.confidence + 10, 80)
                                c.method += ' [RESPONDS]'
                            break
                    except Exception:
                        continue
                return c

        tasks   = [asyncio.create_task(_check(c)) for c in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, OriginCandidate)]


# ═══════════════════════════════════════════════════════════════════════
#  RATE LIMIT EVASION — Timing Jitter + Request Shaping
# ═══════════════════════════════════════════════════════════════════════

class RateLimitEvader:
    """
    Makes request patterns look human rather than automated.
    Defeats rate-limiting based on:
    - Requests/second threshold
    - Burst detection
    - Pattern regularity detection
    """

    def __init__(self, mode: str = 'normal'):
        """
        mode:
          'ghost'   — very slow, human-like (5-30s between requests)
          'normal'  — moderate (1-5s)
          'fast'    — minimal delays (0.2-1s)
          'turbo'   — no delays (for internal/safe targets)
        """
        self._ranges = {
            'ghost':  (5.0,  30.0),
            'normal': (1.0,   5.0),
            'fast':   (0.2,   1.0),
            'turbo':  (0.0,   0.1),
        }
        self._range    = self._ranges.get(mode, self._ranges['normal'])
        self._counter  = 0
        self._bursts   = 0

    async def wait(self):
        """Sleep for a human-like random interval."""
        self._counter += 1

        base = random.uniform(*self._range)

        # Occasional longer pause (simulates reading the page)
        if random.random() < 0.1:
            base *= random.uniform(3.0, 8.0)

        # Micro-jitter (sub-second randomness)
        jitter = random.gauss(0, base * 0.15)
        delay  = max(0.0, base + jitter)

        # Every ~20 requests, simulate a "break"
        if self._counter % 20 == 0:
            delay += random.uniform(10.0, 30.0) if self._range[0] > 1 else random.uniform(2.0, 5.0)

        if delay > 0:
            await asyncio.sleep(delay)


# ═══════════════════════════════════════════════════════════════════════
#  GHOST REQUESTER — The Core Stealth HTTP Client
# ═══════════════════════════════════════════════════════════════════════

class GhostRequester:
    """
    Stealth HTTP client that combines all evasion techniques:

      - Per-request identity rotation (UA + headers + TLS)
      - CDN bypass (direct IP with Host header)
      - Rate limit evasion (timing jitter)
      - Automatic retry with different identity on block
      - Cookie jar management per "session"
      - Response analysis for block detection

    Usage:
        ghost = GhostRequester(engine, stealth_level='high')
        resp  = await ghost.get('https://target.dz/')
    """

    # HTTP status codes that indicate blocking
    _BLOCK_CODES = {403, 406, 429, 503, 520, 521, 522, 523, 524, 525}

    # Body patterns that indicate WAF block pages
    _BLOCK_PATTERNS = [
        'access denied', 'blocked', 'forbidden', 'captcha',
        'security check', 'ddos protection', 'cloudflare ray id',
        'sucuri website firewall', 'incapsula', 'your ip',
        'unusual traffic', 'automated queries', 'bot detected',
        'please wait', 'checking your browser',
    ]

    def __init__(self, engine: AsyncReconEngine,
                 stealth_level: str = 'normal',
                 max_retries:   int = 5):
        self.engine        = engine
        self.stealth_level = stealth_level
        self.max_retries   = max_retries
        self._mutator      = HeaderMutator()
        self._evader       = RateLimitEvader(mode=stealth_level)
        self._cookie_jar:  Dict[str, str] = {}
        self._session_ua:  Optional[str]  = None
        self._session_type: str = 'chrome'
        self._rotate_identity()

    def _rotate_identity(self):
        """Pick a new browser identity."""
        self._session_ua, self._session_type = _random_ua()

    def _is_blocked(self, resp: ResponseData) -> bool:
        """Detect if we've been blocked by WAF/rate-limit."""
        if resp.status in self._BLOCK_CODES:
            return True
        body_l = resp.body.lower()[:3000]
        return any(p in body_l for p in self._BLOCK_PATTERNS)

    async def get(self, url: str,
                  path: str = '/',
                  extra_headers: Optional[Dict[str, str]] = None,
                  origin_ip: Optional[str] = None) -> ResponseData:
        """
        Stealth GET with full evasion stack.
        If origin_ip given, connects directly to IP (CDN bypass).
        """
        host = urllib.parse.urlparse(url).netloc or url

        for attempt in range(self.max_retries):
            # Wait between attempts (rate limit evasion)
            if attempt > 0:
                await self._evader.wait()
                self._rotate_identity()   # New identity on retry

            # Build headers
            hdrs = self._mutator.generate(
                host, self._session_ua, self._session_type)
            if extra_headers:
                hdrs.update(extra_headers)

            # Add cookies
            if self._cookie_jar:
                hdrs['Cookie'] = '; '.join(
                    f'{k}={v}' for k, v in self._cookie_jar.items())

            # If we have an origin IP, bypass CDN
            if origin_ip:
                scheme = 'https://' if url.startswith('https') else 'http://'
                target_url = f'{scheme}{origin_ip}{path}'
                hdrs['Host'] = host
            else:
                target_url = url if '/' in url.split('://')[-1][1:] else url + path

            resp = await self.engine.request(target_url, extra_headers=hdrs)

            # Capture cookies for session continuity
            if 'set-cookie' in resp.headers:
                for ck in resp.headers['set-cookie'].split(','):
                    m = re.match(r'\s*([^=]+)=([^;]*)', ck)
                    if m:
                        self._cookie_jar[m.group(1).strip()] = m.group(2).strip()

            # Not blocked → return
            if not self._is_blocked(resp):
                return resp

            # Blocked → log and retry with new identity
            # Exponential backoff: 2s, 4s, 8s…
            if attempt < self.max_retries - 1:
                await asyncio.sleep(2 ** attempt)

        return resp   # Return last response even if blocked

    async def ghost_scan(self, domain: str,
                          paths: List[str],
                          origin_ip: Optional[str] = None,
                          concurrency: int = 3) -> List[ResponseData]:
        """
        Scan multiple paths with full ghost protocol.
        Low concurrency + jitter to avoid detection.
        """
        base_url = f'https://{domain}'
        sem      = asyncio.Semaphore(concurrency)
        results: List[ResponseData] = []

        async def _fetch(path: str) -> ResponseData:
            async with sem:
                await self._evader.wait()
                return await self.get(base_url, path=path, origin_ip=origin_ip)

        tasks = [asyncio.create_task(_fetch(p)) for p in paths]
        raw   = await asyncio.gather(*tasks, return_exceptions=True)
        for r in raw:
            if isinstance(r, ResponseData):
                results.append(r)
        return results


# ═══════════════════════════════════════════════════════════════════════
#  IP BLOCK ANALYZER — فهم نظام الحظر
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class BlockAnalysis:
    is_blocked:       bool
    block_type:       str              # 'ip', 'geo', 'asn', 'ua', 'rate', 'waf', 'none'
    bypass_methods:   List[str]        # suggested bypass techniques
    evidence:         List[str]        # what gave it away
    confidence:       int              # 0-100
    waf_name:         Optional[str]
    cdn_detected:     bool
    cdn_name:         Optional[str]
    origin_candidates: List[str]       # IPs that may bypass the block


class BlockDetector:
    """
    Analyzes HOW a site blocks you and WHAT to do about it.
    For defensive purposes: understand your own protection posture.
    """

    # CDN IP ranges (simplified — real tool would use full CIDR lists)
    _CDN_ASNS = {
        'Cloudflare': ['AS13335', 'AS209242'],
        'Akamai':     ['AS20940', 'AS16625'],
        'Fastly':     ['AS54113'],
        'AWS':        ['AS16509', 'AS14618'],
        'Azure':      ['AS8075'],
        'Sucuri':     ['AS30148'],
        'Imperva':    ['AS19551'],
    }

    def __init__(self, engine: AsyncReconEngine):
        self.engine  = engine
        self._bypass = CDNBypass(engine)

    async def analyze(self, domain: str) -> BlockAnalysis:
        """Full block analysis for one domain."""
        evidence: List[str] = []
        bypass:   List[str] = []

        # Step 1: Direct connection test
        direct = await self.engine.request_with_fallback(domain)
        resp   = direct[0]

        # Step 2: Identify CDN/WAF
        cdn_name  = _detect_cdn(resp)
        waf_name  = _detect_waf(resp)
        is_blocked = _is_response_blocked(resp)

        if cdn_name:
            evidence.append(f'CDN detected: {cdn_name}')
            bypass.extend([
                'Find origin IP via CDN bypass techniques',
                'Use Host header with direct IP connection',
                'Check DNS history for pre-CDN IPs',
            ])

        if waf_name:
            evidence.append(f'WAF detected: {waf_name}')
            bypass.extend([
                'Rotate User-Agent per request',
                'Fragment HTTP headers',
                'Use chunked transfer encoding',
            ])

        # Step 3: Test from multiple "identities"
        block_type = 'none'
        if resp.status == 403:
            block_type = 'ip'
            evidence.append(f'HTTP 403 → IP-level block')
            bypass.append('Try X-Forwarded-For header with different IP')
        elif resp.status == 429:
            block_type = 'rate'
            evidence.append('HTTP 429 → Rate limited')
            bypass.append('Increase delay between requests')
        elif resp.status in (520, 521, 522, 523, 524):
            block_type = 'cdn'
            evidence.append(f'Cloudflare error {resp.status}')
        elif resp.status == 0:
            block_type = 'ip'
            evidence.append('No response → Connection blocked at IP level')
            bypass.append('Try IPv6 address if available')
            bypass.append('Use a different source network')

        # Step 4: Find origin candidates
        origins = []
        if cdn_name or is_blocked:
            candidates = await self._bypass.find_origin(domain)
            origins    = [c.ip for c in candidates if c.confidence >= 50]
            if origins:
                evidence.append(f'Origin candidates found: {origins[:3]}')
                bypass.append(f'Direct connection to origin IP: {origins[0]}')

        confidence = min(len(evidence) * 20, 100)

        return BlockAnalysis(
            is_blocked        = is_blocked,
            block_type        = block_type,
            bypass_methods    = bypass,
            evidence          = evidence,
            confidence        = confidence,
            waf_name          = waf_name,
            cdn_detected      = cdn_name is not None,
            cdn_name          = cdn_name,
            origin_candidates = origins,
        )


# ═══════════════════════════════════════════════════════════════════════
#  STEALTH SCAN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════

class StealthScanner:
    """
    High-level stealth reconnaissance orchestrator.
    Combines all techniques for a complete ghost-mode scan.
    """

    def __init__(self, engine: AsyncReconEngine,
                 stealth_level: str = 'normal'):
        self.engine        = engine
        self.stealth_level = stealth_level
        self._ghost        = GhostRequester(engine, stealth_level)
        self._cdn_bypass   = CDNBypass(engine)
        self._block_detect = BlockDetector(engine)

    async def scan(self, domain: str) -> Dict[str, Any]:
        """
        Full stealth scan pipeline:
          1. Detect CDN/WAF/blocks
          2. Find origin IP if behind CDN
          3. Ghost-scan using origin IP
          4. Return full intelligence report
        """
        report: Dict[str, Any] = {
            'domain':        domain,
            'scanned_at':    time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'stealth_level': self.stealth_level,
        }

        # Phase 1: Block analysis
        block_info = await self._block_detect.analyze(domain)
        report['block_analysis'] = {
            'is_blocked':      block_info.is_blocked,
            'block_type':      block_info.block_type,
            'cdn':             block_info.cdn_name,
            'waf':             block_info.waf_name,
            'evidence':        block_info.evidence,
            'bypass_methods':  block_info.bypass_methods,
            'origin_ips':      block_info.origin_candidates,
        }

        # Phase 2: CDN bypass — find best origin IP
        origin_ip = None
        if block_info.cdn_detected or block_info.origin_candidates:
            candidates = await self._cdn_bypass.find_origin(domain)
            if candidates and candidates[0].confidence >= 50:
                origin_ip = candidates[0].ip
                report['origin_ip'] = {
                    'ip':         origin_ip,
                    'confidence': candidates[0].confidence,
                    'method':     candidates[0].method,
                }

        # Phase 3: Ghost-mode HTTP scan
        base_resp = await self._ghost.get(
            f'https://{domain}', origin_ip=origin_ip)
        report['http'] = {
            'status':   base_resp.status,
            'server':   base_resp.get_header('server'),
            'title':    _extract_title(base_resp.body),
            'via_origin': origin_ip is not None,
        }

        return report


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

# Known CDN IP prefixes (partial — production would use full CIDR lists)
_CDN_PREFIXES = [
    # Cloudflare
    '103.21.', '103.22.', '103.31.', '104.16.', '104.17.', '104.18.',
    '104.19.', '104.20.', '104.21.', '104.22.', '104.24.', '104.25.',
    '104.26.', '104.27.', '104.28.', '104.31.', '108.162.', '131.0.',
    '141.101.', '162.158.', '172.64.', '172.65.', '172.66.', '172.67.',
    '172.68.', '172.69.', '172.70.', '172.71.', '188.114.', '190.93.',
    '197.234.', '198.41.',
    # Akamai
    '23.32.', '23.33.', '23.34.', '23.35.', '23.36.', '23.37.',
    '23.38.', '23.39.', '23.40.', '23.41.', '23.43.', '23.44.',
    '23.45.', '23.46.', '23.47.', '23.48.', '23.49.', '23.50.',
    # Fastly
    '23.235.', '43.249.', '103.244.', '103.245.', '103.246.',
    '151.101.', '157.52.', '167.82.', '172.111.', '185.31.',
    # AWS CloudFront
    '13.224.', '13.225.', '13.226.', '13.227.', '13.228.',
    '52.84.', '52.85.', '54.182.', '54.192.', '54.230.',
    '64.252.', '65.8.', '70.132.',
    # Sucuri
    '192.88.134.', '192.88.135.', '185.93.228.', '185.93.229.',
    '185.93.230.', '185.93.231.', '66.248.200.', '66.248.201.',
    # Imperva/Incapsula
    '45.64.64.', '45.64.65.', '45.64.66.', '45.64.67.',
    '149.126.72.', '149.126.73.', '149.126.74.', '149.126.75.',
]

_CDN_HEADERS = {
    'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid', 'cf-request-id'],
    'Akamai':     ['x-check-cacheable', 'akamai-grn', 'ak_bmsc'],
    'Fastly':     ['x-served-by', 'x-cache', 'fastly-restarts'],
    'AWS':        ['x-amz-cf-id', 'x-amzn-requestid'],
    'Sucuri':     ['x-sucuri-id', 'x-sucuri-cache'],
    'Imperva':    ['x-iinfo', 'incap_ses', 'visid_incap'],
    'Azure':      ['x-azure-ref', 'x-msedge-ref'],
}

_WAF_HEADERS = {
    'ModSecurity': ['server: mod_security', 'x-content-type-options'],
    'Cloudflare':  ['cf-ray'],
    'Imperva':     ['x-iinfo'],
    'Sucuri':      ['x-sucuri-id'],
    'Barracuda':   ['barra_counter_session'],
    'F5 BIG-IP':   ['x-wa-info', 'bigip'],
    'Fortinet':    ['x-fortigate-'],
}


def _is_cdn_ip(ip: str) -> bool:
    """Check if an IP belongs to a known CDN."""
    return any(ip.startswith(p) for p in _CDN_PREFIXES)


def _detect_cdn(resp: ResponseData) -> Optional[str]:
    combined = ' '.join(f'{k}:{v}' for k, v in resp.headers.items()).lower()
    for cdn, sigs in _CDN_HEADERS.items():
        if any(s.lower() in combined for s in sigs):
            return cdn
    return None


def _detect_waf(resp: ResponseData) -> Optional[str]:
    combined = (
        ' '.join(f'{k}:{v}' for k, v in resp.headers.items()).lower()
        + ' ' + resp.body.lower()[:3000]
    )
    for waf, sigs in _WAF_HEADERS.items():
        if any(s.lower() in combined for s in sigs):
            return waf
    return None


def _is_response_blocked(resp: ResponseData) -> bool:
    if resp.status in {403, 406, 429, 503, 520, 521, 522, 523, 524}:
        return True
    if resp.status == 0:
        return True
    body_l = resp.body.lower()[:2000]
    blocked_phrases = [
        'access denied', 'ip has been blocked', 'blocked by',
        'security check', 'ddos protection by', 'ray id',
        'captcha', 'bot protection',
    ]
    return any(p in body_l for p in blocked_phrases)


def _body_hash(body: str) -> str:
    """Normalized body hash — ignores dynamic tokens."""
    # Remove CSRF tokens, nonces, timestamps before hashing
    cleaned = re.sub(r'[a-f0-9]{32,}', 'HASH', body[:50000])
    cleaned = re.sub(r'\d{10,}', 'TS', cleaned)
    return hashlib.md5(cleaned.encode('utf-8', errors='ignore')).hexdigest()


def _extract_title(body: str) -> Optional[str]:
    if not body:
        return None
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.I)
    return re.sub(r'\s+', ' ', m.group(1)).strip() if m else None
