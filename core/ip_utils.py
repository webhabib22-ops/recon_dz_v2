#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - IP Utilities
Improved: expanded CDN ranges, smarter origin IP discovery,
          added private IP detection, improved type hints
"""

import ipaddress
from typing import Optional, Tuple, Dict, List

from core.async_engine import AsyncReconEngine


# ─────────────────────── CDN Network Definitions ──────────────────────

CDN_NETWORKS: Dict[str, List[str]] = {
    'Cloudflare': [
        '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '104.16.0.0/13',   '104.24.0.0/14',   '108.162.192.0/18',
        '131.0.72.0/22',   '141.101.64.0/18',  '162.158.0.0/15',
        '172.64.0.0/13',   '173.245.48.0/20',  '188.114.96.0/20',
        '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17',
    ],
    'Akamai': [
        '2.16.0.0/13',    '23.0.0.0/12',     '23.192.0.0/11',
        '23.32.0.0/11',   '23.64.0.0/14',    '104.64.0.0/10',
        '184.24.0.0/13',  '184.84.0.0/14',
    ],
    'Imperva/Incapsula': [
        '199.83.128.0/21', '198.143.32.0/19', '149.126.72.0/21',
        '103.28.248.0/22', '45.64.64.0/22',   '192.230.64.0/18',
    ],
    'Sucuri': [
        '66.248.200.0/22', '185.93.228.0/22',
        '192.88.134.0/23', '192.88.135.0/24',
    ],
    'Fastly': [
        '23.235.32.0/20',  '43.249.72.0/22',  '103.244.50.0/24',
        '103.245.222.0/23','103.245.224.0/24', '104.156.80.0/20',
        '151.101.0.0/16',  '157.52.64.0/18',  '167.82.0.0/17',
        '167.82.128.0/20', '172.111.64.0/18',  '185.31.16.0/22',
    ],
    'AWS CloudFront': [
        '13.32.0.0/15', '13.35.0.0/16', '52.46.0.0/18',
        '54.182.0.0/16', '54.192.0.0/12',
    ],
    'Azure CDN': [
        '13.107.0.0/17',   '23.96.0.0/13',
        '40.64.0.0/10',    '104.208.0.0/13',
    ],
}

# Pre-compiled network objects for fast lookup
_COMPILED_CDN: List[Tuple[ipaddress.IPv4Network, str]] = []
for _cdn_name, _cidrs in CDN_NETWORKS.items():
    for _cidr in _cidrs:
        try:
            _COMPILED_CDN.append(
                (ipaddress.ip_network(_cidr, strict=False), _cdn_name)
            )
        except ValueError:
            pass


# ─────────────────────── Public API ───────────────────────────────────

def is_cdn_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """
    Check whether an IP address belongs to a known CDN.
    Returns (True, cdn_name) or (False, None).
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for net, cdn_name in _COMPILED_CDN:
            if ip_obj in net:
                return True, cdn_name
    except (ValueError, TypeError):
        pass
    return False, None


def is_private_ip(ip: str) -> bool:
    """Return True if ip is RFC-1918, loopback, or link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except (ValueError, TypeError):
        return False


async def extract_real_ip(domain: str,
                           engine: AsyncReconEngine) -> Optional[str]:
    """
    Attempt to discover the true origin IP behind a CDN.

    Strategy:
    1. Resolve the domain with DoH.
    2. If the IP belongs to a CDN, probe common bypass subdomains.
    3. Try common HTTP headers that may leak origin IP.
    4. Return the resolved IP even if CDN (so callers always get something).
    """
    # Step 1: DoH resolution
    ip = await engine.resolve_hostname(domain)
    if not ip:
        return None

    # Step 2: Not a CDN → real IP
    is_cdn, cdn_name = is_cdn_ip(ip)
    if not is_cdn:
        return ip

    # Step 3: Try bypass subdomains
    bypass_subs = [
        f'direct.{domain}',   f'origin.{domain}',
        f'origin-www.{domain}', f'real.{domain}',
        f'backend.{domain}',  f'server.{domain}',
    ]
    for sub in bypass_subs:
        try:
            sub_ip = await engine.resolve_hostname(sub)
            if sub_ip and not is_cdn_ip(sub_ip)[0] and not is_private_ip(sub_ip):
                return sub_ip
        except Exception:
            continue

    # Step 4: Fetch the main page and check headers that might leak origin IP
    import re
    resp = await engine.request(f'https://{domain}/')
    if resp.status != 0:
        for hdr_name in ('x-real-ip', 'x-origin-ip', 'x-forwarded-server',
                          'x-backend-server', 'x-host'):
            hdr_val = resp.get_header(hdr_name)
            if hdr_val:
                m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', hdr_val)
                if m:
                    candidate = m.group(1)
                    if not is_private_ip(candidate) and not is_cdn_ip(candidate)[0]:
                        return candidate

    # Step 5: Return CDN IP as fallback (better than nothing)
    return ip
