# -*- coding: utf-8 -*-
"""
ip_utils.py - Utility functions for IP address handling
Part of RECON-DZ v2
"""

import socket
import ipaddress
from typing import Optional, Tuple
from core.async_engine import AsyncReconEngine

# Known CDN networks (manually maintained)
CDN_NETWORKS = {
    'Cloudflare': [
        '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '104.16.0.0/13', '104.24.0.0/14', '108.162.192.0/18',
        '131.0.72.0/22', '141.101.64.0/18', '162.158.0.0/15',
        '172.64.0.0/13', '173.245.48.0/20', '188.114.96.0/20',
        '190.93.240.0/20', '197.234.240.0/22', '198.41.128.0/17'
    ],
    'Akamai': [
        '104.64.0.0/10', '184.24.0.0/13', '184.84.0.0/14',
        '23.0.0.0/12', '2.16.0.0/13'
    ],
    'Incapsula': [
        '199.83.128.0/21', '198.143.32.0/19', '149.126.72.0/21',
        '103.28.248.0/22', '45.64.64.0/22'
    ],
    'Sucuri': [
        '192.88.134.0/23', '185.93.228.0/22', '66.248.200.0/22'
    ]
}


def is_cdn_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """
    Check if an IP belongs to a known CDN network.
    Returns (True, cdn_name) or (False, None)
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cdn_name, networks in CDN_NETWORKS.items():
            for net in networks:
                if ip_obj in ipaddress.ip_network(net):
                    return True, cdn_name
    except Exception:
        pass
    return False, None


async def extract_real_ip(domain: str, engine: AsyncReconEngine) -> Optional[str]:
    """
    Attempt to find the real server IP even if behind a CDN.
    """
    # Step 1: Get IP via DoH
    ip = await engine.resolve_hostname(domain)
    if not ip:
        return None

    # Step 2: Check if it's a known CDN IP
    is_cdn, cdn_name = is_cdn_ip(ip)
    if not is_cdn:
        return ip  # Real IP found

    # Step 3: If CDN, try common subdomains that might point directly to origin
    subdomains = [
        f"direct.{domain}", f"origin.{domain}", f"origin-www.{domain}",
        f"cdn.{domain}", f"static.{domain}", f"img.{domain}"
    ]
    for sub in subdomains:
        try:
            sub_ip = await engine.resolve_hostname(sub)
            if sub_ip and not is_cdn_ip(sub_ip)[0]:
                return sub_ip
        except:
            continue

    # Step 4: Could also try historical DNS data or other tricks,
    # but we stop here to keep it self-contained.
    return None
