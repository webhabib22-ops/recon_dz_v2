# -*- coding: utf-8 -*-
import ipaddress
from typing import Optional, Tuple
# السطر الناقص الذي تسبب في الخطأ
from core.async_engine import AsyncReconEngine 

CDN_NETWORKS = {
    'Cloudflare': ['103.21.244.0/22', '104.16.0.0/13', '172.64.0.0/13'],
    'Akamai': ['23.32.0.0/11', '104.64.0.0/10'],
}

async def extract_real_ip(domain: str, engine: AsyncReconEngine) -> Optional[str]:
    """محاولة استخراج الـ IP الحقيقي عبر النطاقات الفرعية غير المحمية"""
    ip = await engine.resolve_hostname(domain)
    if not ip: return None

    is_cdn = False
    for cdn, nets in CDN_NETWORKS.items():
        for net in nets:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(net):
                is_cdn = True; break

    if not is_cdn: return ip

    # محاولة كشف الـ IP الحقيقي (Origin Lookup)
    shadow_subs = [f"direct.{domain}", f"origin.{domain}", f"dev.{domain}"]
    for sub in shadow_subs:
        real_ip = await engine.resolve_hostname(sub)
        if real_ip:
            return real_ip
    return ip
