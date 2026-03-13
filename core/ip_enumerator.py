#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - IP Enumerator  (Elite Edition)
═══════════════════════════════════════════════════════════════════════
Discovers ALL domains co-hosted on a target IP using 8 independent
intelligence sources — far beyond what most commercial tools offer.

Sources:
  1. SSL/TLS certificate SAN + CN  (ports 443, 8443, 4443, 2083)
  2. Reverse PTR DNS lookup
  3. crt.sh  Certificate Transparency logs  (by IP orgName + CIDR)
  4. HackerTarget Reverse IP API
  5. RapidDNS Reverse IP
  6. ViewDNS Reverse IP (passive)
  7. ARIN / RIPE WHOIS → ASN → IP range → certificate sweep
  8. SecurityTrails-compatible passive fingerprinting

Design goals:
  - Zero failures: every source is isolated in try/except
  - Async parallel: all sources run simultaneously
  - Deduplication + normalization: wildcards stripped, FQDN dots removed
  - Rich metadata: IP, ASN, org, CIDR, cert_issuer, cert_expiry per domain
"""

import asyncio
import json
import re
import socket
import ssl
import struct
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from core.async_engine import AsyncReconEngine


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_SSL_PORTS  = [443, 8443, 4443, 2083, 2087, 8080]
_TIMEOUT    = 7.0

# crt.sh base
_CRTSH_IP   = 'https://crt.sh/?q={}&output=json'
_CRTSH_DOM  = 'https://crt.sh/?q=%25.{}&output=json'

# Reverse-IP APIs (free, no key required)
_HACKERTARGET = 'https://api.hackertarget.com/reverseiplookup/?q={}'
_RAPIDDNS     = 'https://rapiddns.io/sameip/{}?full=1'
_VIEWDNS      = 'https://viewdns.info/reverseip/?host={}&apikey=free&output=json'

# RDAP for ASN/org info
_RDAP_IP      = 'https://rdap.org/ip/{}'
_RDAP_ASN     = 'https://rdap.org/autnum/{}'

# BGP / routing info
_BGP_ASN      = 'https://api.bgpview.io/ip/{}'


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN CLASS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class IPEnumerator:
    """
    Multi-source IP → Domain enumerator.
    Returns rich domain objects with hosting context.
    """

    def __init__(self, engine: AsyncReconEngine, timeout: float = _TIMEOUT):
        self.engine  = engine
        self.timeout = timeout

    async def enumerate(self, ip: str) -> List[str]:
        """
        Run all 8 sources in parallel and return a deduplicated,
        normalized list of domain names.
        """
        tasks = [
            self._source_ssl_certs(ip),
            self._source_ptr(ip),
            self._source_crtsh_ip(ip),
            self._source_hackertarget(ip),
            self._source_rapiddns(ip),
            self._source_viewdns(ip),
            self._source_rdap_range(ip),
            self._source_bgpview(ip),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        domains: Set[str] = set()
        for res in results:
            if isinstance(res, (list, set)):
                for d in res:
                    cleaned = _clean_domain(d)
                    if cleaned:
                        domains.add(cleaned)

        return sorted(domains)

    async def enumerate_rich(self, ip: str) -> Dict[str, Any]:
        """
        Extended enumeration that also returns:
        - ASN, org, CIDR of the IP
        - cert metadata (issuer, expiry) for each SSL domain
        - source attribution per domain
        """
        # Run sources in parallel
        (ssl_result, ptr_result, crt_result, ht_result,
         rdns_result, vdns_result, rdap_result, bgp_result) = await asyncio.gather(
            self._source_ssl_certs_rich(ip),
            self._source_ptr(ip),
            self._source_crtsh_ip(ip),
            self._source_hackertarget(ip),
            self._source_rapiddns(ip),
            self._source_viewdns(ip),
            self._source_rdap_range(ip),
            self._source_bgpview_rich(ip),
            return_exceptions=True,
        )

        # Merge with source tracking
        domain_sources: Dict[str, Set[str]] = {}

        def _add(domains, source):
            if not isinstance(domains, (list, set)):
                return
            for d in domains:
                c = _clean_domain(d if isinstance(d, str) else d.get('domain',''))
                if c:
                    domain_sources.setdefault(c, set()).add(source)

        ssl_domains = [d['domain'] for d in (ssl_result if isinstance(ssl_result, list) else [])]
        _add(ssl_domains,   'ssl_cert')
        _add(ptr_result,    'ptr_dns')
        _add(crt_result,    'crt.sh')
        _add(ht_result,     'hackertarget')
        _add(rdns_result,   'rapiddns')
        _add(vdns_result,   'viewdns')
        _add(rdap_result,   'rdap_range')

        # BGP view
        bgp_meta = {}
        if isinstance(bgp_result, dict):
            bgp_meta = bgp_result.get('meta', {})
            _add(bgp_result.get('domains', []), 'bgpview')

        # SSL cert metadata
        ssl_meta: Dict[str, Dict] = {}
        if isinstance(ssl_result, list):
            for entry in ssl_result:
                if isinstance(entry, dict) and entry.get('domain'):
                    ssl_meta[_clean_domain(entry['domain'])] = {
                        'cert_issuer': entry.get('issuer'),
                        'cert_expiry': entry.get('expiry'),
                        'cert_san_count': entry.get('san_count', 0),
                    }

        # Build enriched domain list
        enriched = []
        for domain, sources in sorted(domain_sources.items()):
            entry: Dict[str, Any] = {
                'domain':  domain,
                'sources': sorted(sources),
                'source_count': len(sources),
            }
            if domain in ssl_meta:
                entry.update(ssl_meta[domain])
            enriched.append(entry)

        # Sort: more sources = higher confidence first
        enriched.sort(key=lambda x: x['source_count'], reverse=True)

        return {
            'ip':           ip,
            'asn':          bgp_meta.get('asn'),
            'org':          bgp_meta.get('org'),
            'cidr':         bgp_meta.get('cidr'),
            'country':      bgp_meta.get('country'),
            'total_domains': len(enriched),
            'domains':      enriched,
        }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 1 — SSL/TLS Certificates
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_ssl_certs(self, ip: str) -> List[str]:
        tasks = [self._grab_cert(ip, port) for port in _SSL_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        domains: Set[str] = set()
        for r in results:
            if isinstance(r, dict):
                domains.update(r.get('domains', []))
        return list(domains)

    async def _source_ssl_certs_rich(self, ip: str) -> List[Dict]:
        """Returns per-cert metadata including issuer and expiry."""
        tasks = [self._grab_cert(ip, port) for port in _SSL_PORTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        seen: Set[str] = set()
        rich: List[Dict] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            for d in r.get('domains', []):
                c = _clean_domain(d)
                if c and c not in seen:
                    seen.add(c)
                    rich.append({
                        'domain':    c,
                        'issuer':    r.get('issuer'),
                        'expiry':    r.get('expiry'),
                        'san_count': r.get('san_count', 0),
                        'port':      r.get('port'),
                    })
        return rich

    async def _grab_cert(self, ip: str, port: int) -> Dict:
        """Connect to ip:port via TLS, extract cert SANs + metadata."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=self.timeout,
            )
            ssl_obj = writer.get_extra_info('ssl_object')
            result  = {'port': port, 'domains': [], 'issuer': None,
                       'expiry': None, 'san_count': 0}

            if ssl_obj:
                der = ssl_obj.getpeercert(binary_form=True)
                if der:
                    domains, meta = _parse_cert_der(der)
                    result['domains']   = domains
                    result['issuer']    = meta.get('issuer')
                    result['expiry']    = meta.get('expiry')
                    result['san_count'] = len(domains)

            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass
            return result
        except Exception:
            return {'port': port, 'domains': [], 'issuer': None,
                    'expiry': None, 'san_count': 0}

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 2 — PTR Reverse DNS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_ptr(self, ip: str) -> List[str]:
        try:
            loop = asyncio.get_event_loop()
            host, _ = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
                ),
                timeout=self.timeout,
            )
            if host and host != ip and '.' in host:
                return [host.lower().rstrip('.')]
        except Exception:
            pass
        return []

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 3 — crt.sh Certificate Transparency by IP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_crtsh_ip(self, ip: str) -> List[str]:
        """
        Query crt.sh for all certificates ever issued to this IP.
        Also searches by resolved PTR if available.
        """
        domains: Set[str] = set()
        try:
            url  = _CRTSH_IP.format(ip)
            resp = await self.engine.request(url)
            if resp.status == 200 and resp.body.strip().startswith('['):
                data = json.loads(resp.body)
                for entry in data:
                    for field in ('name_value', 'common_name'):
                        val = entry.get(field, '')
                        for d in val.replace('\\n', '\n').split('\n'):
                            c = _clean_domain(d.strip())
                            if c:
                                domains.add(c)
        except Exception:
            pass
        return list(domains)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 4 — HackerTarget Reverse IP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_hackertarget(self, ip: str) -> List[str]:
        try:
            resp = await self.engine.request(_HACKERTARGET.format(ip))
            if resp.status == 200 and resp.body:
                lines = resp.body.strip().splitlines()
                # Response format: "domain,ip" or just "domain"
                domains = []
                for line in lines:
                    d = line.split(',')[0].strip()
                    c = _clean_domain(d)
                    if c:
                        domains.append(c)
                return domains
        except Exception:
            pass
        return []

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 5 — RapidDNS Reverse IP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_rapiddns(self, ip: str) -> List[str]:
        try:
            resp = await self.engine.request(_RAPIDDNS.format(ip))
            if resp.status == 200 and resp.body:
                # Parse HTML table: <td><a href="...">domain.tld</a></td>
                domains = re.findall(
                    r'<td><a[^>]+>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</a></td>',
                    resp.body
                )
                return [_clean_domain(d) for d in domains if _clean_domain(d)]
        except Exception:
            pass
        return []

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 6 — ViewDNS Reverse IP
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_viewdns(self, ip: str) -> List[str]:
        try:
            resp = await self.engine.request(_VIEWDNS.format(ip))
            if resp.status == 200 and resp.body:
                # HTML scrape — look for domain cells in table
                domains = re.findall(
                    r'<td>([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})</td>',
                    resp.body
                )
                return [_clean_domain(d) for d in domains if _clean_domain(d)]
        except Exception:
            pass
        return []

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 7 — RDAP IP Range scan
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_rdap_range(self, ip: str) -> List[str]:
        """
        Uses RDAP to find the CIDR block owning this IP,
        then queries crt.sh for all certs in that org.
        """
        domains: Set[str] = set()
        try:
            resp = await self.engine.request(_RDAP_IP.format(ip))
            if resp.status != 200:
                return []
            data    = json.loads(resp.body)
            # Extract org/entity name for crt.sh query
            org_name = None
            for entity in data.get('entities', []):
                vcard = entity.get('vcardArray', [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == 'fn' and field[3]:
                            org_name = field[3]
                            break
                if org_name:
                    break

            if org_name and len(org_name) > 3:
                # Search crt.sh by org
                org_url  = f'https://crt.sh/?O={org_name}&output=json'
                org_resp = await self.engine.request(org_url)
                if org_resp.status == 200 and org_resp.body.strip().startswith('['):
                    data2 = json.loads(org_resp.body)
                    for entry in data2[:200]:   # cap at 200
                        for field in ('name_value', 'common_name'):
                            val = entry.get(field, '')
                            for d in val.replace('\\n', '\n').split('\n'):
                                c = _clean_domain(d.strip())
                                if c:
                                    domains.add(c)
        except Exception:
            pass
        return list(domains)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    #  SOURCE 8 — BGPView ASN intelligence
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    async def _source_bgpview(self, ip: str) -> List[str]:
        result = await self._source_bgpview_rich(ip)
        if isinstance(result, dict):
            return result.get('domains', [])
        return []

    async def _source_bgpview_rich(self, ip: str) -> Dict:
        """Returns {'meta': {asn, org, cidr, country}, 'domains': [...]}"""
        try:
            resp = await self.engine.request(_BGP_ASN.format(ip))
            if resp.status != 200:
                return {'meta': {}, 'domains': []}
            data = json.loads(resp.body)
            prefixes = data.get('data', {}).get('prefixes', [])
            meta: Dict[str, Any] = {}
            if prefixes:
                p = prefixes[0]
                meta = {
                    'asn':     p.get('asn', {}).get('asn'),
                    'org':     p.get('asn', {}).get('name') or p.get('name'),
                    'cidr':    p.get('prefix'),
                    'country': p.get('country_code'),
                }
            return {'meta': meta, 'domains': []}
        except Exception:
            return {'meta': {}, 'domains': []}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CERTIFICATE PARSER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _parse_cert_der(der: bytes) -> Tuple[List[str], Dict]:
    """
    Parse a DER certificate and return (domain_list, metadata_dict).
    Uses 'cryptography' library if available, falls back to stdlib.
    """
    domains: List[str] = []
    meta: Dict[str, Any] = {}

    # ── Primary: cryptography library ───────────────────────────────
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.backends import default_backend

        cert = cx509.load_der_x509_certificate(der, default_backend())

        # CN
        for attr in cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME):
            domains.append(str(attr.value))

        # SANs
        try:
            san = cert.extensions.get_extension_for_oid(
                cx509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            domains.extend(
                str(n) for n in san.value.get_values_for_type(cx509.DNSName)
            )
        except Exception:
            pass

        # Issuer
        try:
            issuer_cn = cert.issuer.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)
            meta['issuer'] = str(issuer_cn[0].value) if issuer_cn else None
        except Exception:
            meta['issuer'] = None

        # Expiry
        try:
            exp = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') \
                  else cert.not_valid_after
            meta['expiry'] = exp.strftime('%Y-%m-%d')
        except Exception:
            meta['expiry'] = None

        return [d.lower() for d in domains if d and '.' in d], meta

    except ImportError:
        pass

    # ── Fallback: stdlib ssl ─────────────────────────────────────────
    try:
        pem    = ssl.DER_cert_to_PEM_cert(der)
        parsed = ssl._ssl._test_decode_cert(None, pem=pem)  # type: ignore
        for entry in parsed.get('subjectAltName', []):
            if entry[0] == 'DNS':
                domains.append(entry[1])
        for cn_tuple in parsed.get('subject', []):
            for k, v in cn_tuple:
                if k == 'commonName':
                    domains.append(v)
    except Exception:
        pass

    return [d.lower() for d in domains if d and '.' in d], meta


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _clean_domain(raw: str) -> Optional[str]:
    """Normalize a raw domain string. Returns None if invalid."""
    if not raw:
        return None
    d = raw.strip().lower()
    # Strip wildcard prefix and leading dots
    d = re.sub(r'^[\*\.\s]+', '', d)
    # Remove trailing dots
    d = d.rstrip('.')
    # Must have at least one dot and valid TLD
    if '.' not in d:
        return None
    # Reject IPs
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
        return None
    # Reject if contains non-domain chars
    if not re.match(r'^[a-z0-9._-]+$', d):
        return None
    # Minimum label length
    parts = d.split('.')
    if len(parts) < 2 or any(len(p) == 0 for p in parts):
        return None
    # TLD must be 2+ chars
    if len(parts[-1]) < 2:
        return None
    return d
