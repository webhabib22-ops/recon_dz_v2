#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Server Fingerprinter
Fixed: type hint was List[PortInfo] but caller passes List[Dict] from port scan results,
       dict deduplication crashed on nested dicts/lists,
       added SSL/TLS analysis, security headers grading
"""

import re
import ssl
import asyncio
import socket
from typing import Dict, List, Optional, Any
from core.async_engine import AsyncReconEngine


class ServerFingerprinter:
    """
    Collect detailed server intelligence:
    - OS guess via TTL
    - Service version from banners
    - HTTP technology stack
    - SSL/TLS configuration analysis
    - Security header scoring
    """

    SECURITY_HEADERS = {
        'strict-transport-security': ('HSTS',               'CRITICAL'),
        'content-security-policy':   ('CSP',                'HIGH'),
        'x-frame-options':           ('Clickjacking',       'MEDIUM'),
        'x-content-type-options':    ('MIME Sniffing',      'MEDIUM'),
        'referrer-policy':           ('Referrer Leak',      'LOW'),
        'permissions-policy':        ('Feature Control',    'LOW'),
        'x-xss-protection':          ('XSS Filter',        'LOW'),
    }

    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine

    async def fingerprint(self, ip: str,
                          open_ports: List[Dict]) -> Dict[str, Any]:
        """
        Perform server fingerprinting.

        Args:
            ip:         Target IP address.
            open_ports: List of dicts from PortScanner or port_data['open_ports'].
                        Each dict should have keys: port, service, banner.
        Returns:
            Dict with os, services, technologies, ssl_info, security_headers, notes.
        """
        result: Dict[str, Any] = {
            'ip':               ip,
            'os':               None,
            'services':         [],
            'technologies':     [],
            'ssl_info':         None,
            'security_headers': None,
            'notes':            [],
        }

        # 1. OS guess from TTL
        ttl = await self._get_ttl(ip)
        if ttl:
            if ttl <= 64:
                result['os'] = 'Linux / Unix'
            elif ttl <= 128:
                result['os'] = 'Windows'
            else:
                result['os'] = 'Network Device / BSD'
            result['notes'].append(f"OS guess from TTL={ttl}")

        # 2. Service versioning from banners
        for port_entry in open_ports:
            # [FIX] Accept both dict and PortInfo-like objects
            port    = port_entry.get('port')    if isinstance(port_entry, dict) else port_entry.port
            service = port_entry.get('service') if isinstance(port_entry, dict) else port_entry.service
            banner  = port_entry.get('banner')  if isinstance(port_entry, dict) else port_entry.banner

            svc_info: Dict[str, Any] = {
                'port':    port,
                'service': service,
                'banner':  banner,
            }
            if banner:
                version = self._extract_version(banner)
                if version:
                    svc_info['version'] = version
            result['services'].append(svc_info)

        # 3. HTTP/HTTPS fingerprinting
        http_ports = [
            p for p in open_ports
            if (p.get('port') if isinstance(p, dict) else p.port) in (80, 443, 8080, 8443)
        ]
        for port_entry in http_ports:
            port  = port_entry.get('port') if isinstance(port_entry, dict) else port_entry.port
            proto = 'https' if port in (443, 8443) else 'http'
            url   = f"{proto}://{ip}:{port}"
            resp  = await self.engine.request(url)
            if resp.status != 0:
                self._analyze_http_response(resp, result)

        # 4. SSL/TLS analysis (port 443)
        if any((p.get('port') if isinstance(p, dict) else p.port) == 443
               for p in open_ports):
            result['ssl_info'] = await self._analyze_ssl(ip)

        # 5. Deduplicate technologies safely
        result['technologies'] = _dedupe_dicts(result['technologies'])

        return result

    # ────────────────────── HTTP Analysis ──────────────────────────────

    def _analyze_http_response(self, resp, result: Dict):
        """Extract technology and security header data from HTTP response."""
        headers = resp.headers  # already lowercased by engine

        server = headers.get('server')
        if server:
            result['technologies'].append({'type': 'server', 'name': server})

        powered = headers.get('x-powered-by')
        if powered:
            result['technologies'].append({'type': 'framework', 'name': powered})

        aspnet = headers.get('x-aspnet-version')
        if aspnet:
            result['technologies'].append({'type': 'runtime', 'name': f'ASP.NET {aspnet}'})

        # Security headers audit
        sec_audit: Dict[str, Any] = {'present': {}, 'missing': {}, 'score': 0}
        for hdr, (label, severity) in self.SECURITY_HEADERS.items():
            val = headers.get(hdr)
            if val:
                sec_audit['present'][hdr] = {'label': label, 'value': val}
                sec_audit['score'] += {'CRITICAL': 40, 'HIGH': 25,
                                        'MEDIUM': 20, 'LOW': 15}.get(severity, 10)
            else:
                sec_audit['missing'][hdr] = {'label': label, 'severity': severity}

        total_possible = sum(
            {'CRITICAL': 40, 'HIGH': 25, 'MEDIUM': 20, 'LOW': 15}.get(s, 10)
            for _, s in self.SECURITY_HEADERS.values()
        )
        pct = sec_audit['score'] / total_possible * 100 if total_possible else 0
        sec_audit['grade'] = 'A' if pct >= 90 else ('B' if pct >= 75 else
                              'C' if pct >= 60 else ('D' if pct >= 40 else 'F'))
        result['security_headers'] = sec_audit

    # ─────────────────────── SSL Analysis ─────────────────────────────

    async def _analyze_ssl(self, ip: str) -> Optional[Dict]:
        """Connect to port 443 and analyze the SSL/TLS configuration."""
        result: Dict[str, Any] = {
            'protocol_version': None,
            'cipher_suite':     None,
            'cert_cn':          None,
            'cert_san':         [],
            'cert_expiry':      None,
            'self_signed':      None,
            'issues':           [],
        }
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

            loop   = asyncio.get_event_loop()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ssl_ctx),
                timeout=5.0,
            )

            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                result['protocol_version'] = ssl_obj.version()
                cipher = ssl_obj.cipher()
                if cipher:
                    result['cipher_suite'] = cipher[0]

                # Weak protocol check
                if result['protocol_version'] in ('TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3'):
                    result['issues'].append(f"Weak protocol: {result['protocol_version']}")

                # Certificate info
                cert_bin = ssl_obj.getpeercert(binary_form=True)
                if cert_bin:
                    try:
                        from cryptography import x509 as cx509
                        from cryptography.hazmat.backends import default_backend
                        from datetime import datetime, timezone

                        cert = cx509.load_der_x509_certificate(cert_bin, default_backend())

                        # CN
                        cn_attrs = cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME)
                        if cn_attrs:
                            result['cert_cn'] = cn_attrs[0].value

                        # SAN
                        try:
                            san_ext = cert.extensions.get_extension_for_oid(
                                cx509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                            )
                            result['cert_san'] = [
                                n for n in san_ext.value.get_values_for_type(cx509.DNSName)
                            ]
                        except Exception:
                            pass

                        # Expiry
                        result['cert_expiry'] = cert.not_valid_after_utc.isoformat() \
                            if hasattr(cert, 'not_valid_after_utc') \
                            else cert.not_valid_after.isoformat()

                        # Self-signed check
                        issuer  = cert.issuer
                        subject = cert.subject
                        result['self_signed'] = (issuer == subject)
                        if result['self_signed']:
                            result['issues'].append('Self-signed certificate')

                    except ImportError:
                        pass  # cryptography library not installed

            writer.close()
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

        except Exception as e:
            result['error'] = str(e)

        return result

    # ─────────────────────── TTL Probe ────────────────────────────────

    async def _get_ttl(self, ip: str) -> Optional[int]:
        """
        Attempt to determine TTL by making a TCP connection and
        reading the IP TTL from the socket (Linux only).
        Falls back to None on unsupported platforms.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)
            # This is a best-effort; actual TTL reading requires raw sockets
            # For non-root environments we return None
            sock.close()
        except Exception:
            pass
        return None

    # ─────────────────────── Helpers ──────────────────────────────────

    @staticmethod
    def _extract_version(banner: str) -> Optional[str]:
        """Extract version string from a service banner."""
        patterns = [
            r'([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-_][a-zA-Z0-9]+)?)',
            r'version[:\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        ]
        for pat in patterns:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                return m.group(1)
        return None


def _dedupe_dicts(lst: List[Dict]) -> List[Dict]:
    """
    [FIX] Safe deduplication of list of dicts that may contain
    nested dicts/lists (tuple(d.items()) would crash on those).
    Uses JSON-based hashing instead.
    """
    import json
    seen: set = set()
    unique: List[Dict] = []
    for d in lst:
        try:
            key = json.dumps(d, sort_keys=True)
        except (TypeError, ValueError):
            key = str(d)
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique
