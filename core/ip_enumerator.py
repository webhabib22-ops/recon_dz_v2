#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - IP Enumerator
Enumerate domains sharing the same IP address via:
1. SSL/TLS certificate SAN extraction
2. Reverse PTR DNS lookup
3. Shodan-style passive methods (extensible)
"""

import asyncio
import socket
import ssl
from typing import List, Optional, Set

from core.async_engine import AsyncReconEngine


class IPEnumerator:
    """
    Enumerate all domain names hosted on a given IP.
    Uses SSL certificate inspection and reverse DNS.
    """

    def __init__(self, engine: AsyncReconEngine, timeout: float = 6.0):
        self.engine  = engine
        self.timeout = timeout

    async def enumerate(self, ip: str) -> List[str]:
        """
        Run all enumeration methods and return deduplicated domain list.
        """
        tasks = [
            self._from_ssl_cert(ip, 443),
            self._from_ssl_cert(ip, 8443),
            self._from_ptr(ip),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        domains: Set[str] = set()
        for res in results:
            if isinstance(res, (list, set)):
                for d in res:
                    d = d.strip().lower().lstrip('*.')
                    if d and '.' in d:
                        domains.add(d)

        return sorted(domains)

    async def _from_ssl_cert(self, ip: str, port: int) -> List[str]:
        """
        Open a TLS connection to ip:port and extract all domain names
        from the server certificate (CN + Subject Alternative Names).
        """
        domains: List[str] = []
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ssl_ctx),
                timeout=self.timeout,
            )

            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                der = ssl_obj.getpeercert(binary_form=True)
                if der:
                    domains = _extract_domains_from_der(der)

            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
            except Exception:
                pass

        except (asyncio.TimeoutError, ConnectionRefusedError,
                ssl.SSLError, OSError):
            pass
        except Exception:
            pass

        return domains

    async def _from_ptr(self, ip: str) -> List[str]:
        """Perform a reverse DNS (PTR) lookup."""
        domains: List[str] = []
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
                domains.append(host.lower().rstrip('.'))
        except Exception:
            pass
        return domains


def _extract_domains_from_der(der: bytes) -> List[str]:
    """
    Extract CN and SAN DNS names from a DER-encoded certificate.
    Uses the 'cryptography' library if available, falls back to
    stdlib ssl parsing otherwise.
    """
    domains: List[str] = []
    try:
        from cryptography import x509 as cx509
        from cryptography.hazmat.backends import default_backend

        cert = cx509.load_der_x509_certificate(der, default_backend())

        # Common Name
        for attr in cert.subject.get_attributes_for_oid(cx509.NameOID.COMMON_NAME):
            domains.append(attr.value)

        # Subject Alternative Names
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                cx509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            domains.extend(san_ext.value.get_values_for_type(cx509.DNSName))
        except cx509.extensions.ExtensionNotFound:
            pass

    except ImportError:
        # Fallback: use stdlib ssl to decode PEM (approximate)
        try:
            pem    = ssl.DER_cert_to_PEM_cert(der)
            ctx    = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            parsed = ssl._ssl._test_decode_cert(  # type: ignore[attr-defined]
                None, pem=pem
            )
            for entry in parsed.get('subjectAltName', []):
                if entry[0] == 'DNS':
                    domains.append(entry[1])
        except Exception:
            pass

    return [d.lower() for d in domains if d and '.' in d]
