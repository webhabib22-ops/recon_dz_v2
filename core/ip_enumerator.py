# -*- coding: utf-8 -*-
"""
ip_enumerator.py - Enumerate domains associated with an IP address
Part of RECON-DZ v2
"""

import asyncio
import socket
import ssl
from typing import List, Set
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from core.async_engine import AsyncReconEngine


class IPEnumerator:
    """
    Enumerate domains hosted on the same IP using various techniques.
    """

    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine
        self.timeout = 5

    async def enumerate(self, ip: str) -> List[str]:
        """
        Perform enumeration using multiple methods.
        """
        domains: Set[str] = set()

        # Method 1: Extract from SSL certificate (port 443)
        ssl_domains = await self._from_ssl_cert(ip)
        domains.update(ssl_domains)

        # Method 2: Reverse DNS (PTR) lookup
        ptr_domains = await self._from_ptr(ip)
        domains.update(ptr_domains)

        # Additional methods (e.g., certificate transparency logs) could be added later

        return list(domains)

    async def _from_ssl_cert(self, ip: str) -> List[str]:
        """
        Connect to port 443 and extract domain names from the SSL certificate.
        """
        domains = []
        try:
            # Create an SSL context that does not verify hostname
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 443, ssl=ssl_context),
                timeout=self.timeout
            )

            # Get the SSL object
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                # Get the certificate in DER format
                der_cert = ssl_object.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())

                # Extract Common Name (CN)
                for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                    domains.append(attr.value)

                # Extract Subject Alternative Names (SAN)
                try:
                    san_ext = cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                    )
                    san = san_ext.value
                    for name in san.get_values_for_type(x509.DNSName):
                        domains.append(name)
                except x509.ExtensionNotFound:
                    pass

            writer.close()
            await writer.wait_closed()

        except (asyncio.TimeoutError, ConnectionRefusedError, ssl.SSLError, OSError):
            # Connection failed or no SSL
            pass
        except Exception:
            # Other errors ignored
            pass

        return list(set(domains))

    async def _from_ptr(self, ip: str) -> List[str]:
        """
        Perform reverse DNS (PTR) lookup.
        """
        domains = []
        try:
            # Use asyncio's getnameinfo in a thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            host, _ = await loop.getnameinfo((ip, 0), socket.NI_NAMEREQD)
            if host and host != ip:
                domains.append(host)
        except (socket.gaierror, asyncio.TimeoutError, OSError):
            pass
        except Exception:
            pass

        return domains
