#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Port Scanner
Fixed: asyncio.Semaphore() moved out of __init__ (requires running event loop),
       improved banner grabbing, added service version extraction,
       vulnerability hints per service
"""

import asyncio
import socket
from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field


@dataclass
class PortInfo:
    """Information about a single open port."""
    port:    int
    state:   str                   # 'open' | 'closed' | 'filtered'
    service: Optional[str]   = None
    banner:  Optional[str]   = None
    version: Optional[str]   = None
    vulns:   List[str]        = field(default_factory=list)


class PortScanner:
    """
    Async TCP port scanner with banner grabbing and basic vulnerability hints.
    Fixed: Semaphore is created inside scan() to guarantee a running event loop.
    """

    COMMON_PORTS: Dict[int, str] = {
        21:    'FTP',
        22:    'SSH',
        23:    'Telnet',
        25:    'SMTP',
        53:    'DNS',
        80:    'HTTP',
        110:   'POP3',
        111:   'RPC',
        135:   'MSRPC',
        139:   'NetBIOS',
        143:   'IMAP',
        389:   'LDAP',
        443:   'HTTPS',
        445:   'SMB',
        636:   'LDAPS',
        993:   'IMAPS',
        995:   'POP3S',
        1433:  'MSSQL',
        1521:  'Oracle',
        1723:  'PPTP',
        2049:  'NFS',
        3306:  'MySQL',
        3389:  'RDP',
        5432:  'PostgreSQL',
        5900:  'VNC',
        6379:  'Redis',
        8080:  'HTTP-Alt',
        8443:  'HTTPS-Alt',
        8888:  'HTTP-Alt2',
        9200:  'Elasticsearch',
        11211: 'Memcached',
        27017: 'MongoDB',
        27018: 'MongoDB-Shard',
    }

    # Known dangerous open conditions
    _VULN_HINTS: Dict[int, str] = {
        21:    'Anonymous FTP login may be allowed',
        23:    'Telnet transmits credentials in cleartext',
        445:   'SMB exposed — check for EternalBlue (MS17-010)',
        3389:  'RDP exposed — check for BlueKeep (CVE-2019-0708)',
        5900:  'VNC exposed — may allow unauthenticated access',
        6379:  'Redis often runs without authentication',
        9200:  'Elasticsearch may expose data without auth',
        11211: 'Memcached UDP amplification DDoS risk',
        27017: 'MongoDB may run without authentication',
    }

    # Probes to send per service to elicit a banner
    _PROBES: Dict[int, bytes] = {
        80:   b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
        8080: b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
        443:  b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
        8443: b'HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n',
        25:   b'EHLO recon.local\r\n',
        21:   b'',      # banner sent on connect
        22:   b'',      # banner sent on connect
        3306: b'',      # banner sent on connect
        5432: b'',      # banner sent on connect
    }

    def __init__(self, timeout: float = 2.0, max_concurrent: int = 150):
        self.timeout        = timeout
        self.max_concurrent = max_concurrent
        # [FIX] Do NOT create asyncio.Semaphore here — no event loop yet.
        # It is created lazily inside scan().
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def scan(self, ip: str,
                   ports: Optional[List[int]] = None) -> List[PortInfo]:
        """
        Scan an IP address for open ports.
        Returns sorted list of open PortInfo objects.
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())

        # [FIX] Create semaphore here, inside async context
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

        tasks   = [self._scan_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports: List[PortInfo] = []
        for res in results:
            if isinstance(res, PortInfo) and res.state == 'open':
                open_ports.append(res)

        return sorted(open_ports, key=lambda p: p.port)

    async def _scan_port(self, ip: str, port: int) -> Optional[PortInfo]:
        """Try to connect; if successful, attempt banner grab."""
        async with self._semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None

            info = PortInfo(
                port    = port,
                state   = 'open',
                service = self.COMMON_PORTS.get(port, 'unknown'),
            )

            # Banner grabbing
            banner = await self._grab_banner(reader, writer, port)
            if banner:
                info.banner  = banner[:300]
                info.version = self._extract_version(banner)

            # Vulnerability hint
            if port in self._VULN_HINTS:
                info.vulns.append(self._VULN_HINTS[port])

            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass

            return info

    async def _grab_banner(self, reader, writer, port: int) -> Optional[str]:
        """Send a probe and read the response banner."""
        probe = self._PROBES.get(port, b'\r\n')
        try:
            if probe:
                writer.write(probe)
                await asyncio.wait_for(writer.drain(), timeout=1.0)

            raw = await asyncio.wait_for(reader.read(2048), timeout=self.timeout)
            return raw.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None

    @staticmethod
    def _extract_version(banner: str) -> Optional[str]:
        """Extract version string from a service banner."""
        import re
        patterns = [
            r'([0-9]+\.[0-9]+(?:\.[0-9p]+)?(?:[-_][a-zA-Z0-9]+)?)',
            r'version[:\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            r'/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        ]
        for pat in patterns:
            m = re.search(pat, banner, re.IGNORECASE)
            if m:
                return m.group(1)
        return None
