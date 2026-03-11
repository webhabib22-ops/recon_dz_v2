# -*- coding: utf-8 -*-
"""
port_scanner.py - Scan open ports on a target IP
Part of RECON-DZ v2
"""

import asyncio
import socket
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class PortInfo:
    port: int
    state: str  # open, closed, filtered
    service: Optional[str] = None
    banner: Optional[str] = None


class PortScanner:
    """
    Scan common ports on an IP address.
    """

    # Common ports with service names
    COMMON_PORTS = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'RPC', 139: 'NetBIOS',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
        1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
        5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        27017: 'MongoDB', 27018: 'MongoDB'
    }

    def __init__(self, timeout: float = 2.0, max_concurrent: int = 100):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan(self, ip: str, ports: Optional[List[int]] = None) -> List[PortInfo]:
        """
        Scan given ports or default common ports.
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())

        tasks = [self._scan_port(ip, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        open_ports = []
        for res in results:
            if isinstance(res, PortInfo) and res.state == 'open':
                open_ports.append(res)
        return open_ports

    async def _scan_port(self, ip: str, port: int) -> Optional[PortInfo]:
        """Try to connect to a port and grab banner."""
        async with self.semaphore:
            try:
                # Use asyncio.open_connection with timeout
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout
                )
                # Connection successful -> port open
                info = PortInfo(port=port, state='open')
                # Try to grab banner
                try:
                    # Send a generic probe for common services
                    if port in [80, 8080, 443, 8443]:
                        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    elif port == 21:
                        pass  # FTP banner is sent on connect
                    elif port == 22:
                        pass  # SSH banner on connect
                    else:
                        writer.write(b"\r\n")
                    await writer.drain()

                    banner_bytes = await asyncio.wait_for(
                        reader.read(1024), timeout=self.timeout
                    )
                    banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                    if banner:
                        info.banner = banner[:200]  # limit length
                except Exception:
                    pass

                # Identify service
                info.service = self.COMMON_PORTS.get(port, 'unknown')
                writer.close()
                await writer.wait_closed()
                return info
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return None
            except Exception:
                return None
