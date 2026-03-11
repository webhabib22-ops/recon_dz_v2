# -*- coding: utf-8 -*-
"""
server_fingerprint.py - Advanced server fingerprinting
Part of RECON-DZ v2
"""

import asyncio
import re
from typing import Dict, List, Optional, Any
from core.port_scanner import PortInfo
from core.async_engine import AsyncReconEngine


class ServerFingerprinter:
    """
    Collect detailed information about the server: OS, services, technologies.
    """

    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine

    async def fingerprint(self, ip: str, open_ports: List[PortInfo]) -> Dict[str, Any]:
        """
        Perform OS detection, service versioning, etc.
        """
        result = {
            'ip': ip,
            'os': None,
            'services': [],
            'technologies': [],
            'notes': []
        }

        # 1. Try to guess OS from TTL (simple)
        ttl = await self._get_ttl(ip)
        if ttl:
            if ttl <= 64:
                result['os'] = 'Linux/Unix'
            elif ttl <= 128:
                result['os'] = 'Windows'
            elif ttl <= 255:
                result['os'] = 'Network device (Cisco/BSD)'
            result['notes'].append(f"TTL based guess: {ttl}")

        # 2. Service versioning via banner grabbing on open ports
        for port_info in open_ports:
            service_info = {
                'port': port_info.port,
                'service': port_info.service,
                'banner': port_info.banner
            }
            # If banner contains version info, try to extract
            if port_info.banner:
                version = self._extract_version(port_info.banner)
                if version:
                    service_info['version'] = version
            result['services'].append(service_info)

        # 3. HTTP specific fingerprinting (if port 80 or 443 open)
        http_ports = [p for p in open_ports if p.port in [80, 443, 8080, 8443]]
        for port_info in http_ports:
            proto = 'https' if port_info.port in [443, 8443] else 'http'
            url = f"{proto}://{ip}:{port_info.port}"
            resp = await self.engine.request(url)
            if resp.status != 0:
                # Server header
                server = resp.get_header('server')
                if server:
                    result['technologies'].append({'type': 'server', 'name': server})
                # X-Powered-By
                powered = resp.get_header('x-powered-by')
                if powered:
                    result['technologies'].append({'type': 'framework', 'name': powered})
                # Cookies / other headers
                # Could add more analysis here

        # Remove duplicates
        result['technologies'] = [dict(t) for t in {tuple(d.items()) for d in result['technologies']}]
        return result

    async def _get_ttl(self, ip: str) -> Optional[int]:
        """
        Ping the target and get TTL (requires ping command or raw sockets).
        For simplicity, we'll use a UDP or TCP probe to observe TTL from response.
        This is complex, so we'll skip or implement simple ICMP ping.
        In Python without root, we can't send raw packets easily. So we'll rely on HTTP TTL from existing connections.
        Actually, we can get TTL from the socket after connecting to an open port.
        """
        # If we have an open port, we can get TTL from the connection
        # For now, we return None to avoid complexity
        return None

    def _extract_version(self, banner: str) -> Optional[str]:
        """Try to extract version string from banner."""
        patterns = [
            r'([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'version[\s=:]+([0-9.]+)',
            r'/([0-9.]+)'
        ]
        for pat in patterns:
            match = re.search(pat, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
