# -*- coding: utf-8 -*-
import re
from typing import Dict, Any, List
from core.port_scanner import PortInfo

class ServerFingerprinter:
    def fingerprint(self, open_ports: List[PortInfo]) -> Dict[str, Any]:
        """تحليل الهوية البرمجية للسيرفر عبر البانرات المجمعة"""
        profile = {'os': 'Unknown', 'web_server': 'Unknown', 'vulnerabilities': []}
        
        for p in open_ports:
            banner = p.banner.lower() if p.banner else ""
            
            # كشف نظام التشغيل عبر مؤشرات الخدمات
            if 'ubuntu' in banner or 'debian' in banner: profile['os'] = 'Linux (Debian/Ubuntu)'
            elif 'centos' in banner or 'redhat' in banner: profile['os'] = 'Linux (RHEL/CentOS)'
            elif 'microsoft' in banner or 'iis' in banner: profile['os'] = 'Windows Server'

            # كشف السيرفر
            if 'nginx' in banner: profile['web_server'] = 'Nginx'
            elif 'apache' in banner: profile['web_server'] = 'Apache'
            
        return profile

