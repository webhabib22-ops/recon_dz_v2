# -*- coding: utf-8 -*-
"""
RECON-DZ v2 - مطور (Algeria Threat Intelligence)
تطوير خاص للجهات العليا - كشف البنية التحتية الوطنية
"""

import json
import ipaddress
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class AlgerianTarget:
    domain: str
    sector: str = "عمومي"
    criticality: str = "low"
    is_sovereign: bool = False # هل الهدف سيادي؟
    infrastructure_type: str = "cloud" # local or cloud

class AlgeriaThreatDatabase:
    def __init__(self):
        # توسيع قاعدة البيانات لتشمل القطاعات الحساسة بدقة
        self.SECTORS = {
            'government': {
                'patterns': [r'\.gov\.dz$', r'\.univ-.*\.dz$', r'ministere', r'daira', r'wilaya'],
                'criticality': 'high',
                'is_sovereign': True
            },
            'energy': {
                'patterns': [r'sonatrach', r'sonelgaz', r'naftal', r'spe\.dz'],
                'criticality': 'critical',
                'is_sovereign': True
            },
            'telecom': {
                'patterns': [r'algerietelecom', r'mobilis', r'djezzy', r'ooredoo', r'at\.dz'],
                'criticality': 'high',
                'is_sovereign': False
            },
            'finance': {
                'patterns': [r'\.bank$', r'banque', r'badr', r'bdl', r'bea', r'bna'],
                'criticality': 'critical',
                'is_sovereign': False
            }
        }
        
        # نطاقات IP السيادية (أمثلة للمحاكاة - يتم تحديثها يدوياً)
        self.ALGERIA_RANGES = {
            'Algerie Telecom': ['41.107.0.0/16', '105.101.0.0/16'],
            'Mobilis': ['197.200.0.0/14'],
            # يمكن إضافة المزيد هنا
        }

    def identify_target(self, domain: str, ip: Optional[str] = None) -> AlgerianTarget:
        """تحليل الهدف بناءً على الاسم والعنوان الرقمي"""
        domain = domain.lower()
        target = AlgerianTarget(domain=domain)

        # 1. كشف القطاع بناءً على الأنماط (Regex)
        for sector, info in self.SECTORS.items():
            for pattern in info['patterns']:
                if re.search(pattern, domain):
                    target.sector = sector
                    target.criticality = info['criticality']
                    target.is_sovereign = info['is_sovereign']
                    break

        # 2. تحليل مكان الاستضافة (Local vs International)
        if ip:
            target.infrastructure_type = "international"
            for isp, ranges in self.ALGERIA_RANGES.items():
                for r in ranges:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
                        target.infrastructure_type = "local"
                        break
        
        return target

    def get_security_brief(self, target: AlgerianTarget) -> str:
        """ملخص أمني سريع للجهات العليا"""
        brief = f"[!] تنبيه أمني: هدف {target.sector.upper()}\n"
        brief += f"[-] الحساسية: {target.criticality}\n"
        brief += f"[-] نوع البنية: {'داخلية (الجزائر)' if target.infrastructure_type == 'local' else 'خارجية'}\n"
        if target.is_sovereign:
            brief += "[!!!] تحذير: هذا الهدف يندرج ضمن البنية التحتية السيادية للدولة."
        return brief

