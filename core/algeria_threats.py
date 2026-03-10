"""
Algeria-specific threat intelligence
"""

import json
import ipaddress
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class AlgerianTarget:
    domain: str
    sector: str = "unknown"
    criticality: str = "low"
    isp: str = "unknown"
    compliance_requirements: List[str] = field(default_factory=list)


class AlgeriaThreatDatabase:
    CRITICAL_DOMAINS = {
        'government': ['gov.dz', 'ministere', 'wilaya-', 'apc-'],
        'banking': ['bank-of-algeria.dz', 'badrdz', 'cpa.dz', 'bna.dz'],
        'telecom': ['algerietelecom.dz', 'mobilis.dz', 'djezzy.dz', 'ooredoo.dz'],
        'energy': ['sonatrach.dz', 'sonelgaz.dz'],
    }
    
    ISP_RANGES = {
        'Algerie_Telecom': ['41.96.0.0/14', '105.96.0.0/13', '197.200.0.0/13'],
        'Mobilis': ['154.121.0.0/16'],
        'Djezzy': ['41.107.0.0/16', '105.235.0.0/16'],
        'Ooredoo': ['41.111.0.0/16', '197.140.0.0/15'],
    }
    
    def identify_target(self, target: str) -> Optional[AlgerianTarget]:
        # Check domain
        for sector, patterns in self.CRITICAL_DOMAINS.items():
            for pattern in patterns:
                if pattern in target.lower():
                    return AlgerianTarget(
                        domain=target,
                        sector=sector,
                        criticality='high' if sector in ['government', 'banking'] else 'medium',
                        isp=self._guess_isp(target),
                        compliance_requirements=['Decree_26_07'] if sector == 'government' else []
                    )
        
        # Check IP
        try:
            ip = ipaddress.ip_address(target)
            for isp, ranges in self.ISP_RANGES.items():
                for r in ranges:
                    if ip in ipaddress.ip_network(r):
                        return AlgerianTarget(
                            domain=str(ip),
                            sector='telecom',
                            criticality='medium',
                            isp=isp.replace('_', ' ')
                        )
        except:
            pass
        
        return None
    
    def _guess_isp(self, domain: str) -> str:
        if 'algerietelecom' in domain or 'mobilis' in domain:
            return 'Algerie Telecom'
        if 'djezzy' in domain:
            return 'Djezzy'
        if 'ooredoo' in domain:
            return 'Ooredoo'
        return 'unknown'
