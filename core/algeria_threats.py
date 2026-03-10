"""
Algeria-specific threat intelligence database
Enhanced with comprehensive detection
"""

import json
import ipaddress
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class AlgerianTarget:
    """Algerian target with full context"""
    domain: str
    ip: Optional[str] = None
    sector: str = "unknown"
    criticality: str = "low"
    isp: str = "unknown"
    compliance_requirements: List[str] = field(default_factory=list)
    common_vulns: List[str] = field(default_factory=list)
    is_gov: bool = False
    is_edu: bool = False
    is_bank: bool = False
    is_telecom: bool = False


class AlgeriaThreatDatabase:
    """Comprehensive Algeria threat database"""
    
    # Domain patterns by sector
    SECTOR_PATTERNS = {
        'government': [
            '.gov.dz', 'ministere', 'ministry', 'wilaya-', 'apc-', 
            'mairie-', 'amb-', 'consulat', 'presidence', 'mdn.dz',
            'mdrp.gov.dz', 'interieur.gov.dz', 'justice.dz',
        ],
        'banking': [
            'bank-of-algeria.dz', 'badrdz', 'cpa.dz', 'cnap.dz',
            'bead.dz', 'bna.dz', 'bh.dz', 'saa.dz', 'algex.dz',
            'sfil.dz', 'banque', 'bank', 'credit', 'caisse',
        ],
        'telecom': [
            'algerietelecom.dz', 'at.dz', 'mobilis.dz', 'djezzy.dz',
            'ooredoo.dz', 'ard.dz', 'poste.dz', 'telecom',
        ],
        'energy': [
            'sonatrach.dz', 'sonelgaz.dz', 'naftal.dz', 'eng.dz',
            'asal.dz', 'sntf.dz', 'sntv.dz', 'enapal.dz', 'energy',
            'petroleum', 'gas', 'electricity',
        ],
        'education': [
            'univ-', 'universite', 'university', 'ecole-', 'school',
            'esi.dz', 'usthb.dz', 'umc.dz', 'umbb.dz', 'edu.dz',
            'fac-', 'faculte', 'institut', 'center-', 'centre-',
        ],
        'health': [
            'chs.dz', 'hopital', 'hospital', 'sante.gov.dz',
            'ministere-sante', 'health', 'medical', 'clinique',
        ],
        'media': [
            'aps.dz', 'entv.dz', 'radioalgerie.dz', 'algerie1.com',
            'tout-sur-lalgerie.com', 'media', 'press', 'news',
        ],
    }
    
    # ISP IP ranges
    ISP_RANGES = {
        'Algerie_Telecom': [
            ipaddress.ip_network('41.96.0.0/14'),
            ipaddress.ip_network('105.96.0.0/13'),
            ipaddress.ip_network('197.200.0.0/13'),
            ipaddress.ip_network('129.45.0.0/16'),
        ],
        'Mobilis': [
            ipaddress.ip_network('154.121.0.0/16'),
        ],
        'Djezzy': [
            ipaddress.ip_network('41.107.0.0/16'),
            ipaddress.ip_network('105.235.0.0/16'),
        ],
        'Ooredoo': [
            ipaddress.ip_network('41.111.0.0/16'),
            ipaddress.ip_network('197.140.0.0/15'),
        ],
    }
    
    # Common vulnerabilities by sector
    SECTOR_VULNS = {
        'government': [
            'outdated_cms', 'exposed_admin', 'weak_ssl', 
            'info_disclosure', 'default_creds',
        ],
        'banking': [
            'api_vulns', 'mobile_banking', 'swift_security',
            'insufficient_encryption', 'session_management',
        ],
        'telecom': [
            'ss7_exposure', 'subscriber_data', 'infrastructure_misconfig',
            'signaling_security', 'core_network',
        ],
        'education': [
            'student_data_exposure', 'weak_auth', 'open_directories',
            'shared_hosting_risks', 'outdated_systems',
        ],
    }
    
    def identify_target(self, target: str, ip: Optional[str] = None) -> Optional[AlgerianTarget]:
        """
        Identify if target is Algerian with full context
        """
        target_lower = target.lower().strip()
        
        # Check 1: .dz TLD
        is_dz_tld = target_lower.endswith('.dz')
        
        # Check 2: IP in Algerian ranges
        is_dz_ip = False
        detected_isp = 'unknown'
        
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for isp_name, ranges in self.ISP_RANGES.items():
                    for network in ranges:
                        if ip_obj in network:
                            is_dz_ip = True
                            detected_isp = isp_name.replace('_', ' ')
                            break
                    if is_dz_ip:
                        break
            except:
                pass
        
        # If neither .dz nor Algerian IP, return None
        if not is_dz_tld and not is_dz_ip:
            return None
        
        # Determine sector
        sector = 'unknown'
        for sec, patterns in self.SECTOR_PATTERNS.items():
            for pattern in patterns:
                if pattern in target_lower:
                    sector = sec
                    break
            if sector != 'unknown':
                break
        
        # Determine criticality
        criticality = 'low'
        if sector in ['government', 'banking', 'energy']:
            criticality = 'high'
            # Check for extra critical
            extra_critical = ['presidence', 'bank-of-algeria', 'sonatrach', 'defense', 'mdn']
            if any(x in target_lower for x in extra_critical):
                criticality = 'critical'
        elif sector in ['telecom', 'health', 'education']:
            criticality = 'medium'
        
        # Compliance
        compliance = []
        if sector == 'government' or is_dz_tld:
            compliance.append('Decree_26_07')
        if sector == 'banking':
            compliance.extend(['Bank_Algeria_Circulars', 'PCI_DSS'])
        
        # Common vulnerabilities
        common_vulns = self.SECTOR_VULNS.get(sector, ['general_security'])
        
        # Flags
        is_gov = sector == 'government'
        is_edu = sector == 'education'
        is_bank = sector == 'banking'
        is_telecom = sector == 'telecom'
        
        # Guess ISP from domain if not detected from IP
        if detected_isp == 'unknown':
            detected_isp = self._guess_isp_from_domain(target_lower)
        
        return AlgerianTarget(
            domain=target,
            ip=ip,
            sector=sector,
            criticality=criticality,
            isp=detected_isp,
            compliance_requirements=compliance,
            common_vulns=common_vulns,
            is_gov=is_gov,
            is_edu=is_edu,
            is_bank=is_bank,
            is_telecom=is_telecom,
        )
    
    def _guess_isp_from_domain(self, domain: str) -> str:
        """Guess ISP from domain name"""
        if any(x in domain for x in ['algerietelecom', 'at.dz', 'mobilis']):
            return 'Algerie Telecom'
        if 'djezzy' in domain:
            return 'Djezzy'
        if 'ooredoo' in domain:
            return 'Ooredoo'
        return 'unknown'
    
    def get_test_recommendations(self, target: AlgerianTarget) -> List[str]:
        """Get recommended tests for target"""
        base_tests = [
            'subdomain_enum',
            'technology_fingerprint',
            'ssl_tls_analysis',
            'security_headers',
        ]
        
        sector_tests = {
            'government': [
                'decree_26_07_compliance',
                'admin_panel_exposure',
                'information_disclosure',
                'weak_authentication',
            ],
            'banking': [
                'api_security',
                'mobile_app_security',
                'swift_infrastructure',
                'transaction_integrity',
            ],
            'telecom': [
                'ss7_diameter_security',
                'subscriber_database',
                'signaling_protection',
                'infrastructure_hardening',
            ],
            'education': [
                'student_data_protection',
                'research_data_security',
                'shared_resource_isolation',
            ],
        }
        
        return base_tests + sector_tests.get(target.sector, [])
    
    def generate_report_summary(self, target: AlgerianTarget) -> Dict:
        """Generate summary for reporting"""
        return {
            'is_algerian': True,
            'domain': target.domain,
            'sector': target.sector,
            'criticality_level': target.criticality,
            'isp': target.isp,
            'compliance_frameworks': target.compliance_requirements,
            'applicable_regulations': self._get_regulations(target),
            'threat_level': self._assess_threat_level(target),
            'recommended_priority': 'immediate' if target.criticality == 'critical' else 'high',
        }
    
    def _get_regulations(self, target: AlgerianTarget) -> List[str]:
        """Get applicable regulations"""
        regs = []
        if target.is_gov:
            regs.append('Decree 26-07: Cybersecurity Framework')
        if target.is_bank:
            regs.append('Bank of Algeria Security Guidelines')
        if target.is_telecom:
            regs.append('ARPT Telecom Security Standards')
        return regs
    
    def _assess_threat_level(self, target: AlgerianTarget) -> str:
        """Assess current threat level"""
        # Simplified - would integrate with threat intel feeds
        if target.criticality == 'critical':
            return 'high_apt_activity'
        elif target.criticality == 'high':
            return 'moderate_targeting'
        return 'general_threats'
