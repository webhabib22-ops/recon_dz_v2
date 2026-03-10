"""
RECON-DZ v2 - Algeria Threat Intelligence Database
Comprehensive security intelligence for Algerian infrastructure
For authorized security assessment and educational purposes
"""

import json
import ipaddress
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AlgerianTarget:
    """Complete Algerian target profile"""
    domain: str
    ip: Optional[str] = None
    sector: str = "unknown"
    criticality: str = "low"
    isp: str = "unknown"
    city: Optional[str] = None
    compliance_requirements: List[str] = field(default_factory=list)
    common_vulnerabilities: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    recommended_tests: List[str] = field(default_factory=list)
    
    # Sector flags
    is_government: bool = False
    is_education: bool = False
    is_banking: bool = False
    is_telecom: bool = False
    is_energy: bool = False
    is_health: bool = False
    is_media: bool = False
    
    # Network info
    asn: Optional[str] = None
    ip_range: Optional[str] = None


class AlgeriaThreatDatabase:
    """
    Professional Algeria threat intelligence database
    Maintained for national cybersecurity defense
    """
    
    # Critical infrastructure sectors
    SECTORS = {
        'government': {
            'patterns': [
                '.gov.dz', 'ministere', 'ministry', 'wilaya-', 'apc-', 
                'mairie-', 'amb-', 'consulat', 'presidence', 'mdn.dz',
                'mdrp.gov.dz', 'interieur.gov.dz', 'justice.dz',
                'finances.gov.dz', 'sante.gov.dz', 'education.gov.dz',
                'madrassa', 'dgsp', 'dgsn', 'douane', 'impots',
            ],
            'criticality': 'critical',
            'compliance': ['Decree_26_07', 'National_Security_Directive'],
            'common_vulns': [
                'outdated_cms', 'exposed_admin_panels', 'weak_ssl_tls',
                'information_disclosure', 'default_credentials',
                'missing_security_headers', 'open_directories',
            ],
            'threat_actors': ['Molerats', 'APT-C-23'],
        },
        'banking': {
            'patterns': [
                'bank-of-algeria.dz', 'badrdz', 'cpa.dz', 'cnap.dz',
                'bead.dz', 'bna.dz', 'bh.dz', 'saa.dz', 'algex.dz',
                'sfil.dz', 'banque', 'bank', 'credit', 'caisse',
                'epargne', 'financement', 'postal', 'ccp',
            ],
            'criticality': 'critical',
            'compliance': ['Bank_of_Algeria_Circulars', 'PCI_DSS', 'SWIFT_CSP'],
            'common_vulns': [
                'api_security_flaws', 'mobile_banking_vulns', 'insufficient_encryption',
                'session_management_issues', 'swift_infrastructure_weakness',
                'atm_network_exposure', 'credential_stuffing',
            ],
            'threat_actors': ['NilePhish', 'Cobalt_Group'],
        },
        'telecom': {
            'patterns': [
                'algerietelecom.dz', 'at.dz', 'mobilis.dz', 'djezzy.dz',
                'ooredoo.dz', 'ard.dz', 'poste.dz', 'pts.dz',
                'telecom', 'communications', 'mobile', 'cellular',
            ],
            'criticality': 'high',
            'compliance': ['ARPT_Regulations', 'Decree_26_07'],
            'common_vulns': [
                'ss7_diameter_exposure', 'subscriber_database_leaks',
                'infrastructure_misconfiguration', 'signaling_vulnerabilities',
                'core_network_exposure', 'lawful_intercept_security',
            ],
            'threat_actors': ['APT-C-23', 'SIGINT_targets'],
        },
        'energy': {
            'patterns': [
                'sonatrach.dz', 'sonelgaz.dz', 'naftal.dz', 'eng.dz',
                'asal.dz', 'sntf.dz', 'sntv.dz', 'enapal.dz',
                'energy', 'petroleum', 'gas', 'electricity', 'oil',
                'naftec', 'hassi', 'skikda', 'arzew', 'bejaia',
            ],
            'criticality': 'critical',
            'compliance': ['Energy_Sector_Directive', 'Decree_26_07'],
            'common_vulns': [
                'scada_exposure', 'industrial_control_systems',
                'outdated_software', 'network_segmentation_issues',
                'remote_access_vulnerabilities', 'supply_chain_risks',
            ],
            'threat_actors': ['APT_groups', 'State_sponsored'],
        },
        'education': {
            'patterns': [
                'univ-', 'universite', 'university', 'ecole-', 'school',
                'esi.dz', 'usthb.dz', 'umc.dz', 'umbb.dz', 'edu.dz',
                'fac-', 'faculte', 'institut', 'center-', 'centre-',
                'medea', 'blida', 'boumerdes', 'oran', 'constantine',
                'annaba', 'setif', 'djelfa', 'tissemssilt',
            ],
            'criticality': 'medium',
            'compliance': ['Ministry_of_Higher_Education_Guidelines'],
            'common_vulns': [
                'student_data_exposure', 'weak_authentication',
                'open_directories', 'shared_hosting_risks',
                'outdated_systems', 'research_data_leaks',
                'unsecured_wifi', 'bring_your_own_device_risks',
            ],
            'threat_actors': ['Student_hackers', 'Credential_stuffing'],
        },
        'health': {
            'patterns': [
                'chs.dz', 'hopital', 'hospital', 'sante.gov.dz',
                'ministere-sante', 'health', 'medical', 'clinique',
                'eph-', 'epsp-', 'santé', 'pharmacy', 'medicament',
            ],
            'criticality': 'high',
            'compliance': ['Health_Data_Protection', 'Decree_26_07'],
            'common_vulns': [
                'patient_data_exposure', 'medical_device_security',
                'ransomware_vulnerability', 'legacy_systems',
                'insufficient_backup', 'third_party_risks',
            ],
            'threat_actors': ['Ransomware_groups', 'Data_thieves'],
        },
        'media': {
            'patterns': [
                'aps.dz', 'entv.dz', 'radioalgerie.dz', 'algerie1.com',
                'tout-sur-lalgerie.com', 'media', 'press', 'news',
                'echourouk', 'elwatan', 'liberte', 'lesoirdalgerie',
            ],
            'criticality': 'medium',
            'compliance': ['Media_Regulatory_Authority'],
            'common_vulns': [
                'defacement_risk', 'ddos_vulnerability',
                'content_management_exploits', 'social_engineering',
            ],
            'threat_actors': ['Hacktivists', 'Defacement_groups'],
        },
    }
    
    # Algerian ISP IP ranges (CIDR)
    ISP_NETWORKS = {
        'Algerie_Telecom': {
            'networks': [
                '41.96.0.0/14',
                '105.96.0.0/13',
                '197.200.0.0/13',
                '129.45.0.0/16',
                '105.100.0.0/16',
                '105.101.0.0/16',
                '105.102.0.0/16',
                '105.103.0.0/16',
                '105.104.0.0/16',
                '105.105.0.0/16',
                '105.106.0.0/16',
                '105.107.0.0/16',
            ],
            'asn': ['AS36947', 'AS37529'],
            'type': 'incumbent',
        },
        'Mobilis': {
            'networks': [
                '154.121.0.0/16',
                '105.102.0.0/16',
            ],
            'asn': ['AS36947'],
            'type': 'mobile',
        },
        'Djezzy': {
            'networks': [
                '41.107.0.0/16',
                '105.235.0.0/16',
                '154.240.0.0/16',
            ],
            'asn': ['AS36947'],
            'type': 'mobile',
        },
        'Ooredoo': {
            'networks': [
                '41.111.0.0/16',
                '197.140.0.0/15',
                '154.247.0.0/16',
            ],
            'asn': ['AS36884'],
            'type': 'mobile',
        },
    }
    
    # Cities and their network allocations
    CITY_NETWORKS = {
        'Algiers': ['41.96.0.0/16', '105.96.0.0/16'],
        'Oran': ['41.97.0.0/16', '105.97.0.0/16'],
        'Constantine': ['41.98.0.0/16', '105.98.0.0/16'],
        'Annaba': ['41.99.0.0/16', '105.99.0.0/16'],
    }
    
    # Compliance frameworks
    COMPLIANCE_FRAMEWORKS = {
        'Decree_26_07': {
            'name': 'Executive Decree No. 26-07 of 2023',
            'scope': ['government', 'critical_infrastructure'],
            'requirements': [
                'mandatory_incident_reporting_24h',
                'data_localization',
                'encryption_standards',
                'certified_security_audits',
                'national_crypto_usage',
            ],
            'penalties': 'criminal_3_to_5_years',
        },
        'Bank_of_Algeria_Circulars': {
            'name': 'Bank of Algeria Security Guidelines',
            'scope': ['banking', 'financial_services'],
            'requirements': [
                'swift_csp_compliance',
                'multi_factor_authentication',
                'transaction_monitoring',
                'penetration_testing_annual',
            ],
        },
    }
    
    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).parent / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load extended data if available
        self.custom_intel = self._load_custom_intel()
    
    def _load_custom_intel(self) -> Dict:
        """Load custom intelligence"""
        intel_file = self.data_dir / "custom_intel.json"
        if intel_file.exists():
            with open(intel_file, 'r') as f:
                return json.load(f)
        return {}
    
    def identify_target(self, target: str, ip: Optional[str] = None) -> Optional[AlgerianTarget]:
        """
        Comprehensive target identification
        """
        target_lower = target.lower().strip()
        
        # Check 1: .dz TLD
        is_dz_domain = target_lower.endswith('.dz')
        
        # Check 2: IP in Algerian ranges
        is_dz_ip = False
        detected_isp = 'unknown'
        detected_city = None
        ip_range = None
        
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for isp_name, data in self.ISP_NETWORKS.items():
                    for network_str in data['networks']:
                        network = ipaddress.ip_network(network_str)
                        if ip_obj in network:
                            is_dz_ip = True
                            detected_isp = isp_name
                            ip_range = network_str
                            
                            # Check city
                            for city, city_nets in self.CITY_NETWORKS.items():
                                if any(ip_obj in ipaddress.ip_network(cn) for cn in city_nets):
                                    detected_city = city
                                    break
                            break
                    if is_dz_ip:
                        break
            except Exception as e:
                pass
        
        # If neither .dz nor Algerian IP, not Algerian
        if not is_dz_domain and not is_dz_ip:
            return None
        
        # Determine sector
        sector = 'unknown'
        sector_data = {}
        
        for sec_name, sec_info in self.SECTORS.items():
            for pattern in sec_info['patterns']:
                if pattern in target_lower:
                    sector = sec_name
                    sector_data = sec_info
                    break
            if sector != 'unknown':
                break
        
        # Determine criticality
        criticality = 'low'
        if sector in ['government', 'banking', 'energy']:
            criticality = 'critical' if any(x in target_lower for x in 
                ['presidence', 'bank-of-algeria', 'sonatrach', 'defense']) else 'high'
        elif sector in ['telecom', 'health']:
            criticality = 'high'
        elif sector in ['education', 'media']:
            criticality = 'medium'
        
        # Build compliance list
        compliance = []
        if sector in ['government', 'energy', 'telecom']:
            compliance.append('Decree_26_07')
        if sector == 'banking':
            compliance.extend(['Bank_of_Algeria_Circulars', 'PCI_DSS'])
        
        # Get ISP from domain if not from IP
        if detected_isp == 'unknown':
            detected_isp = self._guess_isp_from_domain(target_lower)
        
        # Build target object
        target_obj = AlgerianTarget(
            domain=target,
            ip=ip,
            sector=sector,
            criticality=criticality,
            isp=detected_isp,
            city=detected_city,
            compliance_requirements=compliance,
            common_vulnerabilities=sector_data.get('common_vulns', ['general_security']),
            threat_actors=sector_data.get('threat_actors', []),
            recommended_tests=self._get_tests_for_sector(sector),
            is_government=sector == 'government',
            is_education=sector == 'education',
            is_banking=sector == 'banking',
            is_telecom=sector == 'telecom',
            is_energy=sector == 'energy',
            is_health=sector == 'health',
            is_media=sector == 'media',
            ip_range=ip_range,
        )
        
        return target_obj
    
    def _guess_isp_from_domain(self, domain: str) -> str:
        """Guess ISP from domain patterns"""
        if any(x in domain for x in ['algerietelecom', 'at.dz', 'mobilis']):
            return 'Algerie_Telecom'
        if 'djezzy' in domain:
            return 'Djezzy'
        if 'ooredoo' in domain:
            return 'Ooredoo'
        return 'unknown'
    
    def _get_tests_for_sector(self, sector: str) -> List[str]:
        """Get recommended security tests"""
        base_tests = [
            'subdomain_enumeration',
            'technology_fingerprinting',
            'ssl_tls_analysis',
            'security_headers',
            'exposed_endpoints',
        ]
        
        sector_tests = {
            'government': [
                'decree_26_07_compliance',
                'admin_panel_exposure',
                'information_disclosure',
                'weak_authentication',
                'apt_ttp_emulation',
            ],
            'banking': [
                'api_security_assessment',
                'mobile_app_security',
                'swift_infrastructure',
                'transaction_integrity',
                'fraud_detection_capabilities',
            ],
            'telecom': [
                'ss7_diameter_security',
                'subscriber_data_protection',
                'signaling_firewall',
                'core_network_hardening',
            ],
            'energy': [
                'scada_security',
                'industrial_control_systems',
                'network_segmentation',
                'supply_chain_security',
            ],
            'education': [
                'student_data_privacy',
                'research_ip_protection',
                'campus_network_security',
                'byod_policy_compliance',
            ],
        }
        
        return base_tests + sector_tests.get(sector, [])
    
    def generate_test_plan(self, target: AlgerianTarget) -> Dict:
        """Generate comprehensive test plan"""
        return {
            'target': target.domain,
            'classification': {
                'sector': target.sector,
                'criticality': target.criticality,
                'isp': target.isp,
                'city': target.city,
            },
            'compliance_requirements': target.compliance_requirements,
            'phases': [
                {
                    'name': 'reconnaissance',
                    'priority': 'critical',
                    'tests': [
                        'dns_enumeration',
                        'subdomain_discovery',
                        'ip_range_mapping',
                        'technology_fingerprinting',
                    ],
                },
                {
                    'name': 'vulnerability_assessment',
                    'priority': 'high',
                    'tests': target.recommended_tests,
                },
                {
                    'name': 'compliance_verification',
                    'priority': 'critical' if target.is_government else 'medium',
                    'tests': target.compliance_requirements,
                },
            ],
            'threat_context': {
                'likely_threat_actors': target.threat_actors,
                'attack_scenarios': self._get_attack_scenarios(target),
            },
        }
    
    def _get_attack_scenarios(self, target: AlgerianTarget) -> List[str]:
        """Get relevant attack scenarios"""
        scenarios = []
        
        if target.is_government:
            scenarios.extend([
                'spear_phishing_officials',
                'watering_hole_news_sites',
                'credential_harvesting',
                'data_exfiltration',
            ])
        
        if target.is_banking:
            scenarios.extend([
                'swift_fraud',
                'card_skimming',
                'mobile_banking_trojan',
                'insider_threat',
            ])
        
        if target.is_telecom:
            scenarios.extend([
                'ss7_interception',
                'subscriber_tracking',
                'billing_system_fraud',
                'network_disruption',
            ])
        
        return scenarios
    
    def check_compliance_gaps(self, finding: Dict, target: AlgerianTarget) -> List[str]:
        """Check compliance implications"""
        gaps = []
        
        if 'Decree_26_07' in target.compliance_requirements:
            # Check encryption
            if finding.get('type') in ['unencrypted_transmission', 'weak_cipher']:
                gaps.append('Decree_26_07_Article_12_Encryption')
            
            # Check access control
            if finding.get('type') in ['authentication_bypass', 'weak_auth']:
                gaps.append('Decree_26_07_Article_8_Access_Control')
            
            # Check monitoring
            if finding.get('type') in ['insufficient_logging', 'no_monitoring']:
                gaps.append('Decree_26_07_Article_15_Security_Monitoring')
        
        return gaps
    
    def get_threat_intel_summary(self, target: AlgerianTarget) -> Dict:
        """Get threat intelligence summary"""
        return {
            'geopolitical_context': {
                'country_risk': 'medium',
                'sector_targeting': 'high' if target.criticality == 'critical' else 'medium',
                'recent_campaigns': self._get_recent_campaigns(target),
            },
            'apt_activity': {
                'active_groups': target.threat_actors,
                'ttp_observed': self._get_ttp_for_actors(target.threat_actors),
            },
            'recommendations': {
                'immediate_actions': self._get_immediate_actions(target),
                'strategic_improvements': self._get_strategic_improvements(target),
            },
        }
    
    def _get_recent_campaigns(self, target: AlgerianTarget) -> List[str]:
        """Get recent threat campaigns (placeholder for live feed)"""
        # Would integrate with MISP or similar
        return ['Molerats_2024', 'APT-C-23_Mobile_Campaign']
    
    def _get_ttp_for_actors(self, actors: List[str]) -> List[str]:
        """Get TTP for threat actors"""
        ttp_db = {
            'Molerats': ['spear_phishing', 'malicious_documents', 'dropbox_abuse'],
            'APT-C-23': ['mobile_malware', 'watering_hole', 'social_engineering'],
            'NilePhish': ['credential_harvesting', 'web_injection', 'fake_apps'],
        }
        
        all_ttp = []
        for actor in actors:
            all_ttp.extend(ttp_db.get(actor, []))
        
        return list(set(all_ttp))
    
    def _get_immediate_actions(self, target: AlgerianTarget) -> List[str]:
        """Get immediate security actions"""
        actions = [
            'Enable multi-factor authentication',
            'Patch critical vulnerabilities within 24h',
            'Review access logs for anomalies',
        ]
        
        if target.is_government:
            actions.append('Report to CERT-DZ if compromised')
        
        return actions
    
    def _get_strategic_improvements(self, target: AlgerianTarget) -> List[str]:
        """Get strategic recommendations"""
        return [
            'Implement zero-trust architecture',
            'Establish security operations center (SOC)',
            'Regular penetration testing',
            'Employee security awareness training',
        ]
    
    def save_observation(self, target: str, observation: Dict):
        """Save observation for intelligence building"""
        obs_file = self.data_dir / "observations.jsonl"
        
        entry = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'observation': observation,
        }
        
        with open(obs_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
