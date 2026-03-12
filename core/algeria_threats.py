#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Algeria Threat Intelligence Database
Fixed: broken unicode in comments, improved sector logic,
       cleaner dataclass defaults, proper compliance mapping
"""

import json
import ipaddress
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path
from datetime import datetime


@dataclass
class AlgerianTarget:
    """Complete Algerian infrastructure profile."""
    domain:                  str
    ip:                      Optional[str]     = None
    sector:                  str               = "unknown"
    criticality:             str               = "low"
    isp:                     str               = "unknown"
    city:                    Optional[str]     = None
    compliance_requirements: List[str]         = field(default_factory=list)
    common_vulnerabilities:  List[str]         = field(default_factory=list)
    threat_actors:           List[str]         = field(default_factory=list)
    recommended_tests:       List[str]         = field(default_factory=list)
    # Sector flags
    is_government:           bool              = False
    is_education:            bool              = False
    is_banking:              bool              = False
    is_telecom:              bool              = False
    is_energy:               bool              = False
    is_health:               bool              = False
    is_media:                bool              = False
    # Network metadata
    asn:                     Optional[str]     = None
    ip_range:                Optional[str]     = None


class AlgeriaThreatDatabase:
    """
    Algerian threat intelligence database.
    Covers sector classification, ISP/IP mapping, compliance frameworks,
    and recommended security tests.
    """

    # ─────────────────────── Sector Definitions ──────────────────────

    SECTORS: Dict[str, Dict] = {
        'government': {
            'patterns': [
                '.gov.dz', 'ministere', 'ministry', 'wilaya-', 'apc-',
                'mairie-', 'amb-', 'consulat', 'presidence', 'mdn.dz',
                'mdrp.gov.dz', 'interieur.gov.dz', 'justice.dz',
                'finances.gov.dz', 'sante.gov.dz', 'education.gov.dz',
                'dgsp', 'dgsn', 'douane', 'impots',
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
                'credential_stuffing',
            ],
            'threat_actors': ['NilePhish', 'Cobalt_Group'],
        },
        'telecom': {
            'patterns': [
                'algerietelecom.dz', 'at.dz', 'mobilis.dz', 'djezzy.dz',
                'ooredoo.dz', 'ard.dz', 'poste.dz', 'pts.dz',
                'telecom', 'communications',
            ],
            'criticality': 'high',
            'compliance': ['ARPT_Regulations', 'Decree_26_07'],
            'common_vulns': [
                'ss7_diameter_exposure', 'subscriber_database_leaks',
                'infrastructure_misconfiguration', 'signaling_vulnerabilities',
            ],
            'threat_actors': ['APT-C-23', 'SIGINT_targets'],
        },
        'energy': {
            'patterns': [
                'sonatrach.dz', 'sonelgaz.dz', 'naftal.dz', 'eng.dz',
                'asal.dz', 'sntf.dz', 'naftec', 'hassi',
                'energy', 'petroleum', 'gas', 'electricity',
            ],
            'criticality': 'critical',
            'compliance': ['Energy_Sector_Directive', 'Decree_26_07'],
            'common_vulns': [
                'scada_exposure', 'industrial_control_systems',
                'outdated_software', 'network_segmentation_issues',
            ],
            'threat_actors': ['APT_groups', 'State_sponsored'],
        },
        'education': {
            'patterns': [
                'univ-', 'universite', 'university', 'ecole-', 'school',
                'esi.dz', 'usthb.dz', 'umc.dz', 'umbb.dz', 'edu.dz',
                'fac-', 'faculte', 'institut', 'medea', 'blida',
                'boumerdes', 'oran', 'constantine', 'annaba', 'setif',
                'djelfa', 'tissemssilt',
            ],
            'criticality': 'medium',
            'compliance': ['Ministry_of_Higher_Education_Guidelines'],
            'common_vulns': [
                'student_data_exposure', 'weak_authentication',
                'open_directories', 'outdated_systems',
                'research_data_leaks', 'unsecured_wifi',
            ],
            'threat_actors': ['Student_hackers', 'Credential_stuffing'],
        },
        'health': {
            'patterns': [
                'chs.dz', 'hopital', 'hospital', 'sante.gov.dz',
                'health', 'medical', 'clinique', 'eph-', 'epsp-',
                'pharmacy', 'medicament',
            ],
            'criticality': 'high',
            'compliance': ['Health_Data_Protection', 'Decree_26_07'],
            'common_vulns': [
                'patient_data_exposure', 'medical_device_security',
                'ransomware_vulnerability', 'legacy_systems',
            ],
            'threat_actors': ['Ransomware_groups', 'Data_thieves'],
        },
        'media': {
            'patterns': [
                'aps.dz', 'entv.dz', 'radioalgerie.dz', 'media',
                'press', 'news', 'echourouk', 'elwatan',
                'liberte', 'lesoirdalgerie',
            ],
            'criticality': 'medium',
            'compliance': ['Media_Regulatory_Authority'],
            'common_vulns': [
                'defacement_risk', 'ddos_vulnerability',
                'content_management_exploits',
            ],
            'threat_actors': ['Hacktivists', 'Defacement_groups'],
        },
        'commercial': {
            'patterns': [
                'shop', 'store', 'market', 'boutique', 'delivery',
                'livraison', 'commerce', 'vente', 'service',
                'digital', 'soft', 'dev',
            ],
            'criticality': 'medium',
            'compliance': [],
            'common_vulns': [
                'exposed_customer_data', 'weak_authentication',
                'payment_security', 'api_security_flaws',
            ],
            'threat_actors': ['Credential_stuffing', 'Skimming_groups'],
        },
        'hosting': {
            'patterns': [
                'host', 'server', 'cloud', 'vps', 'hebergement',
                'datacenter',
            ],
            'criticality': 'high',
            'compliance': [],
            'common_vulns': [
                'shared_hosting_risks', 'server_misconfiguration',
                'exposed_cpanel', 'weak_ftp',
            ],
            'threat_actors': ['Mass_scanners'],
        },
    }

    # ─────────────────────── Algerian ISP Networks ────────────────────

    ISP_NETWORKS: Dict[str, Dict] = {
        'Algerie_Telecom': {
            'networks': [
                '41.96.0.0/14', '105.96.0.0/13', '197.200.0.0/13',
                '129.45.0.0/16', '105.100.0.0/16', '105.101.0.0/16',
                '105.102.0.0/16', '105.103.0.0/16',
            ],
            'asn': ['AS36947', 'AS37529'],
        },
        'Mobilis': {
            'networks': ['154.121.0.0/16', '105.102.0.0/16'],
            'asn': ['AS36947'],
        },
        'Djezzy': {
            'networks': ['41.107.0.0/16', '105.235.0.0/16', '154.240.0.0/16'],
            'asn': ['AS36947'],
        },
        'Ooredoo': {
            'networks': ['41.111.0.0/16', '197.140.0.0/15', '154.247.0.0/16'],
            'asn': ['AS36884'],
        },
    }

    CITY_NETWORKS: Dict[str, List[str]] = {
        'Algiers':     ['41.96.0.0/16', '105.96.0.0/16'],
        'Oran':        ['41.97.0.0/16', '105.97.0.0/16'],
        'Constantine': ['41.98.0.0/16', '105.98.0.0/16'],
        'Annaba':      ['41.99.0.0/16', '105.99.0.0/16'],
    }

    # ─────────────────────── Compliance Frameworks ────────────────────

    COMPLIANCE_FRAMEWORKS: Dict[str, Dict] = {
        'Decree_26_07': {
            'name':         'Executive Decree No. 26-07 of 2023',
            'scope':        ['government', 'critical_infrastructure'],
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
            'name':         'Bank of Algeria Security Guidelines',
            'scope':        ['banking', 'financial_services'],
            'requirements': [
                'swift_csp_compliance',
                'multi_factor_authentication',
                'transaction_monitoring',
                'penetration_testing_annual',
            ],
        },
    }

    # ─────────────────────── Constructor ──────────────────────────────

    def __init__(self, data_dir: Optional[str] = None):
        self.data_dir = Path(data_dir) if data_dir else Path(__file__).parent / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._custom_intel = self._load_custom_intel()
        # Pre-build network objects for fast IP lookup
        self._isp_networks = self._compile_networks()

    def _load_custom_intel(self) -> Dict:
        intel_file = self.data_dir / "custom_intel.json"
        if intel_file.exists():
            try:
                with open(intel_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _compile_networks(self) -> List[tuple]:
        """Pre-compile ip_network objects for fast lookup."""
        compiled = []
        for isp_name, data in self.ISP_NETWORKS.items():
            for cidr in data['networks']:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    compiled.append((net, isp_name))
                except ValueError:
                    pass
        return compiled

    # ─────────────────────── Public API ───────────────────────────────

    def identify_target(self, target: str,
                        ip: Optional[str] = None) -> Optional['AlgerianTarget']:
        """
        Identify and classify an Algerian target.
        Returns AlgerianTarget or None if not Algerian.
        """
        target_lower = target.lower().strip()

        is_dz_domain = target_lower.endswith('.dz')
        is_dz_ip     = False
        detected_isp = 'unknown'
        detected_city: Optional[str] = None
        ip_range: Optional[str]      = None

        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                for net, isp_name in self._isp_networks:
                    if ip_obj in net:
                        is_dz_ip     = True
                        detected_isp = isp_name
                        ip_range     = str(net)
                        # City detection
                        for city, city_nets in self.CITY_NETWORKS.items():
                            if any(ip_obj in ipaddress.ip_network(cn, strict=False)
                                   for cn in city_nets):
                                detected_city = city
                                break
                        break
            except (ValueError, TypeError):
                pass

        if not is_dz_domain and not is_dz_ip:
            return None

        # Sector classification
        sector, sector_data = self._classify_sector(target_lower)

        # Criticality
        criticality = sector_data.get('criticality', 'medium')
        if sector in ('government', 'banking', 'energy'):
            high_value_kws = ['presidence', 'bank-of-algeria', 'sonatrach', 'defense']
            if any(kw in target_lower for kw in high_value_kws):
                criticality = 'critical'

        # Compliance
        compliance = list(sector_data.get('compliance', []))

        # ISP fallback from domain patterns
        if detected_isp == 'unknown':
            detected_isp = self._guess_isp_from_domain(target_lower)

        return AlgerianTarget(
            domain=target,
            ip=ip,
            sector=sector,
            criticality=criticality,
            isp=detected_isp,
            city=detected_city,
            compliance_requirements=compliance,
            common_vulnerabilities=sector_data.get('common_vulns', []),
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

    def generate_test_plan(self, target: AlgerianTarget) -> Dict:
        """Generate a prioritized security test plan for the target."""
        return {
            'target':     target.domain,
            'classification': {
                'sector':      target.sector,
                'criticality': target.criticality,
                'isp':         target.isp,
                'city':        target.city,
            },
            'compliance_requirements': target.compliance_requirements,
            'phases': [
                {
                    'name':     'reconnaissance',
                    'priority': 'critical',
                    'tests':    [
                        'dns_enumeration', 'subdomain_discovery',
                        'ip_range_mapping', 'technology_fingerprinting',
                    ],
                },
                {
                    'name':     'vulnerability_assessment',
                    'priority': 'high',
                    'tests':    target.recommended_tests,
                },
                {
                    'name':     'compliance_verification',
                    'priority': 'critical' if target.is_government else 'medium',
                    'tests':    target.compliance_requirements,
                },
            ],
            'threat_context': {
                'likely_actors':    target.threat_actors,
                'attack_scenarios': self._get_attack_scenarios(target),
            },
        }

    def check_compliance_gaps(self, finding: Dict,
                               target: AlgerianTarget) -> List[str]:
        """Map a security finding to compliance violations."""
        gaps: List[str] = []
        if 'Decree_26_07' in target.compliance_requirements:
            type_map = {
                'unencrypted_transmission': 'Decree_26_07_Art12_Encryption',
                'weak_cipher':              'Decree_26_07_Art12_Encryption',
                'authentication_bypass':    'Decree_26_07_Art8_Access_Control',
                'weak_auth':                'Decree_26_07_Art8_Access_Control',
                'insufficient_logging':     'Decree_26_07_Art15_Monitoring',
                'no_monitoring':            'Decree_26_07_Art15_Monitoring',
            }
            gap = type_map.get(finding.get('type', ''))
            if gap:
                gaps.append(gap)
        return gaps

    def get_threat_intel_summary(self, target: AlgerianTarget) -> Dict:
        """Return a threat intelligence summary for the target."""
        return {
            'geopolitical_context': {
                'country_risk':      'medium',
                'sector_targeting':  'high' if target.criticality == 'critical' else 'medium',
                'recent_campaigns':  ['Molerats_2024', 'APT-C-23_Mobile_Campaign'],
            },
            'apt_activity': {
                'active_groups': target.threat_actors,
                'ttps_observed': self._get_ttp_for_actors(target.threat_actors),
            },
            'recommendations': {
                'immediate': self._get_immediate_actions(target),
                'strategic': self._get_strategic_improvements(target),
            },
        }

    def save_observation(self, target: str, observation: Dict):
        """Append an observation to the local intelligence store."""
        obs_file = self.data_dir / "observations.jsonl"
        entry = {
            'timestamp':   datetime.now().isoformat(),
            'target':      target,
            'observation': observation,
        }
        with open(obs_file, 'a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    # ─────────────────────── Internal Helpers ─────────────────────────

    def _classify_sector(self, target_lower: str):
        """Return (sector_name, sector_data_dict)."""
        for sec_name, sec_data in self.SECTORS.items():
            for pattern in sec_data['patterns']:
                if pattern in target_lower:
                    return sec_name, sec_data
        # Default for unrecognized .dz domains
        return 'unknown', {
            'criticality': 'medium',
            'compliance':  [],
            'common_vulns': [
                'missing_security_headers', 'weak_authentication',
                'information_disclosure', 'outdated_cms',
            ],
            'threat_actors': [],
        }

    def _guess_isp_from_domain(self, domain: str) -> str:
        if any(x in domain for x in ('algerietelecom', '.at.dz', 'mobilis')):
            return 'Algerie_Telecom'
        if 'djezzy' in domain:
            return 'Djezzy'
        if 'ooredoo' in domain:
            return 'Ooredoo'
        return 'unknown'

    def _get_tests_for_sector(self, sector: str) -> List[str]:
        base = [
            'subdomain_enumeration', 'technology_fingerprinting',
            'ssl_tls_analysis', 'security_headers', 'exposed_endpoints',
        ]
        extra: Dict[str, List[str]] = {
            'government': [
                'decree_26_07_compliance', 'admin_panel_exposure',
                'information_disclosure', 'weak_authentication',
            ],
            'banking': [
                'api_security_assessment', 'mobile_app_security',
                'swift_infrastructure', 'transaction_integrity',
            ],
            'telecom': [
                'ss7_diameter_security', 'subscriber_data_protection',
                'signaling_firewall',
            ],
            'energy': [
                'scada_security', 'network_segmentation',
                'supply_chain_security',
            ],
            'education': [
                'student_data_privacy', 'research_ip_protection',
                'campus_network_security',
            ],
        }
        return base + extra.get(sector, [])

    def _get_attack_scenarios(self, target: AlgerianTarget) -> List[str]:
        scenarios: List[str] = []
        if target.is_government:
            scenarios.extend([
                'spear_phishing_officials', 'watering_hole',
                'credential_harvesting', 'data_exfiltration',
            ])
        if target.is_banking:
            scenarios.extend([
                'swift_fraud', 'card_skimming',
                'mobile_banking_trojan', 'insider_threat',
            ])
        if target.is_telecom:
            scenarios.extend([
                'ss7_interception', 'subscriber_tracking',
                'billing_system_fraud',
            ])
        return scenarios

    def _get_ttp_for_actors(self, actors: List[str]) -> List[str]:
        ttp_db: Dict[str, List[str]] = {
            'Molerats':    ['spear_phishing', 'malicious_documents', 'dropbox_abuse'],
            'APT-C-23':    ['mobile_malware', 'watering_hole', 'social_engineering'],
            'NilePhish':   ['credential_harvesting', 'web_injection', 'fake_apps'],
            'Cobalt_Group':['swift_fraud', 'spear_phishing', 'lateral_movement'],
        }
        ttps: Set[str] = set()
        for actor in actors:
            ttps.update(ttp_db.get(actor, []))
        return list(ttps)

    def _get_immediate_actions(self, target: AlgerianTarget) -> List[str]:
        actions = [
            'Enable multi-factor authentication',
            'Patch critical vulnerabilities within 24h',
            'Review access logs for anomalies',
        ]
        if target.is_government:
            actions.append('Report to CERT-DZ if system is compromised')
        return actions

    def _get_strategic_improvements(self, target: AlgerianTarget) -> List[str]:
        return [
            'Implement zero-trust architecture',
            'Establish Security Operations Center (SOC)',
            'Schedule regular penetration testing',
            'Conduct employee security awareness training',
        ]
