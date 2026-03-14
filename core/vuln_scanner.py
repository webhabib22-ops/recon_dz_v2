#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Vulnerability Scanner (NEW MODULE)
Passive and semi-active vulnerability checks:
- Security header analysis
- SSL/TLS weakness detection
- Sensitive file exposure
- Directory listing detection
- Default credentials exposure
- API endpoint discovery
- Information disclosure patterns
"""

import re
import asyncio
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

from core.async_engine import AsyncReconEngine, ResponseData


@dataclass
class Finding:
    """A single security finding."""
    name:           str
    severity:       str          # critical | high | medium | low | info
    category:       str          # exposure | misconfiguration | version | compliance
    detail:         str
    url:            Optional[str] = None
    recommendation: str           = ""
    cve:            Optional[str] = None
    compliance:     List[str]     = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'name':           self.name,
            'severity':       self.severity,
            'category':       self.category,
            'detail':         self.detail,
            'url':            self.url,
            'recommendation': self.recommendation,
            'cve':            self.cve,
            'compliance':     self.compliance,
        }


class VulnScanner:
    """
    Semi-passive vulnerability scanner.
    Checks for common misconfigurations and exposures.
    """

    # Sensitive paths that should NOT be publicly accessible
    # (Base list, will be extended dynamically if server technology is known)
    SENSITIVE_PATHS = [
        # Version control
        '/.git/HEAD', '/.git/config', '/.svn/entries',
        '/.hg/hgrc', '/.bzr/branch/format',
        # Config & credentials
        '/.env', '/.env.local', '/.env.production',
        '/config.php', '/wp-config.php', '/configuration.php',
        '/settings.php', '/config.yml', '/config.yaml',
        '/database.yml', '/secrets.yml', '/credentials.yml',
        # Backup files
        '/backup.sql', '/backup.zip', '/dump.sql',
        '/db.sql', '/database.sql', '/site.zip',
        # Admin panels
        '/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/',
        '/cpanel/', '/webadmin/', '/siteadmin/', '/manage/',
        # Docker / Infrastructure
        '/Dockerfile', '/docker-compose.yml', '/.dockerenv',
        # API docs
        '/swagger.json', '/swagger.yaml', '/api/swagger',
        '/openapi.json', '/api-docs', '/docs/api',
        # Log files
        '/error.log', '/access.log', '/debug.log', '/app.log',
        # PHP info
        '/phpinfo.php', '/info.php', '/test.php',
        # Monitoring
        '/metrics', '/health', '/actuator', '/actuator/env',
        '/actuator/mappings', '/status',
        # Algerian-specific paths
        '/portail/', '/extranet/', '/intranet/',
    ]

    # Headers that should be present on production sites
    REQUIRED_HEADERS = {
        'strict-transport-security': {
            'label':  'HTTP Strict Transport Security (HSTS)',
            'sev':    'high',
            'detail': 'HSTS forces browsers to use HTTPS. Missing = easy SSL stripping.',
            'rec':    'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'compliance': ['Decree_26_07_Art12', 'PCI_DSS_6.5.10'],
        },
        'content-security-policy': {
            'label':  'Content Security Policy (CSP)',
            'sev':    'medium',
            'detail': 'CSP prevents XSS by restricting resource origins.',
            'rec':    "Add: Content-Security-Policy: default-src 'self'",
        },
        'x-frame-options': {
            'label':  'X-Frame-Options',
            'sev':    'medium',
            'detail': 'Missing X-Frame-Options allows clickjacking attacks.',
            'rec':    'Add: X-Frame-Options: SAMEORIGIN',
        },
        'x-content-type-options': {
            'label':  'X-Content-Type-Options',
            'sev':    'low',
            'detail': 'Missing header allows MIME-type sniffing attacks.',
            'rec':    'Add: X-Content-Type-Options: nosniff',
        },
        'referrer-policy': {
            'label':  'Referrer-Policy',
            'sev':    'low',
            'detail': 'Missing Referrer-Policy may leak sensitive URL information.',
            'rec':    'Add: Referrer-Policy: strict-origin-when-cross-origin',
        },
    }

    # Server version disclosure patterns
    VERSION_DISCLOSURE = [
        (r'Apache/([0-9]+\.[0-9]+\.[0-9]+)',  'Apache'),
        (r'nginx/([0-9]+\.[0-9]+\.[0-9]+)',   'Nginx'),
        (r'PHP/([0-9]+\.[0-9]+\.[0-9]+)',     'PHP'),
        (r'OpenSSL/([0-9]+\.[0-9]+\.[0-9]+)', 'OpenSSL'),
        (r'Microsoft-IIS/([0-9]+\.[0-9]+)',   'IIS'),
        (r'Tomcat/([0-9]+\.[0-9]+\.[0-9]+)',  'Tomcat'),
    ]

    # Known outdated / EOL versions
    EOL_VERSIONS = {
        'Apache':  [('2.2', 'EOL since 2017'), ('2.4.0', 'Vulnerable to CVE-2021-41773')],
        'PHP':     [('5.',  'EOL since 2019'), ('7.0', 'EOL'), ('7.1', 'EOL'), ('7.2', 'EOL')],
        'Nginx':   [('1.6', 'EOL'), ('1.8', 'EOL'), ('1.10', 'EOL')],
        'OpenSSL': [('1.0', 'EOL since 2019'), ('1.1.0', 'EOL')],
    }

    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine

    async def scan(self, base_url: str, main_response: ResponseData,
                   algeria_info=None, server_tech: Optional[Dict] = None) -> List[Finding]:
        """
        Run all vulnerability checks against base_url.
        - algeria_info: object from AlgeriaThreatDatabase.identify_target()
        - server_tech:  dict with detected technologies (e.g. {'server': 'Apache', 'php_version': '8.2'})
        Returns a list of Finding objects sorted by severity.
        """
        findings: List[Finding] = []

        # 1. Security header analysis
        findings.extend(self._check_security_headers(main_response))

        # 2. Server version disclosure
        findings.extend(self._check_version_disclosure(main_response))

        # 3. Sensitive file exposure (concurrent) – with technology‑aware paths
        file_findings = await self._check_sensitive_files(base_url, server_tech)
        findings.extend(file_findings)

        # 4. Directory listing
        findings.extend(await self._check_directory_listing(base_url))

        # 5. Mixed content / HTTP on HTTPS site
        findings.extend(self._check_mixed_content(main_response))

        # 6. Cookie security flags
        findings.extend(self._check_cookie_flags(main_response))

        # 7. Algeria-specific compliance – FIX: safe access to attributes
        if algeria_info:
            findings.extend(self._check_algeria_compliance(main_response, algeria_info))

        # 8. Information disclosure in response
        findings.extend(self._check_info_disclosure(main_response))

        # Sort: critical → high → medium → low → info
        _sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        findings.sort(key=lambda f: _sev_order.get(f.severity, 5))

        return findings

    # ──────────────── Check Methods ───────────────────────────────────

    def _check_security_headers(self, resp: ResponseData) -> List[Finding]:
        findings: List[Finding] = []
        for hdr, meta in self.REQUIRED_HEADERS.items():
            if not resp.get_header(hdr):
                findings.append(Finding(
                    name=f"Missing Security Header: {meta['label']}",
                    severity=meta['sev'],
                    category='misconfiguration',
                    detail=meta['detail'],
                    url=resp.url,
                    recommendation=meta['rec'],
                    compliance=meta.get('compliance', []),
                ))
        return findings

    def _check_version_disclosure(self, resp: ResponseData) -> List[Finding]:
        findings: List[Finding] = []
        server_header = resp.get_header('server')
        powered_by    = resp.get_header('x-powered-by')
        combined      = f"{server_header} {powered_by}"

        for pattern, product in self.VERSION_DISCLOSURE:
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                version = m.group(1)
                findings.append(Finding(
                    name=f"Server Version Disclosed: {product}",
                    severity='low',
                    category='exposure',
                    detail=f"{product} version {version} revealed in HTTP headers.",
                    url=resp.url,
                    recommendation="Remove or obscure version information from HTTP headers.",
                ))
                # Check if EOL
                for (eol_prefix, eol_note) in self.EOL_VERSIONS.get(product, []):
                    if version.startswith(eol_prefix):
                        findings.append(Finding(
                            name=f"End-of-Life Software: {product} {version}",
                            severity='high',
                            category='version',
                            detail=f"{product} {version} is {eol_note} and receives no security patches.",
                            url=resp.url,
                            recommendation=f"Upgrade {product} to the latest stable version immediately.",
                        ))
        return findings

    async def _check_sensitive_files(self, base_url: str,
                                      server_tech: Optional[Dict] = None) -> List[Finding]:
        """Check for exposed sensitive files concurrently."""
        # Start with the base SENSITIVE_PATHS
        paths_to_test = list(self.SENSITIVE_PATHS)

        # --- Stack‑Specific Probing (point 2) ---
        # If we know the server is Apache / PHP, add extra PHP‑specific paths
        if server_tech:
            server = server_tech.get('server', '').lower()
            php_ver = server_tech.get('php_version', '')
            if 'apache' in server or php_ver:
                extra_php_paths = [
                    '/phpinfo.php', '/info.php', '/test.php',
                    '/.user.ini', '/php.ini', '/.htaccess',
                    '/phpmyadmin/scripts/setup.php', '/pma/',
                ]
                # Avoid duplicates
                for p in extra_php_paths:
                    if p not in paths_to_test:
                        paths_to_test.append(p)

        findings: List[Finding] = []
        sem   = asyncio.Semaphore(20)
        tasks = [
            self._probe_path(base_url, path, sem)
            for path in paths_to_test
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Finding):
                findings.append(res)
        return findings

    async def _probe_path(self, base_url: str, path: str,
                           sem: asyncio.Semaphore) -> Optional[Finding]:
        """Probe a single path and return a Finding if exposed."""
        async with sem:
            url  = base_url.rstrip('/') + path
            resp = await self.engine.request(url)
            if resp.status in (200, 403):
                sev = 'critical' if any(
                    x in path for x in
                    ['.env', 'wp-config', '.git', 'config.php', 'backup', '.sql']
                ) else 'high' if any(
                    x in path for x in ['admin', 'phpmyadmin', 'cpanel']
                ) else 'medium'

                if resp.status == 200:
                    label = "Exposed Sensitive File"
                else:
                    label = "Access Restricted (may exist)"
                    sev   = 'low' if sev == 'medium' else sev

                return Finding(
                    name=label,
                    severity=sev,
                    category='exposure',
                    detail=f"Path {path} returned HTTP {resp.status} ({len(resp.body)} bytes).",
                    url=url,
                    recommendation=f"Restrict access to {path} via server configuration or .htaccess.",
                )
        return None

    async def _check_directory_listing(self, base_url: str) -> List[Finding]:
        """Check common directories for directory listing."""
        findings: List[Finding] = []
        dirs = ['/uploads/', '/images/', '/files/', '/static/',
                '/assets/', '/backup/', '/logs/', '/tmp/']
        sem   = asyncio.Semaphore(10)
        tasks = [self._probe_dir_listing(base_url, d, sem) for d in dirs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Finding):
                findings.append(res)
        return findings

    async def _probe_dir_listing(self, base_url: str, path: str,
                                  sem: asyncio.Semaphore) -> Optional[Finding]:
        async with sem:
            url  = base_url.rstrip('/') + path
            resp = await self.engine.request(url)
            if resp.status == 200:
                body_lower = resp.body.lower()
                if any(kw in body_lower for kw in
                       ['index of ', 'directory listing', 'parent directory']):
                    return Finding(
                        name="Directory Listing Enabled",
                        severity='medium',
                        category='misconfiguration',
                        detail=f"Directory listing is enabled at {path}",
                        url=url,
                        recommendation="Disable directory listing: Options -Indexes (Apache) or autoindex off (Nginx).",
                    )
        return None

    def _check_mixed_content(self, resp: ResponseData) -> List[Finding]:
        findings: List[Finding] = []
        if resp.url.startswith('https') and resp.status != 0:
            body = resp.body[:20000]
            http_resources = re.findall(
                r'(?:src|href|action)\s*=\s*["\']http://[^"\']+', body, re.IGNORECASE
            )
            if http_resources:
                findings.append(Finding(
                    name="Mixed Content (HTTP resources on HTTPS page)",
                    severity='medium',
                    category='misconfiguration',
                    detail=f"Found {len(http_resources)} HTTP resource(s) on HTTPS page.",
                    url=resp.url,
                    recommendation="Replace all HTTP resource URLs with HTTPS equivalents.",
                ))
        return findings

    def _check_cookie_flags(self, resp: ResponseData) -> List[Finding]:
        findings: List[Finding] = []
        set_cookie = resp.get_header('set-cookie')
        if not set_cookie:
            return findings

        issues = []
        if 'httponly' not in set_cookie.lower():
            issues.append('HttpOnly flag missing (XSS can steal cookies)')
        if 'secure' not in set_cookie.lower() and resp.url.startswith('https'):
            issues.append('Secure flag missing (cookie may be sent over HTTP)')
        if 'samesite' not in set_cookie.lower():
            issues.append('SameSite flag missing (CSRF risk)')

        if issues:
            findings.append(Finding(
                name="Insecure Cookie Configuration",
                severity='medium',
                category='misconfiguration',
                detail='; '.join(issues),
                url=resp.url,
                recommendation="Set HttpOnly, Secure, and SameSite=Strict on all sensitive cookies.",
            ))
        return findings

    def _check_algeria_compliance(self, resp: ResponseData,
                                   algeria_info) -> List[Finding]:
        """Check Algerian regulatory compliance requirements."""
        findings: List[Finding] = []

        # FIX: Use getattr to avoid AttributeError when algeria_info lacks the attributes
        is_gov = getattr(algeria_info, 'is_government', False)
        is_bank = getattr(algeria_info, 'is_banking', False)

        if is_gov:
            if not resp.get_header('strict-transport-security'):
                findings.append(Finding(
                    name="Decree 26-07 Violation: No HSTS",
                    severity='critical',
                    category='compliance',
                    detail="Government sites must enforce HTTPS per Decree 26-07 Article 12.",
                    url=resp.url,
                    recommendation="Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    compliance=['Decree_26_07_Article_12'],
                ))
            if resp.protocol == 'http':
                findings.append(Finding(
                    name="Decree 26-07 Violation: Site Not HTTPS",
                    severity='critical',
                    category='compliance',
                    detail="Government sites must use encrypted transport (HTTPS).",
                    url=resp.url,
                    recommendation="Enable HTTPS and redirect all HTTP traffic.",
                    compliance=['Decree_26_07_Article_12'],
                ))

        if is_bank:
            if not resp.get_header('content-security-policy'):
                findings.append(Finding(
                    name="PCI-DSS Violation: No Content Security Policy",
                    severity='high',
                    category='compliance',
                    detail="Banking sites require CSP to prevent XSS attacks per PCI-DSS.",
                    url=resp.url,
                    recommendation="Implement a strict Content-Security-Policy.",
                    compliance=['PCI_DSS_6.5.10', 'Bank_of_Algeria_Circulars'],
                ))

        return findings

    def _check_info_disclosure(self, resp: ResponseData) -> List[Finding]:
        """Detect information disclosure patterns in the response body."""
        findings: List[Finding] = []
        body = resp.body[:30000]

        patterns = [
            (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{4,})',
             'Password Disclosed in Page', 'critical'),
            (r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\']([a-zA-Z0-9_\-]{16,})',
             'API Key Disclosed in Page', 'critical'),
            (r'(?:mysql|postgresql|mssql|mongodb)://[^\s"\'<>]+',
             'Database Connection String Exposed', 'critical'),
            (r'stack trace|traceback|exception in thread|at java\.',
             'Stack Trace / Error Disclosure', 'medium'),
            (r'(?:sql syntax|mysql_fetch|ora-[0-9]{5}|sqlite3\.)',
             'SQL Error Message Disclosed', 'high'),
            (r'(?:debug\s*=\s*true|app\.debug\s*=\s*true)',
             'Debug Mode Enabled', 'high'),
        ]

        for pattern, name, sev in patterns:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                findings.append(Finding(
                    name=name,
                    severity=sev,
                    category='exposure',
                    detail=f"Sensitive pattern detected in response body.",
                    url=resp.url,
                    recommendation="Remove sensitive information from public responses.",
                ))

        return findings
