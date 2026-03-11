# -*- coding: utf-8 -*-
"""
cms_detector.py - Detect CMS and version from HTTP responses
Part of RECON-DZ v2
"""

import re
from typing import Dict, Optional, List
from core.async_engine import ResponseData


class CMSDetector:
    """
    Detect Content Management System and its version.
    """

    # Known CMS signatures
    SIGNATURES = {
        'WordPress': {
            'urls': ['/wp-content/', '/wp-includes/', '/wp-json/', '/wp-admin/'],
            'headers': {'x-powered-by': 'wordpress'},
            'meta': {'generator': 'wordpress'},
            'version_files': [
                '/wp-links-opml.php', '/wp-json/', '/readme.html',
                '/wp-admin/css/colors.min.css'
            ],
            'version_pattern': r'ver=([0-9.]+)'
        },
        'Joomla': {
            'urls': ['/media/system/js/', '/templates/', '/administrator/'],
            'headers': {'x-content-encoded-by': 'joomla'},
            'meta': {'generator': 'joomla'},
            'version_files': [
                '/administrator/manifests/files/joomla.xml',
                '/language/en-GB/en-GB.xml'
            ],
            'version_pattern': r'<version>([0-9.]+)</version>'
        },
        'Drupal': {
            'urls': ['/sites/default/', '/core/misc/drupal.js', '/core/'],
            'headers': {'x-generator': 'drupal'},
            'meta': {'generator': 'drupal'},
            'version_files': [
                '/core/CHANGELOG.txt', '/core/RELEASE.txt',
                '/core/lib/Drupal.php'
            ],
            'version_pattern': r'Drupal ([0-9.]+)'
        },
        'Moodle': {
            'urls': ['/theme/', '/lib/javascript.php', '/course/'],
            'headers': {},
            'meta': {'generator': 'moodle'},
            'version_files': [
                '/version.php', '/lib/version.php'
            ],
            'version_pattern': r"version\s*=\s*'([0-9.]+)"
        },
        'PrestaShop': {
            'urls': ['/modules/', '/js/jquery/plugins/', '/themes/'],
            'headers': {'powered-by': 'prestashop'},
            'meta': {'generator': 'prestashop'},
            'version_files': [
                '/install/install_version.php',
                '/config/settings.inc.php'
            ],
            'version_pattern': r'_PS_VERSION_\', \'([0-9.]+)'
        },
        'Shopify': {
            'urls': ['/cdn/shop/', '/shop/'],
            'headers': {'x-shopid': '', 'x-shopify-stage': ''},
            'meta': {},
            'version_files': [],
            'version_pattern': None
        },
        'Magento': {
            'urls': ['/skin/frontend/', '/media/catalog/', '/js/mage/'],
            'headers': {'x-magento-tags': '', 'x-magento-cache-id': ''},
            'meta': {'generator': 'magento'},
            'version_files': [
                '/magento_version', '/RELEASE_NOTES.txt'
            ],
            'version_pattern': r'Magento[^\d]*([0-9.]+)'
        },
    }

    def __init__(self):
        self.cache = {}

    async def detect(self, base_url: str, engine) -> List[Dict]:
        """
        Detect CMS by analyzing the main page and known paths.
        Returns a list of detected CMS with confidence and version.
        """
        results = []
        # First fetch the main page
        main_resp = await engine.request(base_url)
        if main_resp.status != 200:
            return []

        # Check main page content and headers
        cms_hints = self._check_response(main_resp)

        # For each candidate, try to fetch version files
        for cms_name in cms_hints:
            info = {'name': cms_name, 'confidence': 'medium', 'version': None}
            # Try to extract version from main page
            version = self._extract_version_from_response(cms_name, main_resp)
            if version:
                info['version'] = version
                info['confidence'] = 'high'
            else:
                # Try version files
                version = await self._check_version_files(cms_name, base_url, engine)
                if version:
                    info['version'] = version
                    info['confidence'] = 'high'
            results.append(info)

        return results

    def _check_response(self, resp: ResponseData) -> List[str]:
        """Return list of possible CMS names based on response."""
        candidates = []
        body_lower = resp.body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        for cms, sig in self.SIGNATURES.items():
            # Check URLs in body
            for url_pattern in sig['urls']:
                if url_pattern in body_lower:
                    candidates.append(cms)
                    break
            else:
                # Check headers
                for hdr, val in sig['headers'].items():
                    if hdr in headers_lower and (not val or val in headers_lower[hdr]):
                        candidates.append(cms)
                        break
                else:
                    # Check meta tags
                    for meta, val in sig['meta'].items():
                        pattern = rf'<meta\s+name=[\'"]{meta}[\'"]\s+content=[\'"]([^\'"]*)[\'"]'
                        match = re.search(pattern, body_lower)
                        if match and val in match.group(1).lower():
                            candidates.append(cms)
                            break

        return list(set(candidates))

    def _extract_version_from_response(self, cms: str, resp: ResponseData) -> Optional[str]:
        """Extract version from main page content if possible."""
        sig = self.SIGNATURES[cms]
        pattern = sig.get('version_pattern')
        if not pattern:
            return None
        # Try in body
        match = re.search(pattern, resp.body, re.IGNORECASE)
        if match:
            return match.group(1)
        # Try in headers
        for hdr, val in resp.headers.items():
            match = re.search(pattern, val, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    async def _check_version_files(self, cms: str, base_url: str, engine) -> Optional[str]:
        """Fetch known version files and extract version."""
        sig = self.SIGNATURES[cms]
        pattern = sig.get('version_pattern')
        if not pattern:
            return None
        for file_path in sig['version_files']:
            url = base_url.rstrip('/') + file_path
            resp = await engine.request(url)
            if resp.status == 200:
                match = re.search(pattern, resp.body, re.IGNORECASE)
                if match:
                    return match.group(1)
        return None
