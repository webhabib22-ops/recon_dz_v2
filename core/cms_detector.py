#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - CMS Detector
Fixed: PrestaShop regex escape bug, improved confidence scoring,
       added Moodle/OpenCart/Typo3, version extraction robustness
"""

import re
from typing import Dict, List, Optional
from core.async_engine import ResponseData


class CMSDetector:
    """
    Detect Content Management Systems and their versions.
    Uses multi-signal detection: HTML body, headers, meta tags, known paths.
    """

    # Confidence weights per detection method
    _CONF_URL_IN_BODY  = 60
    _CONF_HEADER       = 80
    _CONF_META_TAG     = 75
    _CONF_VERSION_FILE = 90

    SIGNATURES: Dict[str, Dict] = {
        'WordPress': {
            'url_patterns': ['/wp-content/', '/wp-includes/', '/wp-json/'],
            'header_keys':  {'x-powered-by': 'wordpress'},
            'meta_keys':    {'generator': 'wordpress'},
            'version_files': [
                '/wp-links-opml.php', '/readme.html',
                '/wp-admin/css/colors.min.css',
            ],
            'version_pattern': r'(?:ver=|wordpress[^"\']*?v?ersion\s*[:\s])([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        },
        'Joomla': {
            'url_patterns': ['/media/system/js/', '/templates/', '/administrator/'],
            'header_keys':  {'x-content-encoded-by': 'joomla'},
            'meta_keys':    {'generator': 'joomla'},
            'version_files': [
                '/administrator/manifests/files/joomla.xml',
                '/language/en-GB/en-GB.xml',
            ],
            'version_pattern': r'<version>([0-9]+\.[0-9]+(?:\.[0-9]+)?)</version>',
        },
        'Drupal': {
            'url_patterns': ['/sites/default/', '/core/misc/drupal.js', '/core/'],
            'header_keys':  {'x-generator': 'drupal'},
            'meta_keys':    {'generator': 'drupal'},
            'version_files': [
                '/core/CHANGELOG.txt', '/core/RELEASE.txt',
            ],
            'version_pattern': r'Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        },
        'Moodle': {
            'url_patterns': ['/lib/javascript.php', '/course/', '/mod/'],
            'header_keys':  {},
            'meta_keys':    {'generator': 'moodle'},
            'version_files': ['/version.php'],
            'version_pattern': r"\$version\s*=\s*'([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        },
        'PrestaShop': {
            'url_patterns': ['/modules/', '/themes/presta', '/js/jquery/plugins/'],
            'header_keys':  {'powered-by': 'prestashop'},
            'meta_keys':    {'generator': 'prestashop'},
            'version_files': ['/install/install_version.php'],
            # [FIX] Corrected escape sequence: was "PS_VERSION_\\', \\'" which is wrong
            'version_pattern': r"_PS_VERSION_['\"],\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        },
        'Shopify': {
            'url_patterns': ['/cdn/shop/', 'cdn.shopify.com'],
            'header_keys':  {'x-shopid': '', 'x-shopify-stage': ''},
            'meta_keys':    {},
            'version_files': [],
            'version_pattern': None,
        },
        'Magento': {
            'url_patterns': ['/skin/frontend/', '/media/catalog/', '/js/mage/'],
            'header_keys':  {'x-magento-tags': '', 'x-magento-cache-id': ''},
            'meta_keys':    {'generator': 'magento'},
            'version_files': ['/magento_version'],
            'version_pattern': r'Magento[^\d]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        },
        'OpenCart': {
            'url_patterns': ['/catalog/view/theme/', '/index.php?route='],
            'header_keys':  {},
            'meta_keys':    {'generator': 'opencart'},
            'version_files': ['/system/startup.php'],
            'version_pattern': r"VERSION\s*[,=]\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        },
        'TYPO3': {
            'url_patterns': ['/typo3/', '/typo3conf/', '/fileadmin/'],
            'header_keys':  {},
            'meta_keys':    {'generator': 'typo3'},
            'version_files': ['/typo3/sysext/core/ext_emconf.php'],
            'version_pattern': r"version.*?['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        },
        'Laravel': {
            'url_patterns':  [],
            'header_keys':   {'x-powered-by': 'laravel'},
            'meta_keys':     {},
            'version_files': [],
            'version_pattern': r'Laravel/([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'cookie_patterns': ['laravel_session'],
        },
        'Django': {
            'url_patterns':  [],
            'header_keys':   {'x-framework': 'django'},
            'meta_keys':     {},
            'version_files': [],
            'version_pattern': None,
            'body_patterns':   ['csrfmiddlewaretoken', '__django'],
        },
    }

    def __init__(self):
        self._cache: Dict[str, List[Dict]] = {}

    async def detect(self, base_url: str, engine) -> List[Dict]:
        """
        Detect CMS(es) at base_url using the provided engine.
        Returns a list of dicts: {name, version, confidence, methods}.
        """
        cache_key = base_url.rstrip('/')
        if cache_key in self._cache:
            return self._cache[cache_key]

        main_resp = await engine.request(base_url)
        if main_resp.status == 0:
            return []

        # Score each candidate
        scores: Dict[str, Dict] = {}

        for cms_name, sig in self.SIGNATURES.items():
            score, methods = self._score_response(cms_name, sig, main_resp)
            if score > 0:
                scores[cms_name] = {'score': score, 'methods': methods, 'version': None}

        if not scores:
            return []

        # Try to extract versions for all candidates
        for cms_name, data in scores.items():
            version = self._extract_version_from_response(cms_name, main_resp)
            if version:
                data['version']  = version
                data['score']   += 20  # boost for version found
                data['methods'].append('version_from_body')
            else:
                v = await self._check_version_files(cms_name, base_url, engine)
                if v:
                    data['version']  = v
                    data['score']   += 30
                    data['methods'].append('version_from_file')

        # Build result list, highest score first
        results = []
        for cms_name, data in sorted(scores.items(),
                                     key=lambda x: x[1]['score'], reverse=True):
            confidence = 'high' if data['score'] >= 80 else (
                          'medium' if data['score'] >= 50 else 'low')
            results.append({
                'name':       cms_name,
                'version':    data['version'],
                'confidence': confidence,
                'score':      data['score'],
                'methods':    data['methods'],
            })

        self._cache[cache_key] = results
        return results

    # ─────────────────── Detection Helpers ────────────────────────────

    def _score_response(self, cms: str, sig: Dict,
                        resp: ResponseData):
        """Return (score, list_of_matched_methods)."""
        score   = 0
        methods: List[str] = []
        body_lower    = resp.body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}

        # 1. URL patterns in body
        for url_pat in sig.get('url_patterns', []):
            if url_pat.lower() in body_lower:
                score += self._CONF_URL_IN_BODY
                methods.append(f'body_url:{url_pat}')
                break

        # 2. Response headers
        for hdr, val in sig.get('header_keys', {}).items():
            hdr_l = hdr.lower()
            if hdr_l in headers_lower:
                if not val or val.lower() in headers_lower[hdr_l]:
                    score += self._CONF_HEADER
                    methods.append(f'header:{hdr}')
                    break

        # 3. Meta generator tag
        for meta_name, meta_val in sig.get('meta_keys', {}).items():
            pattern = (rf'<meta\s[^>]*name=["\']' + re.escape(meta_name) +
                       r'["\'][^>]*content=["\']([^"\']*)["\']')
            m = re.search(pattern, body_lower, re.IGNORECASE)
            if not m:
                pattern2 = (rf'<meta\s[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']' +
                            re.escape(meta_name) + r'["\']')
                m = re.search(pattern2, body_lower, re.IGNORECASE)
            if m and meta_val.lower() in m.group(1).lower():
                score += self._CONF_META_TAG
                methods.append(f'meta:{meta_name}')
                break

        # 4. Cookie patterns (e.g. Laravel session)
        cookie_hdr = headers_lower.get('set-cookie', '')
        for cookie_pat in sig.get('cookie_patterns', []):
            if cookie_pat.lower() in cookie_hdr:
                score += 50
                methods.append(f'cookie:{cookie_pat}')

        # 5. Body keyword patterns
        for body_pat in sig.get('body_patterns', []):
            if body_pat.lower() in body_lower:
                score += 40
                methods.append(f'body_kw:{body_pat}')
                break

        return score, methods

    def _extract_version_from_response(self, cms: str,
                                        resp: ResponseData) -> Optional[str]:
        """Try to extract version from the main page."""
        pattern = self.SIGNATURES[cms].get('version_pattern')
        if not pattern:
            return None
        # Body search
        m = re.search(pattern, resp.body, re.IGNORECASE)
        if m:
            return m.group(1)
        # Header search
        for val in resp.headers.values():
            m = re.search(pattern, val, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    async def _check_version_files(self, cms: str, base_url: str,
                                    engine) -> Optional[str]:
        """Fetch known version files and extract version string."""
        sig     = self.SIGNATURES[cms]
        pattern = sig.get('version_pattern')
        if not pattern:
            return None
        for file_path in sig.get('version_files', []):
            url  = base_url.rstrip('/') + file_path
            resp = await engine.request(url)
            if resp.status == 200 and resp.body:
                m = re.search(pattern, resp.body, re.IGNORECASE)
                if m:
                    return m.group(1)
        return None
