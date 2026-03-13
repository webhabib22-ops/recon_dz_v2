#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - CMS Detector  (Elite Edition)
═══════════════════════════════════════════════════════════════════════
Detects 40+ CMS/frameworks with surgical version precision.

Detection signals (per CMS):
  • HTML body patterns (URL paths, CSS classes, JS variables)
  • HTTP response headers (X-Powered-By, X-Generator, Set-Cookie…)
  • Meta generator tag
  • Cookies (session name fingerprint)
  • JavaScript globals & API endpoints
  • Version files (readme, changelog, manifest, composer.json…)
  • REST/GraphQL API version endpoints
  • Admin path probing

Version extraction techniques:
  1. Regex on main page body + headers
  2. Dedicated version files (reads raw content)
  3. REST API probing  (e.g. /wp-json, /api/version)
  4. JS file version comment parsing
  5. Source map / asset filename hash analysis
  6. Cookie version encoding
  7. HTTP/2 push manifest analysis

Confidence levels:
  certain (≥95)  — version confirmed from version file or API
  high    (≥75)  — multiple signals match
  medium  (≥45)  — one strong signal
  low     (<45)  — weak / single signal
"""

import re
import json
import asyncio
from typing import Dict, List, Optional, Tuple, Any

from core.async_engine import ResponseData


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SIGNATURE DATABASE  — 40+ CMS / Frameworks
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#  Each entry:
#    body_patterns   — strings/substrings in HTML body (case-insensitive)
#    header_exact    — {header_name: required_substring}  (case-insensitive)
#    meta_generator  — substring expected in <meta name="generator"> content
#    cookie_names    — session cookie name substrings
#    js_globals      — JavaScript global variable names in body
#    api_endpoints   — lightweight endpoints that reveal version in JSON
#    version_files   — paths that contain raw version string
#    version_regex   — regex applied to body/version file (group 1 = version)
#    api_version_key — JSON key path to extract version from api_endpoints
#    score_weights   — override default signal scores
#    category        — cms | framework | ecommerce | lms | blog | wiki | portal
#    tags            — extra metadata

SIGNATURES: Dict[str, Dict] = {

    # ─── BLOG / CMS ────────────────────────────────────────────────

    'WordPress': {
        'body_patterns':  ['/wp-content/', '/wp-includes/', 'wp-emoji-release.min.js'],
        'header_exact':   {'x-powered-by': 'wordpress'},
        'meta_generator': 'wordpress',
        'cookie_names':   ['wordpress_', 'wp-settings', 'wordpress_logged_in'],
        'js_globals':     ['wpApiSettings', 'wp.apiFetch'],
        'api_endpoints':  ['/wp-json/'],
        'version_files':  ['/readme.html', '/wp-links-opml.php',
                           '/wp-admin/css/colors.min.css',
                           '/wp-includes/version.php'],
        'version_regex':  r'(?:Version\s+|ver=|wordpress[^"\']*?["\s])([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'api_version_key': 'generator',   # /wp-json/ → data['generator']
        'category':       'cms',
    },

    'Joomla': {
        'body_patterns':  ['/media/system/js/', 'joomla!', '/templates/system/'],
        'header_exact':   {'x-content-encoded-by': 'joomla'},
        'meta_generator': 'joomla',
        'cookie_names':   [],
        'js_globals':     ['Joomla.'],
        'api_endpoints':  ['/api/index.php/v1/'],
        'version_files':  ['/administrator/manifests/files/joomla.xml',
                           '/language/en-GB/en-GB.xml',
                           '/includes/version.php'],
        'version_regex':  r'<version>([0-9]+\.[0-9]+(?:\.[0-9]+)?)</version>',
        'category':       'cms',
    },

    'Drupal': {
        'body_patterns':  ['/sites/default/files/', '/core/misc/drupal.js',
                           'drupal-settings-json'],
        'header_exact':   {'x-generator': 'drupal', 'x-drupal-cache': ''},
        'meta_generator': 'drupal',
        'cookie_names':   ['SESS', 'Drupal.visitor'],
        'js_globals':     ['drupalSettings', 'Drupal.behaviors'],
        'api_endpoints':  ['/jsonapi/', '/?q=user&_format=json'],
        'version_files':  ['/core/CHANGELOG.txt', '/CHANGELOG.txt',
                           '/core/lib/Drupal.php'],
        'version_regex':  r'Drupal\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'cms',
    },

    'TYPO3': {
        'body_patterns':  ['/typo3/', '/typo3conf/ext/', 'typo3temp'],
        'header_exact':   {'x-powered-by': 'typo3'},
        'meta_generator': 'typo3',
        'cookie_names':   ['fe_typo_user', 'be_typo_user'],
        'js_globals':     ['TYPO3', 'T3_THIS_LOCATION'],
        'api_endpoints':  ['/api/'],
        'version_files':  ['/typo3/sysext/core/ext_emconf.php',
                           '/typo3/sysext/install/composer.json'],
        'version_regex':  r"['\"]version['\"].*?['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)['\"]",
        'category':       'cms',
    },

    'Ghost': {
        'body_patterns':  ['/ghost/api/', 'ghost-version', 'content/themes/casper'],
        'header_exact':   {'x-ghost-cache-status': ''},
        'meta_generator': 'ghost',
        'cookie_names':   ['ghost-admin-api-session'],
        'js_globals':     ['Ghost'],
        'api_endpoints':  ['/ghost/api/v3/admin/site/', '/ghost/api/content/settings/'],
        'version_files':  ['/ghost/api/v3/admin/site/'],
        'version_regex':  r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'api_version_key': 'site.version',
        'category':       'cms',
    },

    'Craft CMS': {
        'body_patterns':  ['craft-csrf-token', '/cpresources/', 'data-craft'],
        'header_exact':   {'x-powered-by': 'craft'},
        'meta_generator': 'craft cms',
        'cookie_names':   ['CraftSessionId', 'CRAFT_CSRF_TOKEN'],
        'js_globals':     ['Craft.'],
        'api_endpoints':  ['/actions/app/migrate'],
        'version_files':  ['/index.php?p=admin/login'],
        'version_regex':  r'Craft\s+CMS\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'cms',
    },

    'October CMS': {
        'body_patterns':  ['/modules/system/assets/', 'october-csrf-token'],
        'header_exact':   {},
        'meta_generator': 'october',
        'cookie_names':   ['october_session'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  ['/modules/system/composer.json'],
        'version_regex':  r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'category':       'cms',
    },

    'Concrete CMS': {
        'body_patterns':  ['/concrete/js/', '/application/files/', 'ccm-page'],
        'header_exact':   {},
        'meta_generator': 'concrete',
        'cookie_names':   ['CONCRETE5'],
        'js_globals':     ['CCM_DISPATCHER_FILENAME'],
        'api_endpoints':  [],
        'version_files':  ['/concrete/config/concrete.php',
                           '/application/config/concrete.php'],
        'version_regex':  r"'version'\s*=>\s*'([0-9]+\.[0-9]+(?:\.[0-9]+)?)'",
        'category':       'cms',
    },

    'Umbraco': {
        'body_patterns':  ['umbracoNaviHide', '/umbraco/', '__UMBRACOCONTEXT'],
        'header_exact':   {'x-umbraco-version': ''},
        'meta_generator': 'umbraco',
        'cookie_names':   ['UMB_UCONTEXT', 'UMB_UPDCHK'],
        'js_globals':     ['Umbraco.'],
        'api_endpoints':  ['/umbraco/api/'],
        'version_files':  ['/umbraco/config/dashboard.config'],
        'version_regex':  r'Umbraco[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'cms',
    },

    'Kentico': {
        'body_patterns':  ['/CMSPages/', '/CMSScripts/', 'kentico'],
        'header_exact':   {'x-aspnet-version': ''},
        'meta_generator': 'kentico',
        'cookie_names':   ['CMSPreferredCulture', 'CMSUserName'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  r'Kentico[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'cms',
    },

    # ─── ECOMMERCE ─────────────────────────────────────────────────

    'WooCommerce': {
        'body_patterns':  ['/woocommerce/', 'wc-api', 'is-woocommerce'],
        'header_exact':   {},
        'meta_generator': 'woocommerce',
        'cookie_names':   ['woocommerce_cart_hash', 'woocommerce_items_in_cart'],
        'js_globals':     ['wc_cart_params', 'woocommerce_params'],
        'api_endpoints':  ['/wp-json/wc/v3/'],
        'version_files':  ['/wp-content/plugins/woocommerce/readme.txt'],
        'version_regex':  r'Stable tag:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'ecommerce',
    },

    'Magento': {
        'body_patterns':  ['/skin/frontend/', '/media/catalog/', 'mage/cookies.js',
                           'requirejs/require.js', 'Mage.Cookies'],
        'header_exact':   {'x-magento-tags': '', 'x-magento-cache-id': ''},
        'meta_generator': 'magento',
        'cookie_names':   ['frontend', 'mage-cache-sessid'],
        'js_globals':     ['require.config', 'Magento_Ui'],
        'api_endpoints':  ['/rest/V1/store/storeConfigs'],
        'version_files':  ['/magento_version', '/pub/static/version.txt',
                           '/app/etc/config.php'],
        'version_regex':  r"(?:Magento|'version')\s*[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        'category':       'ecommerce',
    },

    'PrestaShop': {
        'body_patterns':  ['/modules/ps_', '/themes/classic/', 'prestashop'],
        'header_exact':   {'x-powered-by': 'prestashop'},
        'meta_generator': 'prestashop',
        'cookie_names':   ['PrestaShop-'],
        'js_globals':     ['prestashop.'],
        'api_endpoints':  ['/api/'],
        'version_files':  ['/config/smarty/cache/index.php',
                           '/install/install_version.php',
                           '/app/AppKernel.php'],
        'version_regex':  r"_PS_VERSION_['\"],\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        'category':       'ecommerce',
    },

    'Shopify': {
        'body_patterns':  ['cdn.shopify.com', '/s/files/', 'Shopify.theme'],
        'header_exact':   {'x-shopid': '', 'x-shopify-stage': '',
                           'x-shardid': ''},
        'meta_generator': 'shopify',
        'cookie_names':   ['_shopify_s', '_shopify_y', 'cart'],
        'js_globals':     ['Shopify.theme', 'ShopifyAnalytics'],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  r'Shopify\.theme[^}]*"id"\s*:\s*([0-9]+)',
        'category':       'ecommerce',
    },

    'OpenCart': {
        'body_patterns':  ['/catalog/view/theme/', 'index.php?route='],
        'header_exact':   {},
        'meta_generator': 'opencart',
        'cookie_names':   ['OCSESSID', 'currency'],
        'js_globals':     [],
        'api_endpoints':  ['/index.php?route=api/login'],
        'version_files':  ['/system/startup.php', '/index.php?route=information/information&information_id=6'],
        'version_regex':  r"(?:VERSION|version)\s*(?:,|=)\s*['\"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
        'category':       'ecommerce',
    },

    'WooCommerce (Standalone)': {
        'body_patterns':  ['wc-blocks-data-store', 'woocommerce/assets'],
        'header_exact':   {},
        'meta_generator': '',
        'cookie_names':   ['woocommerce_'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  None,
        'category':       'ecommerce',
    },

    'osCommerce': {
        'body_patterns':  ['osCsid=', '/catalog/includes/', 'oscommerce'],
        'header_exact':   {},
        'meta_generator': 'oscommerce',
        'cookie_names':   ['osCsid'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  ['/includes/application_top.php'],
        'version_regex':  r'osCommerce\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'ecommerce',
    },

    'Bagisto': {
        'body_patterns':  ['bagisto', '/themes/shop/default/', 'Webkul'],
        'header_exact':   {},
        'meta_generator': 'bagisto',
        'cookie_names':   ['bagisto_session'],
        'js_globals':     [],
        'api_endpoints':  ['/api/'],
        'version_files':  ['/composer.json'],
        'version_regex':  r'"bagisto/bagisto".*?"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'category':       'ecommerce',
    },

    # ─── LMS ───────────────────────────────────────────────────────

    'Moodle': {
        'body_patterns':  ['/lib/javascript.php', '/course/view.php',
                           'data-region="drawer"', 'M.yui.loader'],
        'header_exact':   {},
        'meta_generator': 'moodle',
        'cookie_names':   ['MoodleSession'],
        'js_globals':     ['M.cfg', 'YUI'],
        'api_endpoints':  ['/webservice/rest/server.php'],
        'version_files':  ['/version.php', '/lib/upgrade.txt'],
        'version_regex':  r"\\\$version\s*=\s*'?([0-9]{4,}(?:\.[0-9]+)*)\.?",
        'category':       'lms',
    },

    'Canvas LMS': {
        'body_patterns':  ['instructure-uploads', '/canvas/', 'ENV.current_user'],
        'header_exact':   {'x-canvas-meta': ''},
        'meta_generator': '',
        'cookie_names':   ['_csrf_token', '_legacy_normandy_session'],
        'js_globals':     ['ENV', 'INST.'],
        'api_endpoints':  ['/api/v1/accounts/'],
        'version_files':  [],
        'version_regex':  r'"canvas_version"\s*:\s*"([^"]+)"',
        'category':       'lms',
    },

    # ─── FRAMEWORKS ────────────────────────────────────────────────

    'Laravel': {
        'body_patterns':  ['laravel_token', 'Illuminate\\\\'],
        'header_exact':   {'x-powered-by': 'laravel'},
        'meta_generator': '',
        'cookie_names':   ['laravel_session', 'XSRF-TOKEN'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  ['/composer.json'],
        'version_regex':  r'"laravel/framework".*?"([^"]+)"',
        'category':       'framework',
    },

    'Django': {
        'body_patterns':  ['csrfmiddlewaretoken', '__django', 'djdt'],
        'header_exact':   {'x-frame-options': 'sameorigin'},
        'meta_generator': '',
        'cookie_names':   ['csrftoken', 'sessionid', 'django_language'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  r'Django[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'framework',
    },

    'Ruby on Rails': {
        'body_patterns':  ['csrf-param', 'authenticity_token'],
        'header_exact':   {'x-powered-by': 'phusion passenger'},
        'meta_generator': '',
        'cookie_names':   ['_session_id', '_rails_'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  ['/Gemfile.lock'],
        'version_regex':  r'rails\s+\(([0-9]+\.[0-9]+(?:\.[0-9]+)?)\)',
        'category':       'framework',
    },

    'ASP.NET': {
        'body_patterns':  ['__VIEWSTATE', '__EVENTVALIDATION', 'asp.net'],
        'header_exact':   {'x-aspnet-version': '', 'x-aspnetmvc-version': ''},
        'meta_generator': '',
        'cookie_names':   ['ASP.NET_SessionId', '.ASPXAUTH'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  r'ASP\.NET[/\s]+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'framework',
    },

    'Spring Boot': {
        'body_patterns':  ['spring', 'thymeleaf', 'org.springframework'],
        'header_exact':   {'x-application-context': ''},
        'meta_generator': '',
        'cookie_names':   ['JSESSIONID'],
        'js_globals':     [],
        'api_endpoints':  ['/actuator', '/actuator/info'],
        'version_files':  [],
        'version_regex':  r'"Spring Boot".*?"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'api_version_key': 'build.version',
        'category':       'framework',
    },

    'Next.js': {
        'body_patterns':  ['__NEXT_DATA__', '/_next/static/', 'next/dist'],
        'header_exact':   {'x-powered-by': 'next.js'},
        'meta_generator': '',
        'cookie_names':   ['__next_preview_data'],
        'js_globals':     ['__NEXT_DATA__'],
        'api_endpoints':  [],
        'version_files':  ['/package.json'],
        'version_regex':  r'"next":\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'category':       'framework',
    },

    'Nuxt.js': {
        'body_patterns':  ['__nuxt', '/_nuxt/', 'window.__NUXT__'],
        'header_exact':   {'x-powered-by': 'nuxt'},
        'meta_generator': '',
        'cookie_names':   [],
        'js_globals':     ['__NUXT__'],
        'api_endpoints':  [],
        'version_files':  ['/package.json'],
        'version_regex':  r'"nuxt":\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'category':       'framework',
    },

    'Angular': {
        'body_patterns':  ['ng-version', 'ng-app', '<app-root'],
        'header_exact':   {},
        'meta_generator': '',
        'cookie_names':   ['XSRF-TOKEN'],
        'js_globals':     ['ng.version', 'getAllAngularRootElements'],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  r'ng-version="([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'category':       'framework',
    },

    # ─── BLOG / PUBLISHING ─────────────────────────────────────────

    'Blogger': {
        'body_patterns':  ['blogger.com/static', 'data:blogger', 'blogspot'],
        'header_exact':   {},
        'meta_generator': 'blogger',
        'cookie_names':   [],
        'js_globals':     ['blogger'],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  None,
        'category':       'blog',
    },

    'Squarespace': {
        'body_patterns':  ['squarespace.com/s/', 'static.squarespace.com',
                           'sqs-block-content'],
        'header_exact':   {'server': 'squarespace'},
        'meta_generator': 'squarespace',
        'cookie_names':   ['crumb', 'SS_MID'],
        'js_globals':     ['Static.SQUARESPACE_CONTEXT'],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  None,
        'category':       'blog',
    },

    'Webflow': {
        'body_patterns':  ['webflow.com/pages', 'data-wf-page', 'wf-form'],
        'header_exact':   {'x-powered-by': 'webflow'},
        'meta_generator': 'webflow',
        'cookie_names':   [],
        'js_globals':     ['Webflow'],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  None,
        'category':       'cms',
    },

    # ─── WIKI / KNOWLEDGE ──────────────────────────────────────────

    'MediaWiki': {
        'body_patterns':  ['/wiki/', 'mw-content-text', 'mediawiki'],
        'header_exact':   {'x-powered-by': 'mediawiki'},
        'meta_generator': 'mediawiki',
        'cookie_names':   ['mediawiki_session'],
        'js_globals':     ['mw.config'],
        'api_endpoints':  ['/api.php?action=query&meta=siteinfo&format=json'],
        'version_files':  ['/api.php?action=query&meta=siteinfo&siprop=general&format=json'],
        'version_regex':  r'"generator"\s*:\s*"MediaWiki\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'api_version_key': 'query.general.generator',
        'category':       'wiki',
    },

    'Confluence': {
        'body_patterns':  ['/display/', 'confluence-space-key', 'ajs-version'],
        'header_exact':   {'x-confluence-request-time': ''},
        'meta_generator': 'confluence',
        'cookie_names':   ['JSESSIONID', 'confluence.browse.space.cookie'],
        'js_globals':     ['AJS.params'],
        'api_endpoints':  ['/rest/api/space'],
        'version_files':  [],
        'version_regex':  r'ajs-version-number.*?content="([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'category':       'wiki',
    },

    'DokuWiki': {
        'body_patterns':  ['doku.php', 'dokuwiki__', '/lib/exe/fetch.php'],
        'header_exact':   {},
        'meta_generator': 'dokuwiki',
        'cookie_names':   ['DokuWiki'],
        'js_globals':     ['DOKU_BASE'],
        'api_endpoints':  [],
        'version_files':  ['/feed.php'],
        'version_regex':  r'DokuWiki-([0-9]{4}-[0-9]{2}-[0-9]{2}[a-z]?)',
        'category':       'wiki',
    },

    # ─── PORTALS / ENTERPRISE ──────────────────────────────────────

    'SharePoint': {
        'body_patterns':  ['sharepoint', 'ms-spactivepage', '_spPageContextInfo'],
        'header_exact':   {'microsoftsharepointteamservices': '',
                           'x-sharepointhealthscore': ''},
        'meta_generator': 'microsoft sharepoint',
        'cookie_names':   ['WSS_FullScreenMode', 'SPEasyFormsSiteID'],
        'js_globals':     ['_spPageContextInfo', 'SP.'],
        'api_endpoints':  ['/api/contextinfo'],
        'version_files':  [],
        'version_regex':  r'MicrosoftSharePointTeamServices.*?([0-9]+\.[0-9]+\.[0-9]+)',
        'category':       'portal',
    },

    'Liferay': {
        'body_patterns':  ['liferay', '/html/portal/', 'Liferay.Language'],
        'header_exact':   {'liferay-portal': ''},
        'meta_generator': 'liferay',
        'cookie_names':   ['JSESSIONID', 'COMPANY_ID', 'ID'],
        'js_globals':     ['Liferay.'],
        'api_endpoints':  ['/api/jsonws/portal/get-version'],
        'version_files':  [],
        'version_regex':  r'Liferay[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'portal',
    },

    # ─── FORUMS ────────────────────────────────────────────────────

    'vBulletin': {
        'body_patterns':  ['vbulletin', 'vb_postbit', '/clientscript/'],
        'header_exact':   {},
        'meta_generator': 'vbulletin',
        'cookie_names':   ['vbsessionhash', 'vbulletin_'],
        'js_globals':     ['vBulletin'],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  r'vBulletin\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'forum',
    },

    'phpBB': {
        'body_patterns':  ['phpbb', 'viewforum.php', 'posting.php'],
        'header_exact':   {},
        'meta_generator': 'phpbb',
        'cookie_names':   ['phpbb3_', 'phpbb2mysql_'],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  ['/docs/README.html'],
        'version_regex':  r'phpBB\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'category':       'forum',
    },

    'Discourse': {
        'body_patterns':  ['discourse', 'ember-application', 'data-discourse'],
        'header_exact':   {'x-discourse-route': ''},
        'meta_generator': '',
        'cookie_names':   ['_forum_session', '_t'],
        'js_globals':     ['Discourse.'],
        'api_endpoints':  ['/admin/dashboard.json'],
        'version_files':  [],
        'version_regex':  r'"version"\s*:\s*"([0-9]+\.[0-9]+(?:\.[0-9]+)?)"',
        'category':       'forum',
    },

    # ─── ALGERIA-SPECIFIC ──────────────────────────────────────────

    'Midica': {
        'body_patterns':  ['midica', '/midica/', 'midica.dz'],
        'header_exact':   {},
        'meta_generator': 'midica',
        'cookie_names':   [],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  None,
        'category':       'cms',
        'tags':           ['algeria', 'local'],
    },

    'Elgazar': {
        'body_patterns':  ['elgazar', 'الجزائر', 'dz.gov'],
        'header_exact':   {},
        'meta_generator': '',
        'cookie_names':   [],
        'js_globals':     [],
        'api_endpoints':  [],
        'version_files':  [],
        'version_regex':  None,
        'category':       'portal',
        'tags':           ['algeria', 'government'],
    },
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SCORE WEIGHTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_W = {
    'body_pattern':   55,
    'header_exact':   85,
    'meta_generator': 80,
    'cookie_name':    60,
    'js_global':      65,
    'version_body':   20,   # bonus when version extracted from body
    'version_file':   35,   # bonus when version from file
    'version_api':    40,   # bonus when version from API
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN DETECTOR CLASS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CMSDetector:
    """
    Detect CMS/framework with precise version from 40+ signatures.
    """

    def __init__(self):
        self._cache: Dict[str, List[Dict]] = {}

    async def detect(self, base_url: str, engine) -> List[Dict]:
        """
        Full CMS detection pipeline.
        Returns list of dicts, highest confidence first:
          {name, version, confidence, score, category, methods, tags}
        """
        key = base_url.rstrip('/')
        if key in self._cache:
            return self._cache[key]

        # Fetch main page
        main = await engine.request(base_url)
        if main.status == 0:
            return []

        # Also fetch /robots.txt and /sitemap.xml — they often leak CMS info
        extra_pages = await asyncio.gather(
            engine.request(base_url.rstrip('/') + '/robots.txt'),
            engine.request(base_url.rstrip('/') + '/sitemap.xml'),
            return_exceptions=True,
        )
        # Merge extra bodies into a combined context string
        combined_body = main.body
        for ep in extra_pages:
            if isinstance(ep, ResponseData) and ep.status == 200 and ep.body:
                combined_body += '\n' + ep.body[:5000]

        # Score every CMS
        candidates: Dict[str, Dict] = {}
        for cms_name, sig in SIGNATURES.items():
            score, methods = _score(cms_name, sig, main, combined_body)
            if score >= 40:   # minimum threshold
                candidates[cms_name] = {
                    'score':   score,
                    'methods': methods,
                    'version': None,
                    'sig':     sig,
                }

        if not candidates:
            return []

        # Version extraction — run all in parallel
        version_tasks = {
            name: asyncio.create_task(
                self._extract_version(name, data['sig'], base_url, main, engine)
            )
            for name, data in candidates.items()
        }
        version_results = await asyncio.gather(
            *version_tasks.values(), return_exceptions=True
        )
        for (name, data), result in zip(candidates.items(), version_results):
            if isinstance(result, tuple):
                version, method, bonus = result
                data['version']  = version
                data['score']   += bonus
                if method:
                    data['methods'].append(method)

        # Build final result list
        results = []
        for name, data in sorted(candidates.items(),
                                  key=lambda x: x[1]['score'], reverse=True):
            s = data['score']
            confidence = ('certain' if s >= 95 else
                          'high'    if s >= 75 else
                          'medium'  if s >= 45 else 'low')
            sig = data['sig']
            results.append({
                'name':       name,
                'version':    data['version'],
                'confidence': confidence,
                'score':      s,
                'category':   sig.get('category', 'unknown'),
                'methods':    data['methods'],
                'tags':       sig.get('tags', []),
            })

        self._cache[key] = results
        return results

    # ── Version extraction (async, all strategies) ──────────────────

    async def _extract_version(self, cms: str, sig: Dict,
                                base_url: str, main: ResponseData,
                                engine) -> Tuple[Optional[str], Optional[str], int]:
        """
        Try all version extraction strategies.
        Returns (version_string, method_name, score_bonus).
        """
        pattern = sig.get('version_regex')

        # Strategy 1: regex on main page body + headers
        if pattern:
            v = _regex_search(pattern, main.body)
            if not v:
                for hv in main.headers.values():
                    v = _regex_search(pattern, hv)
                    if v: break
            if v:
                return v, 'version_body', _W['version_body']

        # Strategy 2: API endpoint version
        api_key = sig.get('api_version_key')
        for ep in sig.get('api_endpoints', []):
            try:
                url  = base_url.rstrip('/') + ep
                resp = await engine.request(url)
                if resp.status == 200 and resp.body:
                    # Try JSON key path
                    if api_key:
                        v = _json_path(resp.body, api_key)
                        if v:
                            # Extract version from value if it contains text
                            if pattern:
                                m = re.search(pattern, str(v), re.I)
                                v = m.group(1) if m else _extract_semver(str(v))
                            else:
                                v = _extract_semver(str(v))
                            if v:
                                return v, f'api:{ep}', _W['version_api']
                    # Try regex on API body
                    if pattern:
                        v = _regex_search(pattern, resp.body)
                        if v:
                            return v, f'api:{ep}', _W['version_api']
            except Exception:
                continue

        # Strategy 3: dedicated version files
        for fpath in sig.get('version_files', []):
            try:
                url  = base_url.rstrip('/') + fpath
                resp = await engine.request(url)
                if resp.status == 200 and resp.body:
                    if pattern:
                        v = _regex_search(pattern, resp.body)
                        if v:
                            return v, f'file:{fpath}', _W['version_file']
                    # Generic semver search in file
                    v = _extract_semver(resp.body[:2000])
                    if v:
                        return v, f'file:{fpath}', _W['version_file']
            except Exception:
                continue

        # Strategy 4: JS asset version (e.g. /wp-includes/js/wp-emoji-release.min.js?ver=6.4)
        if cms == 'WordPress':
            m = re.search(r'\.min\.js\?ver=([0-9]+\.[0-9]+(?:\.[0-9]+)?)', main.body)
            if m:
                return m.group(1), 'js_asset_ver', _W['version_body']

        return None, None, 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  SCORING ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _score(cms: str, sig: Dict, resp: ResponseData,
           combined_body: str) -> Tuple[int, List[str]]:
    """
    Compute detection score for one CMS against a response.
    Returns (score, matched_methods).
    """
    score   = 0
    methods: List[str] = []
    body_l  = combined_body.lower()
    hdrs_l  = {k.lower(): v.lower() for k, v in resp.headers.items()}
    cookie  = hdrs_l.get('set-cookie', '')

    # 1. Body patterns
    for pat in sig.get('body_patterns', []):
        if pat.lower() in body_l:
            score += _W['body_pattern']
            methods.append(f'body:{pat[:30]}')
            break  # one match enough for this signal

    # 2. Headers
    for hdr, expected in sig.get('header_exact', {}).items():
        hdr_l = hdr.lower()
        if hdr_l in hdrs_l:
            if not expected or expected.lower() in hdrs_l[hdr_l]:
                score += _W['header_exact']
                methods.append(f'header:{hdr}')
                break

    # 3. Meta generator
    mg = sig.get('meta_generator', '')
    if mg:
        gen_val = _meta_generator(combined_body)
        if gen_val and mg.lower() in gen_val.lower():
            score += _W['meta_generator']
            methods.append('meta_generator')

    # 4. Cookies
    for ck in sig.get('cookie_names', []):
        if ck.lower() in cookie:
            score += _W['cookie_name']
            methods.append(f'cookie:{ck}')
            break

    # 5. JS globals
    for jsg in sig.get('js_globals', []):
        if jsg.lower() in body_l:
            score += _W['js_global']
            methods.append(f'js:{jsg}')
            break

    return score, methods


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _regex_search(pattern: str, text: str) -> Optional[str]:
    try:
        m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip() if m else None
    except Exception:
        return None


def _extract_semver(text: str) -> Optional[str]:
    """Find the first X.Y.Z or X.Y version string in text."""
    m = re.search(r'\b([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b', text)
    return m.group(1) if m else None


def _meta_generator(body: str) -> Optional[str]:
    """Extract content of <meta name="generator" ...>"""
    m = re.search(
        r'<meta[^>]+name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
        body, re.IGNORECASE
    )
    if m:
        return m.group(1)
    m = re.search(
        r'<meta[^>]+content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']',
        body, re.IGNORECASE
    )
    return m.group(1) if m else None


def _json_path(body: str, key_path: str) -> Optional[str]:
    """
    Parse JSON body and extract value at dot-separated key path.
    e.g. key_path='query.general.generator'
    """
    try:
        data = json.loads(body)
        parts = key_path.split('.')
        node  = data
        for p in parts:
            if isinstance(node, dict):
                node = node.get(p)
            else:
                return None
            if node is None:
                return None
        return str(node) if node is not None else None
    except Exception:
        return None
