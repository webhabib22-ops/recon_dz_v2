#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Host Profiler  ★ Elite Edition
═══════════════════════════════════════════════════════════════════════════
Given ONE IP → discovers EVERY co-hosted domain → profiles each one with:

  Domain Intel:
    • HTTP status, title, server, response time
    • HTTPS + HSTS + redirect chain
    • Tech stack fingerprint (20+ signals)
    • Security header grade  A→F
    • Redirect target tracking

  CMS Intelligence:
    • 40+ CMS/framework signatures
    • Exact version (4 extraction strategies)
    • Confidence level: certain / high / medium / low

  Infrastructure:
    • ASN, Org, CIDR, Country  (BGPView)
    • IP range co-hosting context

  Algeria Context:
    • Sector classification
    • Criticality rating

  Report:
    • Interactive HTML with Chart.js + live search + filters
    • Full JSON export
    • CLI table with color coding

Competes with: Shodan + BuiltWith + WhatCMS + theHarvester combined.
"""

import asyncio
import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.async_engine     import AsyncReconEngine
from core.ip_enumerator    import IPEnumerator
from core.cms_detector     import CMSDetector
from core.algeria_threats  import AlgeriaThreatDatabase


# ═══════════════════════════════════════════════════════════════════════
#  SECURITY HEADER GRADER
# ═══════════════════════════════════════════════════════════════════════

_SEC_HDRS: Dict[str, int] = {
    'strict-transport-security': 25,   # HSTS — most important
    'content-security-policy':   20,   # CSP
    'x-frame-options':           15,   # Clickjacking
    'x-content-type-options':    15,   # MIME sniffing
    'referrer-policy':           10,   # Privacy
    'permissions-policy':        10,   # Feature policy
    'cross-origin-opener-policy': 5,   # COOP
}
_SEC_MAX = sum(_SEC_HDRS.values())   # 100


def _security_grade(headers: Dict[str, str]) -> Dict[str, Any]:
    hl      = {k.lower() for k in headers}
    score   = sum(pts for h, pts in _SEC_HDRS.items() if h in hl)
    present = [h for h in _SEC_HDRS if h in hl]
    missing = [h for h in _SEC_HDRS if h not in hl]
    pct     = int(score / _SEC_MAX * 100)
    grade   = ('A' if pct >= 80 else 'B' if pct >= 60 else
               'C' if pct >= 40 else 'D' if pct >= 20 else 'F')
    return {'grade': grade, 'score': score, 'pct': pct,
            'present': present, 'missing': missing}


# ═══════════════════════════════════════════════════════════════════════
#  TECH STACK FINGERPRINTER
# ═══════════════════════════════════════════════════════════════════════

_STACK: List[Tuple[str, str]] = [
    # server
    ('server: nginx',             'Nginx'),
    ('server: apache',            'Apache'),
    ('server: microsoft-iis',     'IIS'),
    ('server: litespeed',         'LiteSpeed'),
    ('server: openresty',         'OpenResty'),
    ('server: cloudflare',        'Cloudflare'),
    ('server: caddy',             'Caddy'),
    ('via: varnish',              'Varnish'),
    ('x-cache: hit from cloudfront', 'AWS CloudFront'),
    # language
    ('x-powered-by: php',         'PHP'),
    ('x-powered-by: asp.net',     'ASP.NET'),
    ('x-powered-by: express',     'Node.js'),
    ('x-powered-by: next.js',     'Next.js'),
    ('x-powered-by: laravel',     'Laravel'),
    ('x-powered-by: nestjs',      'NestJS'),
    # runtime detection via cookies
    ('jsessionid',                'Java'),
    ('phpsessid',                 'PHP'),
    ('asp.net_sessionid',         'ASP.NET'),
    ('rack.session',              'Ruby'),
    # frameworks in body
    ('wp-content',                'WordPress'),
    ('__next_data__',             'Next.js'),
    ('window.__nuxt__',           'Nuxt.js'),
    ('ng-version',                'Angular'),
    ('data-reactroot',            'React'),
    ('__vue__',                   'Vue.js'),
    ('django',                    'Django'),
    ('csrfmiddlewaretoken',       'Django'),
    ('laravel_session',           'Laravel'),
    ('sf_redirect',               'Symfony'),
]


def _detect_stack(headers: Dict[str, str], body: str) -> List[str]:
    sig = (
        ' '.join(f'{k}:{v}' for k, v in headers.items()).lower()
        + ' ' + body[:8000].lower()
    )
    seen: set = set()
    out: List[str] = []
    for token, tech in _STACK:
        if token in sig and tech not in seen:
            out.append(tech)
            seen.add(tech)
    return out


# ═══════════════════════════════════════════════════════════════════════
#  DOMAIN PROFILER  (single domain → full profile)
# ═══════════════════════════════════════════════════════════════════════

class DomainProfiler:
    """Fetch + analyze one domain: HTTP + CMS + stack + security."""

    def __init__(self, engine: AsyncReconEngine,
                 cms: CMSDetector,
                 algeria: AlgeriaThreatDatabase):
        self.engine  = engine
        self.cms     = cms
        self.algeria = algeria

    async def profile(self, domain: str,
                      sources: Optional[List[str]] = None) -> Dict[str, Any]:
        # Connect via fallback (HTTPS→HTTP, IP-direct→hostname-direct)
        resp, proto, final_host = await self.engine.request_with_fallback(
            domain, www_fallback=False, path='/'
        )

        base: Dict[str, Any] = {
            'domain':      domain,
            'final_host':  final_host,
            'protocol':    proto.rstrip('://'),
            'active':      resp.status != 0,
            'status':      resp.status,
            'title':       _extract_title(resp.body),
            'server':      resp.get_header('server') or None,
            'ip':          await self.engine.resolve_hostname(final_host),
            'sources':     sources or [],
            'scanned_at':  datetime.utcnow().isoformat(),
            'error':       resp.error if resp.status == 0 else None,
        }

        if resp.status == 0:
            return base

        base_url = f"{proto}{final_host}"

        # Run parallel analysis
        cms_task = asyncio.create_task(
            self.cms.detect(base_url, self.engine))
        stack    = _detect_stack(resp.headers, resp.body)
        sec      = _security_grade(resp.headers)
        cms_res  = await cms_task

        base.update({
            'cms':           cms_res[0] if cms_res else None,
            'cms_all':       cms_res,
            'stack':         stack,
            'security':      sec,
            'https':         proto.startswith('https'),
            'hsts':          'strict-transport-security' in {
                                 k.lower() for k in resp.headers},
            'redirect_count': resp.redirect_count,
            'response_ms':   int(resp.elapsed * 1000),
            'content_length': len(resp.body_bytes),
            'cookies':       _parse_cookies(resp.headers),
        })

        # Algeria context
        ali = self.algeria.identify_target(final_host)
        base['algeria'] = ali.__dict__ if ali else None
        return base


# ═══════════════════════════════════════════════════════════════════════
#  HOST PROFILER  (IP → all domains → all profiles)
# ═══════════════════════════════════════════════════════════════════════

class HostProfiler:
    """
    Entry point: IP → enumerate → profile → report.
    Runs enumeration (8 sources) then profiles all domains in parallel.
    """

    def __init__(self, engine: AsyncReconEngine,
                 algeria: AlgeriaThreatDatabase,
                 concurrency: int = 10):
        self.engine      = engine
        self.algeria     = algeria
        self.concurrency = concurrency
        self._enum       = IPEnumerator(engine)
        self._cms        = CMSDetector()
        self._profiler   = DomainProfiler(engine, self._cms, algeria)

    async def profile_ip(self, ip: str,
                          progress_cb=None) -> Dict[str, Any]:
        """
        Full IP profile pipeline.
        progress_cb(current: int, total: int, domain: str)
        """
        t0 = datetime.utcnow()

        # ── Step 1: Enumerate ──────────────────────────────────────
        rich  = await self._enum.enumerate_rich(ip)
        metas = rich.get('domains', [])
        if not metas:
            return {
                'ip': ip, **_bgp_fields(rich),
                'total_domains': 0, 'active_domains': 0,
                'inactive': 0, 'cms_summary': {},
                'stack_summary': {}, 'security_summary': {},
                'domains': [],
                'elapsed_s': 0,
                'scanned_at': t0.isoformat(),
            }

        src_map = {d['domain']: d.get('sources', []) for d in metas}
        dlist   = [d['domain'] for d in metas]

        # ── Step 2: Profile in parallel ────────────────────────────
        sem   = asyncio.Semaphore(self.concurrency)
        done  = [0]

        async def _one(domain: str) -> Dict:
            async with sem:
                p = await self._profiler.profile(
                    domain, sources=src_map.get(domain, []))
                done[0] += 1
                if progress_cb:
                    try:
                        progress_cb(done[0], len(dlist), domain)
                    except Exception:
                        pass
                return p

        tasks   = [asyncio.create_task(_one(d)) for d in dlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        profiles: List[Dict] = [
            r for r in results if isinstance(r, dict)]

        # ── Step 3: Sort by interest score ─────────────────────────
        profiles.sort(key=_interest_score, reverse=True)

        # ── Step 4: Aggregate summaries ────────────────────────────
        active = [p for p in profiles if p.get('active')]

        cms_summary: Dict[str, int] = {}
        stack_summary: Dict[str, int] = {}
        sec_grades: Dict[str, int] = {}

        for p in active:
            cms = p.get('cms')
            if cms and cms.get('name'):
                n = cms['name']
                cms_summary[n] = cms_summary.get(n, 0) + 1
            for s in p.get('stack', []):
                stack_summary[s] = stack_summary.get(s, 0) + 1
            g = p.get('security', {}).get('grade', 'F')
            sec_grades[g] = sec_grades.get(g, 0) + 1

        elapsed = (datetime.utcnow() - t0).total_seconds()

        return {
            'ip': ip,
            **_bgp_fields(rich),
            'total_domains':    len(profiles),
            'active_domains':   len(active),
            'inactive':         len(profiles) - len(active),
            'cms_summary':      cms_summary,
            'stack_summary':    stack_summary,
            'security_summary': sec_grades,
            'domains':          profiles,
            'elapsed_s':        round(elapsed, 1),
            'scanned_at':       t0.isoformat(),
        }

    async def profile_domain(self, domain: str) -> Dict[str, Any]:
        """Profile a single known domain (no IP enumeration)."""
        return await self._profiler.profile(domain)


# ═══════════════════════════════════════════════════════════════════════
#  INTEREST SCORE  (sorting — most interesting for researcher first)
# ═══════════════════════════════════════════════════════════════════════

def _interest_score(p: Dict) -> int:
    if not p.get('active'):
        return 0
    s = 10
    cms = p.get('cms') or {}
    if cms.get('name'):
        s += 20
    if cms.get('version'):
        s += 15
    s += {'certain': 20, 'high': 15, 'medium': 8, 'low': 2}.get(
        cms.get('confidence', 'low'), 0)
    g = p.get('security', {}).get('grade', 'F')
    s += {'A': 0, 'B': 5, 'C': 10, 'D': 15, 'F': 20}.get(g, 0)
    ali = p.get('algeria') or {}
    s += {'critical': 30, 'high': 20, 'medium': 10, 'low': 5}.get(
        ali.get('criticality', ''), 0)
    if not p.get('https'):
        s += 10
    s += min(len(p.get('sources', [])) * 3, 15)
    return s


# ═══════════════════════════════════════════════════════════════════════
#  HTML REPORT — Interactive, filterable, Chart.js
# ═══════════════════════════════════════════════════════════════════════

def generate_host_profile_html(report: Dict) -> str:
    ip      = report.get('ip', '?')
    org     = report.get('org', 'Unknown')
    asn     = report.get('asn', '?')
    cidr    = report.get('cidr', '?')
    country = report.get('country', '?')
    total   = report.get('total_domains', 0)
    active  = report.get('active_domains', 0)
    elapsed = report.get('elapsed_s', 0)
    cms_s   = report.get('cms_summary', {})
    stk_s   = report.get('stack_summary', {})
    sec_s   = report.get('security_summary', {})
    domains = report.get('domains', [])

    def he(v: Any) -> str:
        return str(v or '').replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    # ── Chart datasets ────────────────────────────────────────────
    cms_labels = json.dumps(list(cms_s.keys())[:8])
    cms_data   = json.dumps(list(cms_s.values())[:8])
    stk_labels = json.dumps(list(stk_s.keys())[:8])
    stk_data   = json.dumps(list(stk_s.values())[:8])
    sec_order  = ['A', 'B', 'C', 'D', 'F']
    sec_data   = json.dumps([sec_s.get(g, 0) for g in sec_order])
    sec_colors = json.dumps(['#10b981','#3b82f6','#f59e0b','#f97316','#ef4444'])

    # ── Domain table rows ─────────────────────────────────────────
    rows_html = ''
    for d in domains:
        is_active = d.get('active', False)
        act_sym   = '●' if is_active else '○'
        act_col   = '#10b981' if is_active else '#ef4444'
        status    = d.get('status', 0)
        st_col    = ('#10b981' if status == 200 else
                     '#f59e0b' if status in (301, 302, 403, 401) else
                     '#ef4444' if status >= 400 else '#94a3b8')
        cms       = d.get('cms') or {}
        cms_name  = he(cms.get('name', ''))
        cms_ver   = he(cms.get('version', ''))
        cms_conf  = cms.get('confidence', '')
        conf_col  = {'certain': '#10b981', 'high': '#3b82f6',
                     'medium': '#f59e0b', 'low': '#94a3b8'}.get(cms_conf, '#94a3b8')
        sec       = d.get('security', {})
        grade     = sec.get('grade', '?')
        grade_col = ('#10b981' if grade in ('A', 'B') else
                     '#f59e0b' if grade == 'C' else '#ef4444')
        stack     = he(', '.join(d.get('stack', [])[:3]))
        https_ico = '🔒' if d.get('https') else '⚠️'
        hsts_ico  = '🛡' if d.get('hsts') else ''
        title     = he((d.get('title') or '')[:50])
        server    = he(d.get('server') or '')
        sources   = he(', '.join(d.get('sources', []))[:35])
        ali       = d.get('algeria') or {}
        sector    = he(ali.get('sector', ''))
        crit      = ali.get('criticality', '')
        crit_col  = {'critical': '#ef4444', 'high': '#f97316',
                     'medium': '#f59e0b', 'low': '#94a3b8'}.get(crit, '')
        ms        = d.get('response_ms', 0)
        domain_lnk = he(d.get('domain', ''))
        proto     = d.get('protocol', 'https')

        ver_cell = ''
        if cms_name:
            ver_cell = (f'<b style="color:#e2e8f0">{cms_name}</b>'
                        + (f'<br><span class="tag" style="color:#f59e0b;'
                           f'border-color:#f59e0b44">v{cms_ver}</span>'
                           if cms_ver else '')
                        + (f'<br><span class="tag" style="color:{conf_col};'
                           f'border-color:{conf_col}44">{cms_conf}</span>'
                           if cms_conf else ''))
        else:
            ver_cell = '<span style="color:#2d4a6a">—</span>'

        rows_html += f"""<tr data-active="{str(is_active).lower()}"
            data-cms="{cms_name.lower()}" data-ver="{cms_ver}"
            data-https="{str(d.get('https',False)).lower()}"
            data-grade="{grade}">
          <td class="mono">
            <a href="{proto}://{domain_lnk}" target="_blank"
               style="color:var(--accent);text-decoration:none;font-size:12px">
              {domain_lnk}
            </a>
          </td>
          <td><span style="color:{act_col};font-size:16px">{act_sym}</span></td>
          <td><b style="color:{st_col};font-family:monospace">{status or '—'}</b></td>
          <td style="font-size:15px">{https_ico}{hsts_ico}</td>
          <td style="color:#94a3b8;font-size:11px">{title}</td>
          <td>{ver_cell}</td>
          <td style="color:#94a3b8;font-size:11px">{stack}</td>
          <td style="color:#64748b;font-size:11px">{server}</td>
          <td><b style="color:{grade_col};font-family:monospace;font-size:15px">{grade}</b></td>
          <td style="color:{crit_col or '#94a3b8'};font-size:11px">{sector}</td>
          <td style="color:#94a3b8;font-size:10px">{ms}ms</td>
          <td style="color:#64748b;font-size:10px">{sources}</td>
        </tr>"""

    # ── CMS filter buttons ────────────────────────────────────────
    cms_btns = ''.join(
        f'<button class="fbtn" onclick="setCMS({json.dumps(k)},this)">'
        f'{he(k)} <span class="cnt">{v}</span></button>'
        for k, v in sorted(cms_s.items(), key=lambda x: -x[1])[:7]
    )

    scanned_at = (report.get('scanned_at') or '')[:19]
    with_ver   = sum(1 for d in domains if d.get('cms', {}) and d.get('cms', {}).get('version'))
    no_https   = sum(1 for d in domains if d.get('active') and not d.get('https'))

    # Full HTML — using raw string with JS regex escaped as \\d+\\.\\d+
    html = (
'<!DOCTYPE html>\n'
'<html lang="en">\n'
'<head>\n'
'<meta charset="UTF-8">\n'
'<meta name="viewport" content="width=device-width,initial-scale=1">\n'
f'<title>RECON-DZ · Host Profile · {he(ip)}</title>\n'
'<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>\n'
'<style>\n'
':root{--bg:#060d1a;--s1:#0b1627;--s2:#101f35;--border:#1a3050;'
'--accent:#00d4ff;--a2:#7c3aed;--text:#dde8f5;--muted:#4e6a8a;'
'--mono:"Courier New",monospace;}\n'
'*{box-sizing:border-box;margin:0;padding:0}\n'
'body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif;'
'font-size:13px;line-height:1.6}\n'
'.hdr{background:linear-gradient(135deg,#050c19,#0a1830);'
'border-bottom:1px solid var(--border);padding:28px 48px;'
'display:flex;justify-content:space-between;align-items:center;gap:20px}\n'
'.hdr-left h1{font-size:22px;font-weight:800;letter-spacing:-0.5px;margin-bottom:4px}\n'
'.hdr-left h1 em{color:var(--accent);font-style:normal}\n'
'.eyebrow{font-family:var(--mono);font-size:10px;color:var(--accent);'
'letter-spacing:3px;text-transform:uppercase;margin-bottom:6px}\n'
'.meta{font-family:var(--mono);font-size:11px;color:var(--muted);line-height:2}\n'
'.ip-box{background:rgba(0,212,255,.07);border:1px solid rgba(0,212,255,.25);'
'border-radius:12px;padding:16px 24px;text-align:center;min-width:180px}\n'
'.ip-box .ip{font-family:var(--mono);font-size:20px;font-weight:700;color:var(--accent)}\n'
'.ip-box .sub{font-size:10px;color:var(--muted);margin-top:2px}\n'
'.wrap{max-width:1700px;margin:0 auto;padding:28px 48px}\n'
'.kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:22px}\n'
'.kpi{background:var(--s1);border:1px solid var(--border);border-radius:10px;'
'padding:14px;text-align:center;position:relative;overflow:hidden}\n'
'.kpi::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;'
'background:linear-gradient(90deg,var(--accent),var(--a2))}\n'
'.kpi .v{font-size:28px;font-weight:800;font-family:var(--mono);color:var(--accent)}\n'
'.kpi .l{font-size:10px;color:var(--muted);margin-top:2px;text-transform:uppercase;letter-spacing:1px}\n'
'.charts{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px}\n'
'.chart-card{background:var(--s1);border:1px solid var(--border);'
'border-radius:12px;padding:18px}\n'
'.card-title{font-family:var(--mono);font-size:10px;letter-spacing:2px;'
'text-transform:uppercase;color:var(--accent);margin-bottom:14px;'
'padding-bottom:8px;border-bottom:1px solid var(--border)}\n'
'.main-card{background:var(--s1);border:1px solid var(--border);border-radius:12px;padding:20px}\n'
'.toolbar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center}\n'
'.search{background:var(--s2);border:1px solid var(--border);border-radius:8px;'
'padding:8px 14px;color:var(--text);font-family:var(--mono);font-size:12px;'
'flex:1;min-width:200px;outline:none}\n'
'.search:focus{border-color:var(--accent)}\n'
'.fbtn{background:var(--s2);border:1px solid var(--border);border-radius:6px;'
'padding:4px 12px;font-size:11px;cursor:pointer;color:var(--muted);'
'font-family:var(--mono);transition:all .15s;white-space:nowrap}\n'
'.fbtn:hover,.fbtn.on{background:rgba(0,212,255,.1);border-color:var(--accent);color:var(--accent)}\n'
'.cnt{background:rgba(0,212,255,.15);border-radius:3px;padding:1px 5px;font-size:9px}\n'
'.tag{display:inline-block;padding:1px 6px;border-radius:3px;'
'font-size:9px;font-weight:700;font-family:var(--mono);border:1px solid transparent}\n'
'.tbl-wrap{overflow-x:auto}\n'
'table{width:100%;border-collapse:collapse;font-size:12px}\n'
'th{background:var(--s2);color:var(--muted);font-size:10px;letter-spacing:1px;'
'text-transform:uppercase;padding:8px 10px;text-align:left;'
'border-bottom:1px solid var(--border);white-space:nowrap;cursor:pointer}\n'
'th:hover{color:var(--accent)}\n'
'td{padding:8px 10px;border-bottom:1px solid rgba(26,48,80,.4);vertical-align:top}\n'
'tr:hover td{background:rgba(0,212,255,.02)}\n'
'tr.hide{display:none}\n'
'.mono{font-family:var(--mono)}\n'
'#count{font-family:var(--mono);font-size:11px;color:var(--muted);padding:4px 8px;'
'background:var(--s2);border-radius:6px;white-space:nowrap}\n'
'footer{text-align:center;padding:20px;color:var(--muted);'
'font-family:var(--mono);font-size:11px;'
'border-top:1px solid var(--border);margin-top:32px}\n'
'@media(max-width:900px){.kpis{grid-template-columns:1fr 1fr}'
'.charts{grid-template-columns:1fr}}\n'
'</style>\n'
'</head>\n'
'<body>\n'

'<div class="hdr">\n'
'<div class="hdr-left">\n'
f'<div class="eyebrow">RECON-DZ v3 &nbsp;·&nbsp; Host Intelligence Report</div>\n'
f'<h1><em>Host</em> Profile &mdash; {he(org)}</h1>\n'
f'<div class="meta">'
f'ASN: AS{he(asn)} &nbsp;|&nbsp; CIDR: {he(cidr)} &nbsp;|&nbsp; '
f'Country: {he(country)} &nbsp;|&nbsp; Scanned: {he(scanned_at)}'
f'</div>\n'
'</div>\n'
f'<div class="ip-box"><div class="ip">{he(ip)}</div>'
f'<div class="sub">Target IP &nbsp;·&nbsp; {he(elapsed)}s scan</div></div>\n'
'</div>\n'

'<div class="wrap">\n'

'<div class="kpis">\n'
f'<div class="kpi"><div class="v">{total}</div><div class="l">Domains Found</div></div>\n'
f'<div class="kpi"><div class="v" style="color:#10b981">{active}</div><div class="l">Active</div></div>\n'
f'<div class="kpi"><div class="v" style="color:#f59e0b">{len(cms_s)}</div><div class="l">CMS Types</div></div>\n'
f'<div class="kpi"><div class="v">{with_ver}</div><div class="l">Versions Found</div></div>\n'
f'<div class="kpi"><div class="v" style="color:#ef4444">{no_https}</div><div class="l">No HTTPS</div></div>\n'
f'<div class="kpi"><div class="v" style="color:#7c3aed">{sum(1 for d in domains if d.get("algeria"))}</div><div class="l">Algerian</div></div>\n'
'</div>\n'

'<div class="charts">\n'
'<div class="chart-card"><div class="card-title">CMS Distribution</div>'
'<canvas id="cmsChart" height="160"></canvas></div>\n'
'<div class="chart-card"><div class="card-title">Tech Stack</div>'
'<canvas id="stkChart" height="160"></canvas></div>\n'
'<div class="chart-card"><div class="card-title">Security Grades</div>'
'<canvas id="secChart" height="160"></canvas></div>\n'
'</div>\n'

'<div class="main-card">\n'
f'<div class="card-title">Domain Intelligence Table &mdash; {total} hosts</div>\n'
'<div class="toolbar">\n'
'<input class="search" id="q" placeholder="Search domain, CMS, version, stack…" oninput="applyFilters()">\n'
'<span id="count"></span>\n'
'</div>\n'
'<div class="toolbar">\n'
'<button class="fbtn on" id="btn-all" onclick="setF(\'all\',this)">All</button>\n'
'<button class="fbtn" onclick="setF(\'active\',this)">Active Only</button>\n'
'<button class="fbtn" onclick="setF(\'cms\',this)">Has CMS</button>\n'
'<button class="fbtn" onclick="setF(\'version\',this)">Has Version</button>\n'
'<button class="fbtn" onclick="setF(\'nossl\',this)">No HTTPS ⚠</button>\n'
'<button class="fbtn" onclick="setF(\'fail\',this)">Grade D/F</button>\n'
f'{cms_btns}\n'
'</div>\n'
'<div class="tbl-wrap">\n'
'<table id="tbl">\n'
'<thead><tr>\n'
'<th onclick="sortCol(0)">Domain ↕</th>\n'
'<th>Live</th>\n'
'<th onclick="sortCol(2)">Status ↕</th>\n'
'<th>TLS</th>\n'
'<th>Title</th>\n'
'<th onclick="sortCol(5)">CMS &amp; Version ↕</th>\n'
'<th>Stack</th>\n'
'<th>Server</th>\n'
'<th onclick="sortCol(8)">Sec ↕</th>\n'
'<th>Algeria</th>\n'
'<th onclick="sortCol(10)">RT ↕</th>\n'
'<th>Sources</th>\n'
'</tr></thead>\n'
f'<tbody id="tbody">{rows_html}</tbody>\n'
'</table>\n'
'</div></div>\n'
'</div>\n'

f'<footer>RECON-DZ v3 &nbsp;·&nbsp; Host Intelligence Profile &nbsp;·&nbsp; '
f'{he(ip)} &nbsp;·&nbsp; Authorized Security Assessment Only</footer>\n'

'<script>\n'
'const COLORS=["#00d4ff","#7c3aed","#10b981","#f59e0b","#ef4444","#3b82f6","#f97316","#8b5cf6"];\n'
f'new Chart("cmsChart",{{type:"doughnut",'
f'data:{{labels:{cms_labels},datasets:[{{data:{cms_data},'
f'backgroundColor:COLORS,borderWidth:0}}]}},'
f'options:{{cutout:"60%",plugins:{{legend:{{position:"right",'
f'labels:{{color:"#4e6a8a",font:{{size:10}}}}}}}}}}}});\n'
f'new Chart("stkChart",{{type:"bar",'
f'data:{{labels:{stk_labels},datasets:[{{data:{stk_data},'
f'backgroundColor:COLORS,borderRadius:4}}]}},'
f'options:{{indexAxis:"y",plugins:{{legend:{{display:false}}}},'
f'scales:{{x:{{ticks:{{color:"#4e6a8a"}},grid:{{color:"#1a3050"}}}},'
f'y:{{ticks:{{color:"#94a3b8"}},grid:{{display:false}}}}}}}}}});\n'
f'new Chart("secChart",{{type:"bar",'
f'data:{{labels:["A","B","C","D","F"],'
f'datasets:[{{data:{sec_data},backgroundColor:{sec_colors},borderRadius:4}}]}},'
f'options:{{plugins:{{legend:{{display:false}}}},'
f'scales:{{x:{{ticks:{{color:"#94a3b8"}},grid:{{display:false}}}},'
f'y:{{ticks:{{color:"#4e6a8a"}},grid:{{color:"#1a3050"}}}}}}}}}});\n'

'let fMode="all", fCMS=null;\n'
'function setF(m,btn){'
'fMode=m;fCMS=null;'
'document.querySelectorAll(".fbtn").forEach(b=>b.classList.remove("on"));'
'btn.classList.add("on");applyFilters();}\n'
'function setCMS(c,btn){'
'fMode="cms-exact";fCMS=c.toLowerCase();'
'document.querySelectorAll(".fbtn").forEach(b=>b.classList.remove("on"));'
'btn.classList.add("on");applyFilters();}\n'
'function applyFilters(){'
'const q=document.getElementById("q").value.toLowerCase();'
'const rows=document.querySelectorAll("#tbody tr");'
'let vis=0;'
'rows.forEach(r=>{'
'const t=r.textContent.toLowerCase();'
'let show=true;'
'if(q&&!t.includes(q))show=false;'
'if(fMode==="active"&&r.dataset.active!=="true")show=false;'
'if(fMode==="cms"&&!r.dataset.cms)show=false;'
'if(fMode==="version"&&!r.dataset.ver)show=false;'
'if(fMode==="nossl"&&r.dataset.https!=="false")show=false;'
'if(fMode==="fail"&&r.dataset.grade!=="D"&&r.dataset.grade!=="F")show=false;'
'if(fMode==="cms-exact"&&fCMS&&!r.dataset.cms.includes(fCMS))show=false;'
'r.classList.toggle("hide",!show);'
'if(show)vis++;'
'});'
'document.getElementById("count").textContent=vis+" shown";}\n'
'applyFilters();\n'

'function sortCol(ci){'
'const tb=document.getElementById("tbody");'
'const rows=[...tb.querySelectorAll("tr")];'
'const asc=tb.dataset.sort==ci;tb.dataset.sort=asc?"":ci;'
'rows.sort((a,b)=>{'
'const av=a.cells[ci]?.textContent.trim()||"";'
'const bv=b.cells[ci]?.textContent.trim()||"";'
'return asc?bv.localeCompare(av,undefined,{numeric:true})'
':av.localeCompare(bv,undefined,{numeric:true});'
'});'
'rows.forEach(r=>tb.appendChild(r));}\n'
'</script>\n'
'</body>\n'
'</html>\n'
    )
    return html


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _extract_title(body: str) -> Optional[str]:
    if not body:
        return None
    m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.I)
    return re.sub(r'\s+', ' ', m.group(1)).strip() if m else None


def _parse_cookies(headers: Dict[str, str]) -> List[str]:
    raw = headers.get('set-cookie', '')
    if not raw:
        return []
    return [c.split('=')[0].strip() for c in raw.split(',') if '=' in c][:5]


def _bgp_fields(rich: Dict) -> Dict:
    return {
        'asn':     rich.get('asn'),
        'org':     rich.get('org'),
        'cidr':    rich.get('cidr'),
        'country': rich.get('country'),
    }
