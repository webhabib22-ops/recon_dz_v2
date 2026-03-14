#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Intelligence Engine  ★ NEVER SEEN BEFORE
═══════════════════════════════════════════════════════════════════════════
الفكرة الجوهرية:
  بدلاً من مجرد جمع المعلومات، هذا المحرك يفكر مثل المهاجم الحقيقي.
  يربط النقاط بين كل المعلومات المجمعة ويستنتج:
  ...
"""

import asyncio
import hashlib
import json
import re
import time
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from core.async_engine import AsyncReconEngine, ResponseData, _empty_response


# ═══════════════════════════════════════════════════════════════════════
#  DATA MODELS
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class BehaviorProbe:
    """نتيجة probe واحد من اختبارات السلوك."""
    probe_name:  str
    status:      int
    elapsed_ms:  float
    headers:     Dict[str, str]
    body_hash:   str    # sha256[:16] — للمقارنة دون تخزين المحتوى
    body_size:   int
    anomaly:     Optional[str] = None   # وصف الشذوذ إن وُجد


@dataclass
class AttackVector:
    """ناقل هجوم محتمل."""
    name:        str
    category:    str    # injection|auth_bypass|info_leak|misconfig|rce|ssrf|idor
    severity:    str    # critical|high|medium|low
    confidence:  float  # 0.0 → 1.0
    evidence:    List[str] = field(default_factory=list)
    bypass_hint: Optional[str] = None
    chain_next:  List[str] = field(default_factory=list)
    cve_hints:   List[str] = field(default_factory=list)
    defense:     str = ""

    def to_dict(self) -> Dict:
        return self.__dict__


@dataclass
class ServerPersonality:
    """
    بصمة شخصية السيرفر — أعمق من مجرد Banner.
    مستوحى من p0f وnmap OS detection لكن على مستوى HTTP.
    """
    server_type:       Optional[str] = None   # nginx|apache|iis|cloudflare|…
    true_server:       Optional[str] = None   # الخادم الحقيقي خلف الـ proxy
    waf_type:          Optional[str] = None
    cdn_provider:      Optional[str] = None
    backend_language:  Optional[str] = None
    os_hint:           Optional[str] = None
    http_version:      Optional[str] = None
    cache_behavior:    Optional[str] = None
    error_fingerprint: Optional[str] = None   # بصمة صفحات الخطأ
    unique_markers:    List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════
#  BEHAVIORAL FINGERPRINTER  — القلب
# ═══════════════════════════════════════════════════════════════════════

class BehavioralFingerprinter:
    """
    يرسل probes ذكية ويحلل الفروق بين الردود.

    المبدأ الثوري:
    السيرفر الصحيح والـ WAF وراءه لهما "توقيعات سلوكية" مختلفة.
    إذا أرسلنا نفس الطلب بطرق مختلفة وقارنا الردود،
    نستطيع فهم البنية الداخلية الكاملة.
    """

    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine

    async def run(self, base_url: str) -> Dict[str, Any]:
        """تنفيذ جميع اختبارات السلوك بشكل متوازٍ."""
        results = await asyncio.gather(
            self._probe_http_versions(base_url),
            self._probe_method_behavior(base_url),
            self._probe_header_manipulation(base_url),
            self._probe_error_diversity(base_url),
            self._probe_cache_behavior(base_url),
            self._probe_encoding_behavior(base_url),
            self._probe_timing_patterns(base_url),
            self._probe_path_traversal_clues(base_url),
            self._probe_protocol_quirks(base_url),
            self._probe_tls_details(base_url),
            return_exceptions=True,
        )
        labels = [
            'http_versions', 'method_behavior', 'header_manipulation',
            'error_diversity', 'cache_behavior', 'encoding_behavior',
            'timing_patterns', 'path_traversal_clues', 'protocol_quirks',
            'tls_details',
        ]
        out = {}
        for label, res in zip(labels, results):
            out[label] = res if not isinstance(res, Exception) else {'error': str(res)}
        return out

    # ── 1. HTTP Version Probing ──────────────────────────────────
    async def _probe_http_versions(self, url: str) -> Dict:
        """
        هل يختلف رد السيرفر بين HTTP/1.0 و HTTP/1.1؟
        الاختلاف يكشف وجود reverse proxy أو load balancer.
        """
        findings = {}

        # HTTP/1.1 عادي
        r1 = await self.engine.request(url, extra_headers={
            'Connection': 'close',
            'Cache-Control': 'no-cache',
        })
        findings['http11_status'] = r1.status
        findings['http11_server'] = r1.get_header('server')
        findings['http11_via']    = r1.get_header('via')

        # طلب مع Connection: keep-alive
        r2 = await self.engine.request(url, extra_headers={
            'Connection': 'keep-alive',
        })
        findings['keepalive_server'] = r2.get_header('server')

        # هل تغير الـ server header؟ → reverse proxy مكشوف
        if (findings['http11_server'] and findings['keepalive_server']
                and findings['http11_server'] != findings['keepalive_server']):
            findings['anomaly'] = (
                f"Server header changes with Connection type: "
                f"{findings['http11_server']} vs {findings['keepalive_server']}"
            )

        # هل هناك X-Forwarded-For في الرد؟ → proxy يكشف نفسه
        fwd = r1.get_header('x-forwarded-for') or r1.get_header('x-real-ip')
        if fwd:
            findings['proxy_leak'] = f"Proxy leaks internal IP: {fwd}"

        return findings

    # ── 2. HTTP Method Behavior ──────────────────────────────────
    async def _probe_method_behavior(self, url: str) -> Dict:
        """
        اختبار طرق HTTP غير المعتادة.
        TRACE كشف: يعكس headers وقد يكشف credentials داخلية.
        OPTIONS: يكشف الطرق المسموحة.
        HEAD vs GET: هل نفس الـ headers؟
        """
        findings: Dict[str, Any] = {}

        # HEAD
        head_r = await self.engine.request(url, method='HEAD')
        findings['head_status'] = head_r.status
        findings['head_server'] = head_r.get_header('server')

        # OPTIONS — يكشف CORS و Allow header
        opt_r = await self.engine.request(url, method='OPTIONS')
        allow = opt_r.get_header('allow')
        cors  = opt_r.get_header('access-control-allow-origin')
        findings['options_status']  = opt_r.status
        findings['allowed_methods'] = allow
        findings['cors_wildcard']   = (cors == '*')

        if cors == '*':
            findings['cors_issue'] = 'CORS wildcard (*) — any origin can read responses'

        # TRACE — مخصص فقط لكشف XST
        trace_r = await self.engine.request(url, method='TRACE')
        if trace_r.status == 200 and 'TRACE' in (trace_r.body[:200]):
            findings['xst_vulnerable'] = True
            findings['xst_detail']     = 'TRACE method enabled — XST attack possible'

        # PUT على مسار عشوائي — هل يقبل؟
        put_r = await self.engine.request(
            url.rstrip('/') + '/recon_dz_probe_delete_me.txt',
            method='PUT', data=b'probe'
        )
        if put_r.status in (200, 201, 204):
            findings['arbitrary_write'] = (
                f'PUT method accepted (HTTP {put_r.status}) — file upload possible')

        return findings

    # ── 3. Header Manipulation ───────────────────────────────────
    async def _probe_header_manipulation(self, url: str) -> Dict:
        """
        الفكرة الأساسية: WAF يتحقق من headers معينة.
        إذا غيرنا قيمة X-Forwarded-For، هل يتغير الرد؟
        → كشف IP-based bypasses.

        Host header injection: هل يقبل host مختلف؟
        → كشف virtual hosting misconfiguration.
        """
        findings: Dict[str, Any] = {}
        host = url.split('://')[-1].split('/')[0]

        probes = [
            # X-Forwarded-For spoofing — هل يؤثر على الـ WAF؟
            ('xff_localhost',   {'X-Forwarded-For': '127.0.0.1'}),
            ('xff_internal',    {'X-Forwarded-For': '10.0.0.1'}),
            ('xff_cloudflare',  {'X-Forwarded-For': '1.1.1.1'}),
            # Real-IP header bypass
            ('x_real_ip',       {'X-Real-IP': '127.0.0.1'}),
            ('x_originating',   {'X-Originating-IP': '127.0.0.1'}),
            # Content negotiation
            ('accept_json',     {'Accept': 'application/json'}),
            ('accept_xml',      {'Accept': 'application/xml'}),
            # Fake host — virtual host probing
            ('host_internal',   {'Host': f'internal.{host}'}),
            ('host_admin',      {'Host': f'admin.{host}'}),
            # Cache poisoning probe
            ('cache_buster',    {'X-Cache-Key': 'recon-dz-probe',
                                 'X-Forwarded-Host': f'evil.{host}'}),
        ]

        baseline = await self.engine.request(url)
        baseline_hash = _body_hash(baseline.body)
        baseline_status = baseline.status

        for name, hdrs in probes:
            try:
                r = await self.engine.request(url, extra_headers=hdrs)
                diff = {
                    'status':      r.status,
                    'size_diff':   len(r.body) - len(baseline.body),
                    'server_diff': r.get_header('server') != baseline.get_header('server'),
                    'body_diff':   _body_hash(r.body) != baseline_hash,
                }
                # شذوذ: تغير الـ status أو الـ body
                if diff['status'] != baseline_status or diff['body_diff']:
                    diff['anomaly'] = (
                        f"Response differs with {name}: "
                        f"status {baseline_status}→{diff['status']}, "
                        f"size_diff={diff['size_diff']}"
                    )
                findings[name] = diff
            except Exception as e:
                findings[name] = {'error': str(e)}

        # Host header injection test
        try:
            host_inject = await self.engine.request(
                url, extra_headers={'Host': 'evil-host.com'})
            if host_inject.status < 400:
                findings['host_header_injection'] = (
                    f'Host header injection accepted (status {host_inject.status})'
                    ' — potential cache poisoning / SSRF'
                )
        except Exception:
            pass

        return findings

    # ── 4. Error Page Diversity ──────────────────────────────────
    async def _probe_error_diversity(self, url: str) -> Dict:
        """
        كل 40x error يكشف معلومات مختلفة.
        نقارن 404 من مسارات مختلفة لاكتشاف:
        - هل هناك "soft 404" (يرجع 200 لمسارات غير موجودة)
        - هل تختلف صفحات 404 حسب نوع الملف؟ → path enumeration possible
        - هل رسالة 500 تكشف framework/version؟
        """
        findings: Dict[str, Any] = {}
        base = url.rstrip('/')

        probes = [
            (f'{base}/recon_dz_404_test_xyz123',          'generic_404'),
            (f'{base}/recon_dz_404_test_xyz123.php',      '404_php'),
            (f'{base}/recon_dz_404_test_xyz123.asp',      '404_asp'),
            (f'{base}/recon_dz_404_test_xyz123.jsp',      '404_jsp'),
            (f'{base}/recon_dz_404_test_xyz123/',         '404_dir'),
            (f'{base}/admin/recon_dz_404_test',           '404_admin'),
            (f'{base}/api/recon_dz_404_test',             '404_api'),
        ]

        responses = await asyncio.gather(
            *[self.engine.request(p) for p, _ in probes],
            return_exceptions=True
        )

        hashes   = set()
        statuses = set()
        for (path, label), resp in zip(probes, responses):
            if isinstance(resp, Exception):
                continue
            h = _body_hash(resp.body)
            s = resp.status
            statuses.add(s)
            hashes.add(h)
            findings[label] = {'status': s, 'size': len(resp.body), 'hash': h}

            # Soft 404 detection
            if s == 200:
                findings['soft_404_detected'] = (
                    f'{path} returned 200 — soft 404 may hide real content')

        # هل تختلف صفحات 404 حسب نوع الملف؟
        if len(hashes) > 2:
            findings['error_page_diversity'] = (
                f'{len(hashes)} unique error pages for {len(probes)} probes '
                '— server reveals path context (enumeration possible)')

        # هل يوجد 500 error؟ → يكشف framework
        for (path, label), resp in zip(probes, responses):
            if isinstance(resp, ResponseData) and resp.status == 500:
                framework_leak = _detect_framework_from_error(resp.body)
                if framework_leak:
                    findings['framework_from_500'] = framework_leak

        return findings

    # ── 5. Cache Behavior ────────────────────────────────────────
    async def _probe_cache_behavior(self, url: str) -> Dict:
        """
        Cache poisoning surface analysis.
        نرسل نفس الطلب مرتين ونقارن:
        - هل X-Cache يختلف؟ → cache hit/miss behavior
        - هل Vary header يكشف ما يُؤثر على الـ cache؟
        - هل Age header يكشف cache TTL؟
        """
        findings: Dict[str, Any] = {}

        r1 = await self.engine.request(url)
        await asyncio.sleep(0.3)
        r2 = await self.engine.request(url)

        findings['xcache_r1'] = r1.get_header('x-cache')
        findings['xcache_r2'] = r2.get_header('x-cache')
        findings['age_r1']    = r1.get_header('age')
        findings['age_r2']    = r2.get_header('age')
        findings['vary']      = r1.get_header('vary')
        findings['etag']      = r1.get_header('etag')
        findings['cache_control'] = r1.get_header('cache-control')

        # هل Vary: * ؟ → cache uncacheable
        vary = r1.get_header('vary', '')
        if 'accept-encoding' not in vary.lower() and vary:
            findings['unusual_vary'] = (
                f'Vary: {vary} — unusual Vary header may indicate cache poisoning surface')

        # هل الـ ETag يكشف inode؟ (Apache القديم)
        etag = r1.get_header('etag', '')
        if re.match(r'"[0-9a-f]+-[0-9a-f]+-[0-9a-f]+"', etag):
            findings['etag_inode_leak'] = (
                f'ETag format {etag} may expose inode number (Apache < 2.4)')

        # Cache poisoning test: هل يقبل X-Forwarded-Host في الـ cache key؟
        r3 = await self.engine.request(url, extra_headers={
            'X-Forwarded-Host': 'evil.attacker.com'})
        body3 = r3.body[:500]
        if 'evil.attacker.com' in body3:
            findings['cache_poisoning_risk'] = (
                'CRITICAL: X-Forwarded-Host reflected in response — '
                'cache poisoning possible')

        return findings

    # ── 6. Encoding Behavior ─────────────────────────────────────
    async def _probe_encoding_behavior(self, url: str) -> Dict:
        """
        Double encoding / unicode normalization bypass probes.
        نختبر هل الـ WAF يُطبّق normalisation قبل الـ backend؟
        إذا كان الجواب لا → bypass ممكن.
        """
        findings: Dict[str, Any] = {}
        base = url.rstrip('/')

        encoding_probes = [
            # Double URL encoding
            ('double_encoded_slash',  f'{base}/%252e%252e/'),
            # Unicode normalization
            ('unicode_dot_dot',       f'{base}/\u002e\u002e/'),
            # Null byte
            ('null_byte',             f'{base}/test%00.php'),
            # Path normalization
            ('path_normalize',        f'{base}/./'),
            ('double_slash',          f'{base}//'),
            ('trailing_dot',          f'{base}/test.'),
        ]

        baseline = await self.engine.request(f'{base}/')
        baseline_status = baseline.status

        for name, probe_url in encoding_probes:
            try:
                r = await self.engine.request(probe_url)
                diff = r.status != baseline_status or len(r.body) != len(baseline.body)
                if diff:
                    findings[name] = {
                        'status':   r.status,
                        'baseline': baseline_status,
                        'anomaly':  f'Response differs for {name} — potential bypass'
                    }
            except Exception:
                pass

        return findings

    # ── 7. Timing Patterns ───────────────────────────────────────
    async def _probe_timing_patterns(self, url: str) -> Dict:
        """
        Time-based fingerprinting.
        الفرق في أوقات الاستجابة بين مسارات موجودة وغير موجودة
        يكشف وجود مسارات خفية حتى لو أرجعت 404.
        """
        findings: Dict[str, Any] = {}
        base = url.rstrip('/')

        # قياس baseline timing (5 requests)
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            await self.engine.request(url)
            times.append((time.perf_counter() - t0) * 1000)

        avg_baseline = sum(times) / len(times)
        findings['baseline_ms'] = round(avg_baseline, 1)

        # مسارات حساسة — هل تختلف أوقاتها؟
        sensitive = [
            ('/admin/', '/wp-admin/', '/phpmyadmin/', '/api/',
             '/graphql', '/api/v1/', '/api/v2/')
        ][0]

        timing_results = {}
        for path in sensitive:
            t0 = time.perf_counter()
            r  = await self.engine.request(base + path)
            elapsed = (time.perf_counter() - t0) * 1000

            timing_results[path] = {
                'ms':     round(elapsed, 1),
                'status': r.status,
                'diff':   round(elapsed - avg_baseline, 1),
            }

            # إذا استغرقت أكثر من 2x baseline → likely exists (DB query)
            if elapsed > avg_baseline * 2.5 and r.status in (403, 404):
                timing_results[path]['timing_anomaly'] = (
                    f'Path {path} took {round(elapsed,1)}ms vs baseline {round(avg_baseline,1)}ms '
                    '— likely exists despite 404/403 response')

        findings['path_timing'] = timing_results
        return findings

    # ── 8. Path Traversal Clues ──────────────────────────────────
    async def _probe_path_traversal_clues(self, url: str) -> Dict:
        """
        لا نحاول path traversal بشكل مباشر (هذا active attack).
        لكن نكشف هل السيرفر يُطبّق normalisation أم لا
        من خلال ردوده على مسارات صحيحة بصيغ مختلفة.
        """
        findings: Dict[str, Any] = {}
        base = url.rstrip('/')

        test_pairs = [
            (f'{base}/',         f'{base}/./',    'dot_slash_normalized'),
            (f'{base}/',         f'{base}/a/../', 'dotdot_normalized'),
            (f'{base}/index',    f'{base}/Index', 'case_sensitivity'),
        ]

        for url_a, url_b, label in test_pairs:
            try:
                ra = await self.engine.request(url_a)
                rb = await self.engine.request(url_b)
                same = (ra.status == rb.status
                        and _body_hash(ra.body) == _body_hash(rb.body))
                findings[label] = {
                    'normalized': same,
                    'status_a':   ra.status,
                    'status_b':   rb.status,
                }
                if label == 'case_sensitivity' and not same:
                    findings['case_sensitive_fs'] = (
                        'Filesystem is case-sensitive (Linux) — '
                        'case-variation bypass may work on WAF rules')
            except Exception:
                pass

        return findings

    # ── 9. Protocol Quirks ───────────────────────────────────────
    async def _probe_protocol_quirks(self, url: str) -> Dict:
        """
        اختبارات مستوى البروتوكول.
        نكشف: هل السيرفر يقبل طلبات ناقصة الـ headers؟
        هل يكشف معلومات في رد أخطاء البروتوكول؟
        """
        findings: Dict[str, Any] = {}

        # هل Content-Length خاطئ يسبب مشكلة؟
        r = await self.engine.request(url, extra_headers={
            'Content-Length': '99999',
            'Transfer-Encoding': 'chunked',
        })
        if r.status not in (400, 413, 0):
            findings['te_cl_desync'] = (
                f'Server accepts conflicting TE+CL headers (status {r.status}) '
                '— potential HTTP request smuggling surface')

        # هل Accept-Encoding يختلف الرد عند gzip؟
        r_gz = await self.engine.request(url, extra_headers={
            'Accept-Encoding': 'gzip, deflate'})
        r_no = await self.engine.request(url, extra_headers={
            'Accept-Encoding': 'identity'})
        findings['gzip_enabled'] = r_gz.get_header('content-encoding') == 'gzip'

        # هل الـ server يكشف version في X-Powered-By?
        xpb = r.get_header('x-powered-by')
        if xpb:
            findings['x_powered_by'] = xpb
            ver = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', xpb)
            if ver:
                findings['version_leak'] = (
                    f'X-Powered-By reveals version: {xpb}')

        return findings

    # ── 10. TLS Deep Analysis ────────────────────────────────────
    async def _probe_tls_details(self, url: str) -> Dict:
        """
        تحليل TLS أعمق من مجرد "HTTPS نعم/لا".
        نكشف: cipher suites ضعيفة، protocols قديمة، cert chains.
        """
        findings: Dict[str, Any] = {}
        if not url.startswith('https'):
            findings['https'] = False
            return findings

        findings['https'] = True
        host = url.split('://')[-1].split('/')[0].split(':')[0]
        port = 443

        try:
            loop = asyncio.get_event_loop()

            def _get_tls_info():
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        return {
                            'protocol':    ssock.version(),
                            'cipher':      ssock.cipher(),
                            'cert':        ssock.getpeercert(),
                        }

            info = await asyncio.wait_for(
                loop.run_in_executor(None, _get_tls_info),
                timeout=10.0
            )

            proto  = info.get('protocol', '')
            cipher = info.get('cipher', ('', '', 0))
            cert   = info.get('cert', {})

            findings['tls_protocol'] = proto
            findings['cipher_suite'] = cipher[0] if cipher else None
            findings['key_bits']     = cipher[2] if len(cipher) > 2 else None

            # ضعيف: TLSv1.0 أو TLSv1.1
            if proto in ('TLSv1', 'TLSv1.1'):
                findings['weak_tls'] = (
                    f'{proto} is deprecated since 2020 — upgrade to TLS 1.2+')

            # cipher ضعيف
            if cipher and cipher[0]:
                c = cipher[0].upper()
                if 'RC4' in c:
                    findings['weak_cipher'] = 'RC4 cipher — broken, trivially crackable'
                elif 'MD5' in c:
                    findings['weak_cipher'] = 'MD5 in cipher suite — collision attacks'
                elif 'NULL' in c:
                    findings['weak_cipher'] = 'NULL cipher — NO encryption at all'
                elif 'EXPORT' in c:
                    findings['weak_cipher'] = 'EXPORT cipher — downgrade attack possible'
                elif ('DES' in c and '3DES' not in c):
                    findings['weak_cipher'] = 'DES cipher — 56-bit, easily broken'

            # cert expiry
            if cert and cert.get('notAfter'):
                try:
                    expiry = ssl.cert_time_to_seconds(cert['notAfter'])
                    remaining_days = int((expiry - time.time()) / 86400)
                    findings['cert_expires_days'] = remaining_days
                    if remaining_days < 30:
                        findings['cert_expiry_warning'] = (
                            f'Certificate expires in {remaining_days} days')
                    elif remaining_days < 0:
                        findings['cert_expired'] = 'Certificate EXPIRED'
                except Exception:
                    pass

            # SAN / alt names
            if cert:
                sans = cert.get('subjectAltName', [])
                findings['cert_sans_count'] = len(sans)
                if len(sans) > 100:
                    findings['wildcard_rich_cert'] = (
                        f'{len(sans)} SANs — may indicate shared hosting / CDN')

        except Exception as e:
            findings['tls_error'] = str(e)

        return findings


# ═══════════════════════════════════════════════════════════════════════
#  ATTACK SURFACE MAPPER  — يربط النقاط ويولّد خريطة الثغرات
# ═══════════════════════════════════════════════════════════════════════

class AttackSurfaceMapper:
    """
    يأخذ جميع المعلومات المجمعة ويولّد:
    1. قائمة AttackVectors مرتبة حسب احتمالية النجاح
    2. Attack chains (تسلسل الهجوم)
    3. Defense recommendations
    """

    def analyze(self,
                behavior:    Dict,
                cms_info:    List[Dict],
                vuln_findings: List,
                server_fp:   Dict,
                open_ports:  List[Dict],
                subdomains:  List) -> List[AttackVector]:
        """
        subdomains: قائمة تحتوي إما نصوصًا (أسماء نطاقات) أو قواميس تحتوي مفتاح 'domain'
        """
        vectors: List[AttackVector] = []

        vectors.extend(self._from_behavior(behavior))
        vectors.extend(self._from_cms(cms_info))
        vectors.extend(self._from_ports(open_ports))
        vectors.extend(self._from_subdomains(subdomains))
        vectors.extend(self._from_server_fp(server_fp))

        # ترتيب: severity أولاً ثم confidence
        _sev = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        vectors.sort(key=lambda v: (_sev.get(v.severity, 9), -v.confidence))

        return vectors

    def _from_behavior(self, beh: Dict) -> List[AttackVector]:
        vectors: List[AttackVector] = []

        # CORS Wildcard
        mb = beh.get('method_behavior', {})
        if mb.get('cors_wildcard'):
            vectors.append(AttackVector(
                name='CORS Wildcard Misconfiguration',
                category='misconfig',
                severity='high',
                confidence=0.95,
                evidence=['Access-Control-Allow-Origin: * detected'],
                defense='Restrict CORS to trusted origins only.',
                chain_next=['credential_theft', 'api_abuse'],
            ))

        if mb.get('xst_vulnerable'):
            vectors.append(AttackVector(
                name='Cross-Site Tracing (XST)',
                category='injection',
                severity='medium',
                confidence=0.9,
                evidence=['TRACE method enabled'],
                defense='Disable TRACE method in server config.',
            ))

        if mb.get('arbitrary_write'):
            vectors.append(AttackVector(
                name='Arbitrary File Write via PUT',
                category='rce',
                severity='critical',
                confidence=0.85,
                evidence=[mb['arbitrary_write']],
                defense='Disable PUT method unless required.',
                chain_next=['rce_via_webshell'],
            ))

        # Header manipulation anomalies
        hm = beh.get('header_manipulation', {})
        if hm.get('host_header_injection'):
            vectors.append(AttackVector(
                name='Host Header Injection',
                category='misconfig',
                severity='high',
                confidence=0.8,
                evidence=[hm['host_header_injection']],
                bypass_hint='Use Host: evil.com to poison cache or trigger SSRF',
                defense='Validate Host header against whitelist.',
                chain_next=['cache_poisoning', 'ssrf'],
            ))

        if hm.get('cache_poisoning_risk'):
            vectors.append(AttackVector(
                name='Cache Poisoning via X-Forwarded-Host',
                category='injection',
                severity='critical',
                confidence=0.9,
                evidence=[hm['cache_poisoning_risk']],
                defense='Strip unrecognized forwarding headers at edge.',
                chain_next=['reflected_xss_via_cache'],
            ))

        # Cache behavior
        cb = beh.get('cache_behavior', {})
        if cb.get('etag_inode_leak'):
            vectors.append(AttackVector(
                name='ETag Inode Disclosure',
                category='info_leak',
                severity='low',
                confidence=0.7,
                evidence=[cb['etag_inode_leak']],
                defense='Configure FileETag MTime Size in Apache.',
            ))

        # Protocol quirks
        pq = beh.get('protocol_quirks', {})
        if pq.get('te_cl_desync'):
            vectors.append(AttackVector(
                name='HTTP Request Smuggling Surface',
                category='injection',
                severity='critical',
                confidence=0.6,
                evidence=[pq['te_cl_desync']],
                bypass_hint='TE-CL desync may bypass WAF and reach backend directly',
                defense='Normalize TE/CL headers at reverse proxy.',
                chain_next=['waf_bypass', 'cache_deception'],
                cve_hints=['CVE-2020-11724', 'CVE-2019-18277'],
            ))

        if pq.get('version_leak'):
            vectors.append(AttackVector(
                name='Version Disclosure via X-Powered-By',
                category='info_leak',
                severity='low',
                confidence=1.0,
                evidence=[pq['version_leak']],
                defense='Remove X-Powered-By header.',
            ))

        # Timing anomalies
        tp = beh.get('timing_patterns', {})
        pt = tp.get('path_timing', {}) if isinstance(tp, dict) else {}
        for path, pdata in pt.items():
            if isinstance(pdata, dict) and pdata.get('timing_anomaly'):
                vectors.append(AttackVector(
                    name=f'Timing Anomaly — Hidden Path: {path}',
                    category='info_leak',
                    severity='medium',
                    confidence=0.65,
                    evidence=[pdata['timing_anomaly']],
                    bypass_hint='Path likely exists despite 404 — try with different methods',
                    defense='Ensure consistent response times for all 404s.',
                ))

        # TLS issues
        tls = beh.get('tls_details', {})
        if tls.get('weak_tls'):
            vectors.append(AttackVector(
                name='Weak TLS Protocol',
                category='misconfig',
                severity='high',
                confidence=1.0,
                evidence=[tls['weak_tls']],
                defense='Disable TLS 1.0/1.1. Enable only TLS 1.2 and 1.3.',
                cve_hints=['CVE-2011-3389 (BEAST)', 'POODLE'],
            ))
        if tls.get('weak_cipher'):
            vectors.append(AttackVector(
                name='Weak Cipher Suite',
                category='misconfig',
                severity='high',
                confidence=1.0,
                evidence=[tls['weak_cipher']],
                defense='Configure strong cipher suites only (AES-GCM, ChaCha20).',
            ))
        if tls.get('cert_expired'):
            vectors.append(AttackVector(
                name='Expired TLS Certificate',
                category='misconfig',
                severity='high',
                confidence=1.0,
                evidence=['Certificate is expired'],
                defense='Renew certificate immediately.',
            ))

        # Encoding bypass
        enc = beh.get('encoding_behavior', {})
        for probe_name, data in enc.items():
            if isinstance(data, dict) and data.get('anomaly'):
                vectors.append(AttackVector(
                    name=f'Encoding Bypass Surface: {probe_name}',
                    category='injection',
                    severity='medium',
                    confidence=0.6,
                    evidence=[data['anomaly']],
                    bypass_hint='Server normalizes differently than WAF — bypass possible',
                    defense='Normalize URLs at WAF level before backend.',
                ))

        # Error diversity → enumeration
        ed = beh.get('error_diversity', {})
        if ed.get('error_page_diversity'):
            vectors.append(AttackVector(
                name='Error-Based Path Enumeration',
                category='info_leak',
                severity='medium',
                confidence=0.75,
                evidence=[ed['error_page_diversity']],
                defense='Standardize all error page responses.',
            ))
        if ed.get('soft_404_detected'):
            vectors.append(AttackVector(
                name='Soft 404 — Hidden Content',
                category='info_leak',
                severity='low',
                confidence=0.7,
                evidence=[ed['soft_404_detected']],
                defense='Return proper 404 status for non-existent resources.',
            ))

        # HTTP version anomalies
        hv = beh.get('http_versions', {})
        if hv.get('proxy_leak'):
            vectors.append(AttackVector(
                name='Internal IP Disclosure via Proxy Headers',
                category='info_leak',
                severity='medium',
                confidence=0.9,
                evidence=[hv['proxy_leak']],
                defense='Strip X-Forwarded-For and X-Real-IP from outbound responses.',
            ))

        return vectors

    def _from_cms(self, cms_list: List[Dict]) -> List[AttackVector]:
        vectors: List[AttackVector] = []
        if not cms_list:
            return vectors

        cms = cms_list[0]
        name    = cms.get('name', '')
        version = cms.get('version')

        # CMS known vulnerabilities mapping
        cms_vulns: Dict[str, List[Dict]] = {
            'WordPress': [
                {'ver_prefix': '5.',  'cve': 'CVE-2022-21661', 'name': 'SQL Injection in WP_Query', 'sev': 'critical'},
                {'ver_prefix': '4.',  'cve': 'CVE-2019-8942',  'name': 'RCE via image metadata',    'sev': 'critical'},
                {'ver_prefix': '',    'cve': 'CVE-2023-2745',  'name': 'Directory Traversal',        'sev': 'high'},
            ],
            'Joomla': [
                {'ver_prefix': '3.',  'cve': 'CVE-2023-23752', 'name': 'Improper Access Check → Info Leak', 'sev': 'high'},
                {'ver_prefix': '4.0', 'cve': 'CVE-2022-23796', 'name': 'XSS in Admin',               'sev': 'medium'},
            ],
            'Drupal': [
                {'ver_prefix': '8.',  'cve': 'CVE-2018-7600',  'name': 'Drupalgeddon 2 — RCE',      'sev': 'critical'},
                {'ver_prefix': '9.',  'cve': 'CVE-2022-25271', 'name': 'Input validation bypass',    'sev': 'high'},
            ],
            'PrestaShop': [
                {'ver_prefix': '',    'cve': 'CVE-2023-30839', 'name': 'SQL Injection',              'sev': 'critical'},
                {'ver_prefix': '1.7', 'cve': 'CVE-2022-31101', 'name': 'XSS via image caption',     'sev': 'medium'},
            ],
            'Magento': [
                {'ver_prefix': '2.',  'cve': 'CVE-2022-24086', 'name': 'Server-Side Template Injection → RCE', 'sev': 'critical'},
                {'ver_prefix': '',    'cve': 'CVE-2023-21394', 'name': 'Stored XSS',                 'sev': 'medium'},
            ],
            'Moodle': [
                {'ver_prefix': '3.',  'cve': 'CVE-2021-36394', 'name': 'RCE via assignment',        'sev': 'critical'},
                {'ver_prefix': '',    'cve': 'CVE-2022-45151', 'name': 'SSRF in file picker',       'sev': 'high'},
            ],
        }

        known = cms_vulns.get(name, [])
        for vuln in known:
            prefix = vuln['ver_prefix']
            if not prefix or (version and version.startswith(prefix)):
                vectors.append(AttackVector(
                    name=f'{name} — {vuln["name"]}',
                    category='injection',
                    severity=vuln['sev'],
                    confidence=0.7 if version else 0.4,
                    evidence=[
                        f'{name} {version or "unknown version"} detected',
                        f'Vulnerability matches version prefix: {prefix or "all versions"}',
                    ],
                    bypass_hint=f'Check {vuln["cve"]} PoC — may need auth or specific config',
                    defense=f'Update {name} to latest stable version. Patch {vuln["cve"]}.',
                    cve_hints=[vuln['cve']],
                ))

        # CMS Admin panel exposure
        admin_paths = {
            'WordPress': '/wp-admin/',
            'Joomla':    '/administrator/',
            'Drupal':    '/user/login',
            'PrestaShop': '/admin/',
        }
        if name in admin_paths:
            vectors.append(AttackVector(
                name=f'{name} Admin Panel Exposed',
                category='auth_bypass',
                severity='medium',
                confidence=0.8,
                evidence=[f'Admin at {admin_paths[name]}'],
                bypass_hint='Try default credentials, bruteforce, or auth bypass CVEs',
                defense=f'Restrict {admin_paths[name]} to trusted IPs.',
                chain_next=['credential_brute_force', 'auth_bypass'],
            ))

        return vectors

    def _from_ports(self, ports: List[Dict]) -> List[AttackVector]:
        vectors: List[AttackVector] = []
        risky = {
            21:   ('FTP Exposed',             'high',   'FTP transmits credentials in plaintext'),
            23:   ('Telnet Exposed',           'critical','Telnet is unencrypted — full credential leak'),
            3306: ('MySQL Exposed to Internet','critical','Database port should never be public'),
            5432: ('PostgreSQL Exposed',       'critical','Database port should never be public'),
            6379: ('Redis Exposed',            'critical','Redis often has no auth — full data access'),
            27017:('MongoDB Exposed',          'critical','MongoDB often has no auth by default'),
            2375: ('Docker API Exposed',       'critical','Unauthenticated Docker = full server control'),
            8080: ('Dev/Test Port Open',       'medium',  'May expose debug interface'),
            8443: ('Alt-HTTPS Port Open',      'low',     'Secondary SSL port'),
            9200: ('Elasticsearch Exposed',    'critical','Elasticsearch often has no auth'),
            5601: ('Kibana Exposed',           'high',    'Kibana admin interface'),
            4848: ('GlassFish Admin Exposed',  'high',    'Java EE admin console'),
        }
        port_nums = {p.get('port') for p in ports if isinstance(p, dict)}
        for port_num, (name, sev, detail) in risky.items():
            if port_num in port_nums:
                vectors.append(AttackVector(
                    name=name,
                    category='misconfig',
                    severity=sev,
                    confidence=1.0,
                    evidence=[f'Port {port_num} open'],
                    defense=f'Firewall port {port_num} from public access.',
                    bypass_hint=detail,
                ))
        return vectors

    def _from_subdomains(self, subs: List) -> List[AttackVector]:
        """
        توليد AttackVectors من قائمة النطاقات الفرعية.
        يدخل subs قائمة قد تحتوي على نصوص أو قواميس بمفتاح 'domain'.
        """
        vectors: List[AttackVector] = []
        risky_keywords = {
            'dev':      ('Development Environment Exposed', 'high'),
            'staging':  ('Staging Environment Exposed', 'high'),
            'test':     ('Test Environment Exposed', 'medium'),
            'old':      ('Old/Legacy Environment Exposed', 'high'),
            'api':      ('API Subdomain — attack surface', 'medium'),
            'admin':    ('Admin Subdomain Exposed', 'high'),
            'vpn':      ('VPN Subdomain Exposed', 'medium'),
            'mail':     ('Mail Server Exposed', 'low'),
            'ftp':      ('FTP Subdomain Exposed', 'high'),
            'git':      ('Git Subdomain — source code exposure risk', 'high'),
            'jenkins':  ('Jenkins CI Exposed', 'critical'),
            'gitlab':   ('GitLab Exposed', 'high'),
            'grafana':  ('Grafana Exposed', 'high'),
            'kibana':   ('Kibana Exposed', 'critical'),
        }

        for sub in subs:
            # استخراج اسم النطاق إذا كان العنصر قاموسًا
            if isinstance(sub, dict):
                domain = sub.get('domain', '')
                if not domain:
                    continue
            else:
                domain = str(sub)

            domain_lower = domain.lower()
            for kw, (name, sev) in risky_keywords.items():
                if kw in domain_lower:
                    vectors.append(AttackVector(
                        name=f'{name}: {domain}',
                        category='misconfig',
                        severity=sev,
                        confidence=0.7,
                        evidence=[f'Subdomain {domain} contains keyword "{kw}"'],
                        defense=f'Remove or restrict access to {domain} if not needed.',
                    ))
                    break  # أول كلمة تظهر تكفي
        return vectors

    def _from_server_fp(self, fp: Dict) -> List[AttackVector]:
        vectors: List[AttackVector] = []
        if not fp:
            return vectors

        # Banner disclosure
        server = fp.get('server') or ''
        ver_m  = re.search(r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', server)
        if ver_m and server:
            vectors.append(AttackVector(
                name=f'Server Version Disclosed: {server}',
                category='info_leak',
                severity='low',
                confidence=1.0,
                evidence=[f'Server header: {server}'],
                defense='Remove version from Server header.',
            ))

        return vectors


# ═══════════════════════════════════════════════════════════════════════
#  INTELLIGENCE ENGINE — الواجهة الرئيسية
# ═══════════════════════════════════════════════════════════════════════

class IntelligenceEngine:
    """
    الواجهة الموحدة.
    يأخذ base_url + جميع البيانات المجمعة،
    يشغل BehavioralFingerprinter + AttackSurfaceMapper،
    يرجع تقرير ذكاء كامل.
    """

    def __init__(self, engine: AsyncReconEngine):
        self.engine   = engine
        self.behavior = BehavioralFingerprinter(engine)
        self.mapper   = AttackSurfaceMapper()

    async def analyze(self,
                      base_url:     str,
                      cms_info:     Optional[List[Dict]]  = None,
                      vuln_findings: Optional[List]       = None,
                      server_fp:    Optional[Dict]        = None,
                      open_ports:   Optional[List[Dict]]  = None,
                      subdomains:   Optional[List]        = None,
                      ) -> Dict[str, Any]:
        """
        تشغيل التحليل الكامل.
        """
        t0 = datetime.utcnow()

        # Behavioral fingerprinting (parallel probes)
        behavior = await self.behavior.run(base_url)

        # Server personality extraction
        personality = _extract_personality(behavior, server_fp or {})

        # Attack surface mapping
        vectors = self.mapper.analyze(
            behavior     = behavior,
            cms_info     = cms_info or [],
            vuln_findings= vuln_findings or [],
            server_fp    = server_fp or {},
            open_ports   = open_ports or [],
            subdomains   = subdomains or [],
        )

        # Attack chain builder
        chains = _build_attack_chains(vectors)

        # Risk score
        risk = _calculate_risk_score(vectors)

        elapsed = (datetime.utcnow() - t0).total_seconds()

        return {
            'base_url':      base_url,
            'analyzed_at':   t0.isoformat(),
            'elapsed_s':     round(elapsed, 2),
            'risk_score':    risk,
            'risk_grade':    _risk_grade(risk),
            'personality':   personality.__dict__,
            'behavior':      behavior,
            'attack_vectors': [v.to_dict() for v in vectors],
            'attack_chains': chains,
            'total_vectors': len(vectors),
            'critical':      sum(1 for v in vectors if v.severity == 'critical'),
            'high':          sum(1 for v in vectors if v.severity == 'high'),
            'medium':        sum(1 for v in vectors if v.severity == 'medium'),
            'low':           sum(1 for v in vectors if v.severity == 'low'),
        }


# ═══════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════

def _body_hash(body: str) -> str:
    return hashlib.sha256(body[:5000].encode('utf-8', errors='replace')).hexdigest()[:16]


def _detect_framework_from_error(body: str) -> Optional[str]:
    body_l = body.lower()
    patterns = [
        ('Laravel',      'whoops! there was an error'),
        ('Django',       'djangotemplatesdoesnotexist'),
        ('Rails',        'actioncontroller::routingerror'),
        ('Spring Boot',  'whitelabel error page'),
        ('ASP.NET',      'runtime error'),
        ('PHP',          'fatal error'),
        ('Node.js',      'cannot get /'),
    ]
    for name, sig in patterns:
        if sig in body_l:
            return f'{name} stack trace detected in 500 error'
    return None


def _extract_personality(behavior: Dict, server_fp: Dict) -> ServerPersonality:
    p = ServerPersonality()
    hv = behavior.get('http_versions', {})
    pq = behavior.get('protocol_quirks', {})

    p.server_type = hv.get('http11_server')
    p.http_version = 'HTTP/1.1'  # default
    p.cache_behavior = ('cached' if behavior.get('cache_behavior', {}).get('xcache_r2')
                        else 'no-cache')

    xpb = pq.get('x_powered_by', '')
    if 'php' in xpb.lower():
        p.backend_language = 'PHP'
    elif 'asp.net' in xpb.lower():
        p.backend_language = 'ASP.NET'
    elif 'express' in xpb.lower():
        p.backend_language = 'Node.js'

    # Detect true server behind proxy
    via = hv.get('http11_via', '')
    if via:
        p.unique_markers.append(f'Via: {via}')
        if 'nginx' in via.lower():
            p.true_server = 'Nginx (via header)'
        elif 'apache' in via.lower():
            p.true_server = 'Apache (via header)'

    return p


def _build_attack_chains(vectors: List[AttackVector]) -> List[Dict]:
    """
    يبني تسلسلات هجوم منطقية من العلاقات بين الـ vectors.
    """
    chains = []
    # chain: info_leak → credential_attack → rce
    has_info_leak  = any(v.category == 'info_leak' for v in vectors)
    has_auth       = any(v.category == 'auth_bypass' for v in vectors)
    has_injection  = any(v.category == 'injection'  for v in vectors)
    has_misconfig  = any(v.category == 'misconfig'  for v in vectors)

    if has_info_leak and has_injection:
        chains.append({
            'name':  'Recon → Exploit Chain',
            'steps': [
                'Information disclosure reveals backend technology/version',
                'Known CVE identified for discovered version',
                'Exploit via injection vulnerability',
            ],
            'likelihood': 'HIGH',
        })

    if has_misconfig and has_auth:
        chains.append({
            'name':  'Misconfiguration → Privilege Escalation',
            'steps': [
                'Misconfigured access controls discovered',
                'Admin panel accessible from internet',
                'Bruteforce or default credentials attempt',
                'Full admin access obtained',
            ],
            'likelihood': 'HIGH',
        })

    if has_injection:
        chains.append({
            'name':  'WAF Bypass → Direct Exploit',
            'steps': [
                'Behavioral analysis reveals WAF/backend discrepancy',
                'Encoding bypass or HTTP smuggling identified',
                'Payload reaches backend unfiltered',
            ],
            'likelihood': 'MEDIUM',
        })

    return chains


def _calculate_risk_score(vectors: List[AttackVector]) -> int:
    weights = {'critical': 40, 'high': 20, 'medium': 8, 'low': 2}
    total = 0
    for v in vectors:
        total += int(weights.get(v.severity, 0) * v.confidence)
    return min(total, 100)


def _risk_grade(score: int) -> str:
    if score >= 80: return 'CRITICAL'
    if score >= 60: return 'HIGH'
    if score >= 40: return 'MEDIUM'
    if score >= 20: return 'LOW'
    return 'MINIMAL'
