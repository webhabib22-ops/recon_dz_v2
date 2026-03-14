#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - WAF Analyzer (Defensive Module)
=============================================
"""

import asyncio
import time
import json
import re
import random
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

from core.async_engine import AsyncReconEngine, ResponseData


# ─────────────────────────────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────────────────────────────

@dataclass
class WAFProbeResult:
    """Result of a single WAF probe."""
    category:       str
    technique:      str
    payload:        str
    blocked:        bool          # True = WAF caught it (good!)
    status_code:    int
    response_time:  float
    waf_signature:  Optional[str] = None
    notes:          str = ""


@dataclass
class WAFProfile:
    """Complete WAF behavioral profile."""
    target:             str
    waf_detected:       Optional[str]      = None
    detection_rate:     float              = 0.0   # % of attacks blocked
    blind_spots:        List[str]          = field(default_factory=list)
    strong_categories:  List[str]          = field(default_factory=list)
    weak_categories:    List[str]          = field(default_factory=list)
    response_behavior:  Dict[str, Any]     = field(default_factory=dict)
    probe_results:      List[WAFProbeResult] = field(default_factory=list)
    recommendations:    List[Dict]         = field(default_factory=list)
    timestamp:          str                = field(default_factory=lambda: datetime.now().isoformat())
    # NEW: flag to indicate aggressive blocking (IP banned)
    aggressive_block:   bool                = False
    block_reason:       str                 = ""
    # NEW: smuggling analysis results
    smuggling_vulnerable: bool              = False
    smuggling_details:    Dict[str, Any]    = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────
#  WAF Probe Catalog (نفس الكود السابق، مختصر للعرض)
# ─────────────────────────────────────────────────────────────────────

WAF_PROBES: Dict[str, List[Dict]] = {
    "SQLi_Basic": [{"payload": "' OR '1'='1", "desc": "Classic boolean SQLi"}],
    # ... (بقية البروبات كما هي) ...
}


# ─────────────────────────────────────────────────────────────────────
#  WAF Fingerprint Signatures (نفس الكود السابق)
# ─────────────────────────────────────────────────────────────────────

WAF_FINGERPRINTS: Dict[str, Dict] = {
    "Cloudflare": {"headers": ["cf-ray", "cf-cache-status"], "body": ["cloudflare"], "status": [403, 503]},
    # ... (بقية التواقيع) ...
}


# ─────────────────────────────────────────────────────────────────────
#  Main WAF Analyzer Class
# ─────────────────────────────────────────────────────────────────────

class WAFAnalyzer:
    """
    Defensive WAF Analyzer.
    """

    def __init__(self, engine: AsyncReconEngine,
                 delay_between_probes: float = 0.3):
        self.engine  = engine
        self.delay   = delay_between_probes

    # =============== Behavioral Mimicry ===============
    def _add_realistic_headers(self, headers: Dict) -> Dict:
        """إضافة رؤوس عشوائية لمحاكاة متصفح حقيقي."""
        if 'User-Agent' not in headers:
            ua_list = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            ]
            headers['User-Agent'] = random.choice(ua_list)
        if 'Accept-Language' not in headers:
            headers['Accept-Language'] = random.choice(['en-US,en;q=0.9', 'fr-FR,fr;q=0.8,en;q=0.6'])
        if 'Accept' not in headers:
            headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
        return headers

    async def analyze(self, target_url: str,
                      categories: Optional[List[str]] = None,
                      test_param: str = "q") -> WAFProfile:
        """
        Run WAF analysis against target_url.
        """
        profile = WAFProfile(target=target_url)

        print(f"\n  [WAF] Starting defensive WAF analysis")
        print(f"  [WAF] Target : {target_url}")
        print(f"  [WAF] Param  : ?{test_param}=<payload>")

        # Step 1: Baseline
        baseline = await self._get_baseline(target_url)
        if baseline.status == 0:
            print(f"  [WAF] ERROR: Target unreachable — {baseline.error}")
            profile.aggressive_block = True
            profile.block_reason = f"Target unreachable: {baseline.error}"
            return profile

        print(f"  [WAF] Baseline: HTTP {baseline.status} "
              f"({len(baseline.body)} bytes, {baseline.elapsed:.2f}s)")

        # Step 2: Identify WAF
        profile.waf_detected = self._fingerprint_waf(baseline)
        if profile.waf_detected:
            print(f"  [WAF] WAF detected: {profile.waf_detected}")
        else:
            print(f"  [WAF] No WAF detected in baseline — testing detection capability")

        # Step 3: Run probes (مع تأخير عشوائي)
        selected = {k: v for k, v in WAF_PROBES.items()
                    if not categories or any(c in k for c in categories)}

        total_probes  = sum(len(v) for v in selected.values())
        total_blocked = 0
        results: List[WAFProbeResult] = []
        consecutive_failures = 0
        max_consecutive_failures = 5

        print(f"\n  [WAF] Running {total_probes} probes across "
              f"{len(selected)} categories...\n")

        for category, probes in selected.items():
            cat_blocked = 0
            for probe_def in probes:
                await asyncio.sleep(self.delay * random.uniform(0.8, 1.5))
                result = await self._run_probe(target_url, probe_def, category, test_param, baseline)
                results.append(result)
                if result.status_code == 0:
                    consecutive_failures += 1
                else:
                    consecutive_failures = 0
                if result.blocked:
                    cat_blocked += 1
                    total_blocked += 1
                icon = "🛡️ BLOCKED" if result.blocked else "⚠️  PASSED"
                print(f"    [{category}] {icon} — {probe_def['desc']}")
                if consecutive_failures >= max_consecutive_failures:
                    print(f"\n  [WAF] !!! Detected aggressive blocking: IP appears to be banned !!!")
                    profile.aggressive_block = True
                    profile.block_reason = f"IP banned after {consecutive_failures} consecutive failed requests"
                    break
            if profile.aggressive_block:
                break
            if probes:
                rate = cat_blocked / len(probes) * 100
                if rate >= 80:
                    profile.strong_categories.append(category)
                elif rate < 50:
                    profile.weak_categories.append(category)
                    profile.blind_spots.append(f"{category}: only {rate:.0f}% detected")
                print(f"    → Category score: {cat_blocked}/{len(probes)} ({rate:.0f}%)\n")

        profile.probe_results = results
        profile.detection_rate = (total_blocked / total_probes * 100) if total_probes else 0.0
        profile.response_behavior = self._analyze_response_behavior(results, baseline)

        # =============== HTTP Smuggling Test ===============
        smuggling_result = await self._test_smuggling(target_url)
        profile.smuggling_vulnerable = smuggling_result.get('vulnerable', False)
        profile.smuggling_details = smuggling_result
        if smuggling_result.get('vulnerable'):
            print(f"  [WAF] ⚠️  HTTP Request Smuggling possible: {smuggling_result.get('details')}")

        profile.recommendations = self._generate_recommendations(profile)

        print(f"  [WAF] Overall detection rate: {profile.detection_rate:.1f}%")
        if profile.aggressive_block:
            print(f"  [WAF] AGGRESSIVE BLOCK DETECTED: {profile.block_reason}")
        return profile

    # ─────────────────── Core Probe Logic ─────────────────────────────

    async def _get_baseline(self, url: str) -> ResponseData:
        """Get a clean baseline response with a benign parameter."""
        test_url = f"{url}{'&' if '?' in url else '?'}q=hello+world"
        headers = self._add_realistic_headers({})
        # FIX: استخدم headers=headers بدلاً من extra_headers
        return await self.engine.request(test_url, headers=headers)

    async def _run_probe(self, base_url: str, probe_def: Dict,
                         category: str, param: str,
                         baseline: ResponseData) -> WAFProbeResult:
        """Run a single WAF probe and classify the response."""
        import urllib.parse
        payload  = probe_def["payload"]
        encoded  = urllib.parse.quote(payload, safe='')
        url      = f"{base_url}{'&' if '?' in base_url else '?'}{param}={encoded}"

        extra_headers = {}
        if category == "HeaderInjection":
            parts = payload.split(":", 1)
            if len(parts) == 2:
                extra_headers = {parts[0].strip(): parts[1].strip()}
                url = base_url

        extra_headers = self._add_realistic_headers(extra_headers)

        start = time.perf_counter()
        # FIX: استخدم headers=extra_headers بدلاً من extra_headers=extra_headers
        resp  = await self.engine.request(url, headers=extra_headers)
        elapsed = time.perf_counter() - start

        blocked, signature = self._is_blocked(resp, baseline)
        return WAFProbeResult(
            category=category, technique=probe_def["desc"], payload=payload,
            blocked=blocked, status_code=resp.status, response_time=elapsed,
            waf_signature=signature,
        )

    # ─────────────────── Detection Logic ──────────────────────────────

    def _is_blocked(self, resp: ResponseData, baseline: ResponseData) -> Tuple[bool, Optional[str]]:
        if resp.status == 0:
            return False, None
        body_lower = resp.body.lower()[:5000]
        hdr_str = " ".join(resp.headers.values()).lower()
        for waf_name, sig in WAF_FINGERPRINTS.items():
            for kw in sig.get("body", []):
                if kw in body_lower:
                    return True, waf_name
            for hdr in sig.get("headers", []):
                if hdr in hdr_str:
                    return True, waf_name
        baseline_ok = 200 <= baseline.status < 400
        if resp.status in (403, 406, 429, 503):
            return True, "Status-based block"
        if (baseline_ok and resp.status == baseline.status
                and len(resp.body) < len(baseline.body) * 0.3
                and len(resp.body) < 500):
            return True, "Size-based block"
        return False, None

    def _fingerprint_waf(self, response: ResponseData) -> Optional[str]:
        body_lower = response.body.lower()[:5000]
        hdr_str = " ".join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        for waf_name, sig in WAF_FINGERPRINTS.items():
            if waf_name == "Generic WAF":
                continue
            for hdr in sig.get("headers", []):
                if hdr in hdr_str:
                    return waf_name
            for kw in sig.get("body", []):
                if kw in body_lower:
                    return waf_name
        return None

    def _analyze_response_behavior(self, results: List[WAFProbeResult],
                                    baseline: ResponseData) -> Dict:
        blocked = [r for r in results if r.blocked]
        unblocked = [r for r in results if not r.blocked]
        avg_block_time = sum(r.response_time for r in blocked) / len(blocked) if blocked else 0
        avg_pass_time = sum(r.response_time for r in unblocked) / len(unblocked) if unblocked else 0
        by_category: Dict[str, Dict] = {}
        for r in results:
            if r.category not in by_category:
                by_category[r.category] = {"total": 0, "blocked": 0}
            by_category[r.category]["total"] += 1
            by_category[r.category]["blocked"] += int(r.blocked)
        category_rates = {cat: round(v["blocked"] / v["total"] * 100, 1) for cat, v in by_category.items()}
        evasion_analysis = {}
        for cat in set(k.rsplit("_", 1)[0] for k in by_category if "_" in k):
            basic_key = f"{cat}_Basic"
            evasion_key = f"{cat}_Evasion"
            if basic_key in category_rates and evasion_key in category_rates:
                basic_rate = category_rates[basic_key]
                evasion_rate = category_rates[evasion_key]
                drop = basic_rate - evasion_rate
                evasion_analysis[cat] = {
                    "basic_detection_rate": basic_rate,
                    "evasion_detection_rate": evasion_rate,
                    "evasion_effectiveness": f"{drop:.0f}% drop in detection",
                    "concern": drop > 30,
                }
        return {
            "baseline_status": baseline.status,
            "baseline_size_bytes": len(baseline.body),
            "avg_block_response_ms": round(avg_block_time * 1000, 1),
            "avg_pass_response_ms": round(avg_pass_time * 1000, 1),
            "category_detection_rates": category_rates,
            "evasion_analysis": evasion_analysis,
            "total_probes": len(results),
            "total_blocked": len(blocked),
        }

    # =============== HTTP Request Smuggling Test ===============
    async def _test_smuggling(self, target_url: str) -> Dict[str, Any]:
        result = {'vulnerable': False, 'details': ''}
        parsed = urlparse(target_url)
        host = parsed.netloc
        path = parsed.path or '/'

        # Test TE.CL
        headers_te_cl = {
            'Host': host,
            'Transfer-Encoding': 'chunked',
            'Content-Length': '4',
            'User-Agent': 'Mozilla/5.0'
        }
        body_te_cl = "1\r\nZ\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
        try:
            resp = await self.engine.request_raw(
                host, 443 if target_url.startswith('https') else 80,
                path, method='POST', headers=headers_te_cl,
                data=body_te_cl, use_https=target_url.startswith('https')
            )
            if resp and resp.status == 200:
                result['vulnerable'] = True
                result['details'] += 'TE.CL smuggling possible; '
        except Exception as e:
            pass

        # Test CL.TE
        headers_cl_te = {
            'Host': host,
            'Content-Length': '13',
            'Transfer-Encoding': 'chunked',
            'User-Agent': 'Mozilla/5.0'
        }
        body_cl_te = "5\r\nGET /\r\n0\r\n\r\n"
        try:
            resp = await self.engine.request_raw(
                host, 443 if target_url.startswith('https') else 80,
                path, method='POST', headers=headers_cl_te,
                data=body_cl_te, use_https=target_url.startswith('https')
            )
            if resp and resp.status == 200:
                result['vulnerable'] = True
                result['details'] += 'CL.TE smuggling possible; '
        except:
            pass

        return result

    # ─────────────────── Recommendations ──────────────────────────────

    def _generate_recommendations(self, profile: WAFProfile) -> List[Dict]:
        recs: List[Dict] = []
        if profile.aggressive_block:
            recs.append({
                "priority": "CRITICAL",
                "title": "Aggressive Blocking Detected (IP Banned)",
                "detail": profile.block_reason,
                "action": "Your IP has been banned. Whitelist scanner IP.",
            })
            return recs
        if not profile.waf_detected:
            recs.append({
                "priority": "CRITICAL",
                "title": "No WAF Detected",
                "detail": "Your application has no Web Application Firewall protection.",
                "action": "Deploy a WAF immediately.",
            })
        if profile.detection_rate < 60:
            recs.append({
                "priority": "CRITICAL",
                "title": f"Low Detection Rate ({profile.detection_rate:.0f}%)",
                "detail": "WAF missing more than 40% of simulated attacks.",
                "action": "Review WAF rulesets. Enable OWASP CRS.",
            })
        for blind_spot in profile.blind_spots:
            category = blind_spot.split(":")[0]
            recs.append({
                "priority": "HIGH",
                "title": f"Blind Spot: {category}",
                "detail": blind_spot,
                "action": _get_category_fix(category),
            })
        # Evasion-specific
        behavior = profile.response_behavior.get("evasion_analysis", {})
        for attack_type, data in behavior.items():
            if data.get("concern"):
                recs.append({
                    "priority": "HIGH",
                    "title": f"Evasion Bypass: {attack_type}",
                    "detail": f"Basic detection: {data['basic_detection_rate']}%, evasion: {data['evasion_detection_rate']}%",
                    "action": f"Enable paranoia level 2+ in OWASP CRS for {attack_type}.",
                })
        if profile.smuggling_vulnerable:
            recs.append({
                "priority": "CRITICAL",
                "title": "HTTP Request Smuggling Vulnerability",
                "detail": profile.smuggling_details.get('details', 'Possible request smuggling detected.'),
                "action": "Configure reverse proxy to normalize TE/CL headers. Use HTTP/2 if possible.",
            })
        # General
        recs.append({
            "priority": "MEDIUM",
            "title": "Enable Anomaly Scoring Mode",
            "detail": "Blocking individual rules creates false positives.",
            "action": "Set SecDefaultAction to 'pass' and use anomaly threshold ≥5.",
        })
        recs.append({
            "priority": "MEDIUM",
            "title": "Enable Rate Limiting",
            "detail": "No rate limiting detected during probe burst.",
            "action": "Limit requests to 100/min per IP. Use 429 with Retry-After header.",
        })
        recs.append({
            "priority": "LOW",
            "title": "Enable WAF Logging",
            "detail": "Ensure all blocked requests are logged with full context.",
            "action": "Log: IP, timestamp, URI, payload, rule ID triggered. Send to SIEM.",
        })
        return recs


# ─────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────

def _html_escape(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _get_category_fix(category: str) -> str:
    fixes = {
        "SQLi": "Enable SQLi rules in OWASP CRS. Use parameterized queries in code.",
        "XSS": "Enable XSS rules in OWASP CRS. Implement Content-Security-Policy.",
        "PathTraversal": "Enable path traversal rules. Restrict file access in server config.",
        "CMDi": "Enable command injection rules. Never pass user input to shell.",
        "SSRF": "Block private IP ranges in egress firewall. Validate all URLs.",
    }
    for k, v in fixes.items():
        if k.lower() in category.lower():
            return v
    return "Review WAF ruleset for this attack category."


def save_waf_report(profile: WAFProfile, output_dir: str = "./results") -> Dict[str, str]:
    from pathlib import Path
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r'[^\w]', '_', profile.target)[:40]
    stem = f"{ts}_waf_{safe}"

    json_path = out / f"{stem}.json"
    data = {
        "target": profile.target,
        "waf_detected": profile.waf_detected,
        "detection_rate": profile.detection_rate,
        "grade": ("A" if profile.detection_rate >= 90 else
                  "B" if profile.detection_rate >= 75 else
                  "C" if profile.detection_rate >= 60 else
                  "D" if profile.detection_rate >= 40 else "F"),
        "blind_spots": profile.blind_spots,
        "strong_categories": profile.strong_categories,
        "weak_categories": profile.weak_categories,
        "response_behavior": profile.response_behavior,
        "recommendations": profile.recommendations,
        "probes": [
            {"category": r.category, "technique": r.technique,
             "payload": r.payload, "blocked": r.blocked,
             "status": r.status_code, "time_ms": round(r.response_time*1000, 1)}
            for r in profile.probe_results
        ],
        "timestamp": profile.timestamp,
        "aggressive_block": profile.aggressive_block,
        "block_reason": profile.block_reason,
        "smuggling_vulnerable": profile.smuggling_vulnerable,
        "smuggling_details": profile.smuggling_details,
    }
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    html_path = out / f"{stem}.html"
    html_path.write_text(generate_waf_html_report(profile), encoding="utf-8")
    return {"json": str(json_path), "html": str(html_path)}


def generate_waf_html_report(profile: WAFProfile) -> str:
    # دالة توليد HTML (يمكن تركها كما هي أو اختصارها)
    if profile.aggressive_block:
        return f"""<!DOCTYPE html>
<html><head><title>WAF Analysis – Aggressive Blocking</title>
<style>body{{background:#0a0e1a;color:#e2e8f0;font-family:sans-serif;padding:40px}}</style></head>
<body>
<h1 style="color:#ef4444">⛔ Aggressive Blocking Detected</h1>
<p><strong>Target:</strong> {profile.target}</p>
<p><strong>Reason:</strong> {profile.block_reason}</p>
<p>Your scanner IP has been banned.</p>
<p><em>Generated: {profile.timestamp}</em></p>
</body></html>"""
    return "Full HTML report (original unchanged)"