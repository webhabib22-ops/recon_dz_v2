#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - WAF Analyzer (Defensive Module)
=============================================
Purpose: Analyze your own WAF's detection capabilities to identify
         blind spots BEFORE attackers do. All tests are passive probes
         designed to map WAF behavior, not to exploit target systems.

Usage:   Run ONLY against systems you own or have written authorization to test.
"""

import asyncio
import time
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime

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


# ─────────────────────────────────────────────────────────────────────
#  WAF Probe Catalog
#  Each probe tests whether the WAF detects a known attack pattern.
#  These are the SAME patterns real attackers use — knowing your WAF
#  blocks them is essential for defensive posture assessment.
# ─────────────────────────────────────────────────────────────────────

WAF_PROBES: Dict[str, List[Dict]] = {

    # ── SQL Injection ─────────────────────────────────────────────────
    "SQLi_Basic": [
        {"payload": "' OR '1'='1",           "desc": "Classic boolean SQLi"},
        {"payload": "' OR 1=1--",            "desc": "Comment-based SQLi"},
        {"payload": "1; DROP TABLE users--", "desc": "Stacked query SQLi"},
        {"payload": "' UNION SELECT 1,2,3--","desc": "UNION-based SQLi"},
        {"payload": "admin'--",              "desc": "Auth bypass SQLi"},
    ],
    "SQLi_Evasion": [
        {"payload": "' /*!OR*/ '1'='1",      "desc": "MySQL inline comment bypass"},
        {"payload": "' %09OR%09'1'='1",      "desc": "Tab character evasion"},
        {"payload": "' OORR '1'='1",         "desc": "Double keyword evasion"},
        {"payload": "'\t OR\t'1'='1",        "desc": "Whitespace variation"},
        {"payload": "%27%20OR%20%271%27%3D%271", "desc": "URL-encoded SQLi"},
        {"payload": "' OR/**/'1'='1",        "desc": "Comment-based whitespace bypass"},
        {"payload": "'+OR+'1'%3D'1",         "desc": "Mixed encoding SQLi"},
    ],

    # ── Cross-Site Scripting ──────────────────────────────────────────
    "XSS_Basic": [
        {"payload": "<script>alert(1)</script>",        "desc": "Basic XSS"},
        {"payload": "<img src=x onerror=alert(1)>",     "desc": "Img onerror XSS"},
        {"payload": "javascript:alert(1)",              "desc": "JS protocol XSS"},
        {"payload": "<svg onload=alert(1)>",            "desc": "SVG onload XSS"},
        {"payload": "\"><script>alert(1)</script>",     "desc": "Attribute breakout XSS"},
    ],
    "XSS_Evasion": [
        {"payload": "<ScRiPt>alert(1)</ScRiPt>",        "desc": "Case variation XSS"},
        {"payload": "<script>alert`1`</script>",        "desc": "Template literal XSS"},
        {"payload": "<img src=x onerror=&#97;lert(1)>", "desc": "HTML entity XSS"},
        {"payload": "%3Cscript%3Ealert(1)%3C/script%3E","desc": "URL-encoded XSS"},
        {"payload": "<scr\x00ipt>alert(1)</script>",    "desc": "Null byte XSS"},
        {"payload": "<svg><script>alert(1)</script>",   "desc": "SVG nested script"},
        {"payload": "<<script>alert(1)//<</script>",    "desc": "Double-bracket evasion"},
    ],

    # ── Path Traversal ────────────────────────────────────────────────
    "PathTraversal_Basic": [
        {"payload": "../../../../etc/passwd",           "desc": "Unix path traversal"},
        {"payload": "..\\..\\..\\windows\\win.ini",     "desc": "Windows path traversal"},
        {"payload": "/etc/passwd",                       "desc": "Absolute path"},
        {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd",  "desc": "URL-encoded traversal"},
    ],
    "PathTraversal_Evasion": [
        {"payload": "....//....//etc/passwd",           "desc": "Double-dot evasion"},
        {"payload": "..%252f..%252fetc%252fpasswd",     "desc": "Double URL-encoded"},
        {"payload": "%2e%2e/%2e%2e/etc/passwd",         "desc": "Mixed encoding traversal"},
        {"payload": "..%c0%af..%c0%afetc/passwd",       "desc": "Unicode slash traversal"},
        {"payload": "/./././etc/passwd",                 "desc": "Dot normalization bypass"},
    ],

    # ── Command Injection ─────────────────────────────────────────────
    "CMDi_Basic": [
        {"payload": "; ls -la",               "desc": "Basic command injection"},
        {"payload": "| whoami",               "desc": "Pipe injection"},
        {"payload": "`id`",                   "desc": "Backtick injection"},
        {"payload": "$(id)",                  "desc": "Subshell injection"},
        {"payload": "&& cat /etc/passwd",     "desc": "AND injection"},
    ],
    "CMDi_Evasion": [
        {"payload": ";l%73",                  "desc": "URL-encoded command"},
        {"payload": ";w'h'o'a'm'i",           "desc": "Quote splitting evasion"},
        {"payload": ";wh\\oami",              "desc": "Backslash evasion"},
        {"payload": "$IFS$()ls",              "desc": "IFS-based space bypass"},
        {"payload": ";{ls,-la}",              "desc": "Brace expansion injection"},
    ],

    # ── SSRF (Server-Side Request Forgery) ────────────────────────────
    "SSRF_Basic": [
        {"payload": "http://127.0.0.1/",                    "desc": "Localhost SSRF"},
        {"payload": "http://169.254.169.254/latest/meta-data/", "desc": "AWS metadata SSRF"},
        {"payload": "http://[::1]/",                         "desc": "IPv6 loopback SSRF"},
        {"payload": "http://0.0.0.0/",                       "desc": "Zero IP SSRF"},
    ],
    "SSRF_Evasion": [
        {"payload": "http://127.0.0.1.nip.io/",              "desc": "DNS rebinding SSRF"},
        {"payload": "http://2130706433/",                    "desc": "Decimal IP SSRF"},
        {"payload": "http://0x7f000001/",                    "desc": "Hex IP SSRF"},
        {"payload": "http://localhost:80@evil.com/",         "desc": "URL confusion SSRF"},
        {"payload": "dict://127.0.0.1:6379/",               "desc": "Dict protocol SSRF"},
    ],

    # ── HTTP Header Injection ─────────────────────────────────────────
    "HeaderInjection": [
        {"payload": "X-Forwarded-For: 127.0.0.1",           "desc": "IP spoofing header"},
        {"payload": "X-Real-IP: 127.0.0.1",                 "desc": "Real IP spoof"},
        {"payload": "X-Originating-IP: 127.0.0.1",          "desc": "Origin IP spoof"},
        {"payload": "X-Custom-IP-Authorization: 127.0.0.1", "desc": "Custom auth header"},
        {"payload": "X-Forwarded-Host: evil.com",           "desc": "Host header injection"},
    ],

    # ── Large Payload / DoS Protection ────────────────────────────────
    "PayloadSize": [
        {"payload": "A" * 1000,   "desc": "1KB payload"},
        {"payload": "A" * 8000,   "desc": "8KB payload"},
        {"payload": "A" * 65536,  "desc": "64KB payload"},
    ],

    # ── Protocol / Encoding Tricks ────────────────────────────────────
    "EncodingTricks": [
        {"payload": "%00",               "desc": "Null byte injection"},
        {"payload": "%0d%0a",            "desc": "CRLF injection"},
        {"payload": "\u003cscript\u003e","desc": "Unicode script tag"},
        {"payload": "&#60;script&#62;",  "desc": "HTML entity tags"},
        {"payload": "+ADw-script+AD4-",  "desc": "UTF-7 XSS"},
    ],
}


# ─────────────────────────────────────────────────────────────────────
#  WAF Fingerprint Signatures
# ─────────────────────────────────────────────────────────────────────

WAF_FINGERPRINTS: Dict[str, Dict] = {
    "Cloudflare": {
        "headers":     ["cf-ray", "cf-cache-status", "__cfduid"],
        "body":        ["cloudflare", "error 1010", "error 1020"],
        "status":      [403, 503],
        "block_page":  "attention required",
    },
    "AWS WAF": {
        "headers":     ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id"],
        "body":        ["aws", "403 forbidden"],
        "status":      [403],
    },
    "Imperva / Incapsula": {
        "headers":     ["x-iinfo", "incap_ses", "visid_incap"],
        "body":        ["incapsula", "request unsuccessful"],
        "status":      [403],
    },
    "ModSecurity": {
        "headers":     ["x-modsecurity", "mod_security"],
        "body":        ["modsecurity", "not acceptable", "406 not acceptable"],
        "status":      [403, 406],
    },
    "Sucuri": {
        "headers":     ["x-sucuri-id", "x-sucuri-cache"],
        "body":        ["sucuri", "access denied"],
        "status":      [403],
    },
    "F5 BIG-IP ASM": {
        "headers":     ["x-cnection", "x-wa-info", "bigipserver"],
        "body":        ["the requested url was rejected", "f5"],
        "status":      [403],
    },
    "Akamai": {
        "headers":     ["akamai-grn", "x-check-cacheable", "ak_bmsc"],
        "body":        ["access denied", "akamai"],
        "status":      [403],
    },
    "Fortinet": {
        "headers":     ["fortigate", "fortiwan"],
        "body":        ["fortigate", "fortiwall"],
        "status":      [403],
    },
    "Generic WAF": {
        "body":        ["blocked", "security policy", "illegal request",
                        "bad request", "request rejected", "web application firewall"],
        "status":      [403, 406, 429, 503],
    },
}


# ─────────────────────────────────────────────────────────────────────
#  Main WAF Analyzer Class
# ─────────────────────────────────────────────────────────────────────

class WAFAnalyzer:
    """
    Defensive WAF Analyzer.

    Sends known attack patterns to your own WAF and measures:
    - Detection rate (% blocked)
    - Which attack categories are missed (blind spots)
    - How quickly the WAF responds to attacks
    - Whether evasion techniques bypass detection
    - WAF identity and behavioral fingerprint

    Use the WAFProfile output to harden your WAF ruleset.
    """

    def __init__(self, engine: AsyncReconEngine,
                 delay_between_probes: float = 0.3):
        self.engine  = engine
        self.delay   = delay_between_probes

    async def analyze(self, target_url: str,
                      categories: Optional[List[str]] = None,
                      test_param: str = "q") -> WAFProfile:
        """
        Run WAF analysis against target_url.

        Args:
            target_url:  Full URL (e.g. https://yoursite.dz/search)
            categories:  Specific categories to test (None = all)
            test_param:  GET parameter to inject payloads into
        Returns:
            WAFProfile with full behavioral analysis
        """
        profile = WAFProfile(target=target_url)

        print(f"\n  [WAF] Starting defensive WAF analysis")
        print(f"  [WAF] Target : {target_url}")
        print(f"  [WAF] Param  : ?{test_param}=<payload>")

        # Step 1: Baseline — get normal response fingerprint
        baseline = await self._get_baseline(target_url)
        if baseline.status == 0:
            print(f"  [WAF] ERROR: Target unreachable — {baseline.error}")
            return profile

        print(f"  [WAF] Baseline: HTTP {baseline.status} "
              f"({len(baseline.body)} bytes, {baseline.elapsed:.2f}s)")

        # Step 2: Identify WAF from baseline
        profile.waf_detected = self._fingerprint_waf(baseline)
        if profile.waf_detected:
            print(f"  [WAF] WAF detected: {profile.waf_detected}")
        else:
            print(f"  [WAF] No WAF detected in baseline — testing detection capability")

        # Step 3: Run probes
        selected = {k: v for k, v in WAF_PROBES.items()
                    if not categories or any(c in k for c in categories)}

        total_probes  = sum(len(v) for v in selected.values())
        total_blocked = 0
        results: List[WAFProbeResult] = []

        print(f"\n  [WAF] Running {total_probes} probes across "
              f"{len(selected)} categories...\n")

        for category, probes in selected.items():
            cat_blocked = 0
            cat_results: List[WAFProbeResult] = []

            for probe_def in probes:
                await asyncio.sleep(self.delay)

                result = await self._run_probe(
                    target_url, probe_def, category,
                    test_param, baseline
                )
                cat_results.append(result)
                results.append(result)

                if result.blocked:
                    cat_blocked += 1
                    total_blocked += 1

                icon = "🛡️ BLOCKED" if result.blocked else "⚠️  PASSED"
                print(f"    [{category}] {icon} — {probe_def['desc']}")

            # Category summary
            rate = cat_blocked / len(probes) * 100 if probes else 0
            if rate >= 80:
                profile.strong_categories.append(category)
            elif rate < 50:
                profile.weak_categories.append(category)
                profile.blind_spots.append(
                    f"{category}: only {rate:.0f}% detected"
                )
            print(f"    → Category score: {cat_blocked}/{len(probes)} "
                  f"({rate:.0f}%)\n")

        profile.probe_results    = results
        profile.detection_rate   = (total_blocked / total_probes * 100
                                     if total_probes else 0)

        # Step 4: Behavioral analysis
        profile.response_behavior = self._analyze_response_behavior(results, baseline)

        # Step 5: Generate recommendations
        profile.recommendations = self._generate_recommendations(profile)

        print(f"  [WAF] Overall detection rate: {profile.detection_rate:.1f}%")
        print(f"  [WAF] Strong categories : {profile.strong_categories}")
        print(f"  [WAF] Weak categories   : {profile.weak_categories}")

        return profile

    # ─────────────────── Core Probe Logic ─────────────────────────────

    async def _get_baseline(self, url: str) -> ResponseData:
        """Get a clean baseline response with a benign parameter."""
        test_url = f"{url}{'&' if '?' in url else '?'}q=hello+world"
        return await self.engine.request(test_url)

    async def _run_probe(self, base_url: str, probe_def: Dict,
                          category: str, param: str,
                          baseline: ResponseData) -> WAFProbeResult:
        """Run a single WAF probe and classify the response."""
        import urllib.parse
        payload  = probe_def["payload"]
        encoded  = urllib.parse.quote(payload, safe='')
        url      = f"{base_url}{'&' if '?' in base_url else '?'}{param}={encoded}"

        # For header injection probes, inject as headers
        extra_headers = {}
        if category == "HeaderInjection":
            parts = payload.split(":", 1)
            if len(parts) == 2:
                extra_headers = {parts[0].strip(): parts[1].strip()}
                url = base_url

        start = time.perf_counter()
        resp  = await self.engine.request(url, extra_headers=extra_headers)
        elapsed = time.perf_counter() - start

        blocked, signature = self._is_blocked(resp, baseline)

        return WAFProbeResult(
            category      = category,
            technique     = probe_def["desc"],
            payload       = payload,
            blocked       = blocked,
            status_code   = resp.status,
            response_time = elapsed,
            waf_signature = signature,
        )

    # ─────────────────── Detection Logic ──────────────────────────────

    def _is_blocked(self, resp: ResponseData,
                    baseline: ResponseData) -> Tuple[bool, Optional[str]]:
        """
        Determine whether the WAF blocked the request.
        A request is considered blocked if:
        - Status code differs significantly from baseline
        - Response body contains known WAF block signatures
        - Response time is unusually fast (WAF short-circuit)
        """
        if resp.status == 0:
            return False, None

        body_lower = resp.body.lower()[:5000]
        hdr_str    = " ".join(resp.headers.values()).lower()

        # Check known WAF block pages
        for waf_name, sig in WAF_FINGERPRINTS.items():
            for kw in sig.get("body", []):
                if kw in body_lower:
                    return True, waf_name
            for hdr in sig.get("headers", []):
                if hdr in hdr_str:
                    return True, waf_name

        # Status code change from baseline indicates blocking
        baseline_ok = 200 <= baseline.status < 400
        if resp.status in (403, 406, 429, 503):
            return True, "Status-based block"

        # Response size dramatically smaller = likely block page
        if (baseline_ok and resp.status == baseline.status
                and len(resp.body) < len(baseline.body) * 0.3
                and len(resp.body) < 500):
            return True, "Size-based block"

        return False, None

    def _fingerprint_waf(self, response: ResponseData) -> Optional[str]:
        """Identify WAF from a normal response."""
        body_lower = response.body.lower()[:5000]
        hdr_str    = " ".join(
            f"{k}:{v}" for k, v in response.headers.items()
        ).lower()

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

    # ─────────────────── Behavioral Analysis ──────────────────────────

    def _analyze_response_behavior(self, results: List[WAFProbeResult],
                                    baseline: ResponseData) -> Dict:
        """Analyze how the WAF responds behaviorally."""
        blocked   = [r for r in results if r.blocked]
        unblocked = [r for r in results if not r.blocked]

        avg_block_time = (sum(r.response_time for r in blocked) / len(blocked)
                          if blocked else 0)
        avg_pass_time  = (sum(r.response_time for r in unblocked) / len(unblocked)
                          if unblocked else 0)

        # Which categories have worst detection
        by_category: Dict[str, Dict] = {}
        for r in results:
            if r.category not in by_category:
                by_category[r.category] = {"total": 0, "blocked": 0}
            by_category[r.category]["total"]   += 1
            by_category[r.category]["blocked"] += int(r.blocked)

        category_rates = {
            cat: round(v["blocked"] / v["total"] * 100, 1)
            for cat, v in by_category.items()
        }

        # Evasion effectiveness: compare Basic vs Evasion detection
        evasion_analysis = {}
        for cat in set(k.rsplit("_", 1)[0] for k in by_category if "_" in k):
            basic_key   = f"{cat}_Basic"
            evasion_key = f"{cat}_Evasion"
            if basic_key in category_rates and evasion_key in category_rates:
                basic_rate   = category_rates[basic_key]
                evasion_rate = category_rates[evasion_key]
                drop = basic_rate - evasion_rate
                evasion_analysis[cat] = {
                    "basic_detection_rate":   basic_rate,
                    "evasion_detection_rate": evasion_rate,
                    "evasion_effectiveness":  f"{drop:.0f}% drop in detection",
                    "concern": drop > 30,
                }

        return {
            "baseline_status":        baseline.status,
            "baseline_size_bytes":    len(baseline.body),
            "avg_block_response_ms":  round(avg_block_time * 1000, 1),
            "avg_pass_response_ms":   round(avg_pass_time * 1000, 1),
            "category_detection_rates": category_rates,
            "evasion_analysis":       evasion_analysis,
            "total_probes":           len(results),
            "total_blocked":          len(blocked),
        }

    # ─────────────────── Recommendations ──────────────────────────────

    def _generate_recommendations(self, profile: WAFProfile) -> List[Dict]:
        """Generate actionable hardening recommendations."""
        recs: List[Dict] = []

        if not profile.waf_detected:
            recs.append({
                "priority":  "CRITICAL",
                "title":     "No WAF Detected",
                "detail":    "Your application has no Web Application Firewall protection.",
                "action":    "Deploy a WAF immediately. Consider Cloudflare, AWS WAF, or ModSecurity.",
            })

        if profile.detection_rate < 60:
            recs.append({
                "priority": "CRITICAL",
                "title":    f"Low Detection Rate ({profile.detection_rate:.0f}%)",
                "detail":   "Your WAF is missing more than 40% of simulated attacks.",
                "action":   "Review and update WAF rulesets. Enable OWASP CRS (Core Rule Set).",
            })

        for blind_spot in profile.blind_spots:
            category = blind_spot.split(":")[0]
            rec = {
                "priority": "HIGH",
                "title":    f"Blind Spot: {category}",
                "detail":   blind_spot,
                "action":   _get_category_fix(category),
            }
            recs.append(rec)

        # Evasion-specific recommendations
        behavior = profile.response_behavior.get("evasion_analysis", {})
        for attack_type, data in behavior.items():
            if data.get("concern"):
                recs.append({
                    "priority": "HIGH",
                    "title":    f"Evasion Bypass: {attack_type}",
                    "detail":   (f"Basic {attack_type} detection: "
                                 f"{data['basic_detection_rate']}% but "
                                 f"evasion techniques drop to "
                                 f"{data['evasion_detection_rate']}%"),
                    "action":   f"Enable paranoia level 2+ in OWASP CRS for {attack_type}.",
                })

        # General best practices
        recs.append({
            "priority": "MEDIUM",
            "title":    "Enable Anomaly Scoring Mode",
            "detail":   "Blocking individual rules creates false positives. Anomaly scoring accumulates evidence.",
            "action":   "Set SecDefaultAction to 'pass' and use anomaly threshold ≥5.",
        })
        recs.append({
            "priority": "MEDIUM",
            "title":    "Enable Rate Limiting",
            "detail":   "No rate limiting detected during probe burst.",
            "action":   "Limit requests to 100/min per IP. Use 429 with Retry-After header.",
        })
        recs.append({
            "priority": "LOW",
            "title":    "Enable WAF Logging",
            "detail":   "Ensure all blocked requests are logged with full context.",
            "action":   "Log: IP, timestamp, URI, payload, rule ID triggered. Send to SIEM.",
        })

        return recs


# ─────────────────────────────────────────────────────────────────────
#  Report Generator
# ─────────────────────────────────────────────────────────────────────

def generate_waf_html_report(profile: WAFProfile) -> str:
    """
    Generate a professional interactive HTML report from WAFProfile.
    Includes charts, filterable findings table, and recommendations.
    """
    # Build category chart data
    behavior      = profile.response_behavior
    cat_rates     = behavior.get("category_detection_rates", {})
    evasion_data  = behavior.get("evasion_analysis", {})

    categories_js = json.dumps(list(cat_rates.keys()))
    rates_js      = json.dumps(list(cat_rates.values()))

    # Build probe table rows
    probe_rows = ""
    for r in profile.probe_results:
        status_class = "blocked" if r.blocked else "passed"
        icon         = "🛡️" if r.blocked else "⚠️"
        probe_rows  += f"""
        <tr class="{status_class}">
          <td><span class="badge badge-{status_class}">{icon} {'BLOCKED' if r.blocked else 'BYPASSED'}</span></td>
          <td>{r.category}</td>
          <td>{r.technique}</td>
          <td><code class="payload">{_html_escape(r.payload[:60])}{'…' if len(r.payload)>60 else ''}</code></td>
          <td>{r.status_code}</td>
          <td>{r.response_time*1000:.0f}ms</td>
          <td>{r.waf_signature or '—'}</td>
        </tr>"""

    # Build recommendations
    rec_html = ""
    for rec in profile.recommendations:
        prio_class = rec["priority"].lower()
        rec_html  += f"""
        <div class="rec-card rec-{prio_class}">
          <div class="rec-header">
            <span class="rec-badge {prio_class}">{rec['priority']}</span>
            <strong>{rec['title']}</strong>
          </div>
          <p class="rec-detail">{rec['detail']}</p>
          <div class="rec-action"><span class="action-label">▶ Action</span> {rec['action']}</div>
        </div>"""

    # Evasion comparison table
    evasion_html = ""
    for attack, data in evasion_data.items():
        concern_badge = '<span class="badge badge-passed" style="background:#e74c3c">⚠️ CONCERN</span>' if data.get("concern") else '<span class="badge badge-blocked">✓ OK</span>'
        evasion_html += f"""
        <tr>
          <td><strong>{attack}</strong></td>
          <td>{data['basic_detection_rate']}%</td>
          <td>{data['evasion_detection_rate']}%</td>
          <td>{data['evasion_effectiveness']}</td>
          <td>{concern_badge}</td>
        </tr>"""

    overall_color = ("#27ae60" if profile.detection_rate >= 80
                     else "#f39c12" if profile.detection_rate >= 50
                     else "#e74c3c")
    overall_grade = ("A" if profile.detection_rate >= 90
                     else "B" if profile.detection_rate >= 75
                     else "C" if profile.detection_rate >= 60
                     else "D" if profile.detection_rate >= 40
                     else "F")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WAF Analysis Report — {profile.target}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');

  :root {{
    --bg:        #0a0e1a;
    --surface:   #111827;
    --surface2:  #1a2236;
    --border:    #1e3a5f;
    --accent:    #00d4ff;
    --accent2:   #7c3aed;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --green:     #10b981;
    --yellow:    #f59e0b;
    --red:       #ef4444;
    --mono:      'JetBrains Mono', monospace;
    --sans:      'Syne', sans-serif;
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
  }}

  /* ── Header ── */
  .header {{
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1b3e 50%, #0a0e1a 100%);
    border-bottom: 1px solid var(--border);
    padding: 40px 60px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute; inset: 0;
    background: repeating-linear-gradient(
      90deg, transparent, transparent 80px,
      rgba(0,212,255,.03) 80px, rgba(0,212,255,.03) 81px
    );
  }}
  .header-top {{ display: flex; justify-content: space-between; align-items: flex-start; }}
  .logo {{ font-size: 11px; font-family: var(--mono); color: var(--accent); letter-spacing: 3px; text-transform: uppercase; }}
  .report-title {{ font-size: 32px; font-weight: 800; margin: 16px 0 4px; letter-spacing: -1px; }}
  .report-title span {{ color: var(--accent); }}
  .report-meta {{ font-family: var(--mono); font-size: 12px; color: var(--muted); }}
  .grade-box {{
    text-align: center;
    background: rgba(0,0,0,.4);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px 30px;
  }}
  .grade-letter {{ font-size: 64px; font-weight: 800; color: {overall_color}; line-height: 1; }}
  .grade-label {{ font-family: var(--mono); font-size: 11px; color: var(--muted); margin-top: 4px; }}

  /* ── Layout ── */
  .container {{ max-width: 1400px; margin: 0 auto; padding: 40px 60px; }}
  .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
  .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 24px; margin-bottom: 24px; }}
  @media (max-width: 900px) {{ .grid-2, .grid-3 {{ grid-template-columns: 1fr; }} }}

  /* ── Cards ── */
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px;
  }}
  .card-title {{
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--accent);
    margin-bottom: 16px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }}

  /* ── Stat boxes ── */
  .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 24px; }}
  .stat {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    text-align: center;
    position: relative;
    overflow: hidden;
  }}
  .stat::before {{
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--accent2));
  }}
  .stat-value {{ font-size: 36px; font-weight: 800; font-family: var(--mono); color: var(--accent); }}
  .stat-label {{ font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }}

  /* ── Table ── */
  .table-wrap {{ overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12px; }}
  th {{
    background: var(--surface2);
    color: var(--muted);
    font-size: 10px;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }}
  td {{ padding: 10px 14px; border-bottom: 1px solid rgba(30,58,95,.3); vertical-align: middle; }}
  tr:hover td {{ background: rgba(0,212,255,.03); }}
  tr.passed td {{ opacity: .75; }}

  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .5px;
  }}
  .badge-blocked {{ background: rgba(16,185,129,.15); color: var(--green); border: 1px solid rgba(16,185,129,.3); }}
  .badge-passed  {{ background: rgba(239,68,68,.15);  color: var(--red);   border: 1px solid rgba(239,68,68,.3); }}

  code.payload {{
    background: rgba(0,0,0,.4);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 11px;
    color: #fbbf24;
    word-break: break-all;
  }}

  /* ── Filter bar ── */
  .filter-bar {{
    display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;
  }}
  .filter-btn {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--muted);
    padding: 6px 16px;
    border-radius: 20px;
    cursor: pointer;
    font-family: var(--mono);
    font-size: 11px;
    transition: all .2s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent);
    border-color: var(--accent);
    color: #000;
  }}

  /* ── Recommendations ── */
  .rec-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 18px;
    margin-bottom: 12px;
    border-left: 4px solid var(--border);
  }}
  .rec-card.rec-critical {{ border-left-color: var(--red); }}
  .rec-card.rec-high     {{ border-left-color: var(--yellow); }}
  .rec-card.rec-medium   {{ border-left-color: var(--accent); }}
  .rec-card.rec-low      {{ border-left-color: var(--green); }}
  .rec-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .rec-badge {{
    display: inline-block; padding: 2px 10px; border-radius: 4px;
    font-size: 10px; font-weight: 700; font-family: var(--mono);
  }}
  .rec-badge.critical {{ background: rgba(239,68,68,.2);  color: var(--red); }}
  .rec-badge.high     {{ background: rgba(245,158,11,.2); color: var(--yellow); }}
  .rec-badge.medium   {{ background: rgba(0,212,255,.1);  color: var(--accent); }}
  .rec-badge.low      {{ background: rgba(16,185,129,.1); color: var(--green); }}
  .rec-detail {{ color: var(--muted); font-size: 13px; margin-bottom: 10px; }}
  .rec-action {{ font-family: var(--mono); font-size: 12px; background: rgba(0,0,0,.3); padding: 10px 14px; border-radius: 6px; border-left: 2px solid var(--accent); }}
  .action-label {{ color: var(--accent); font-weight: 700; margin-right: 8px; }}

  /* ── Donut ── */
  .donut-wrap {{ position: relative; width: 160px; height: 160px; margin: 0 auto 16px; }}
  .donut-center {{
    position: absolute; top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    text-align: center;
  }}
  .donut-pct {{ font-size: 26px; font-weight: 800; color: var(--accent); font-family: var(--mono); }}
  .donut-sub {{ font-size: 10px; color: var(--muted); }}

  /* ── Section headers ── */
  .section-title {{
    font-size: 20px; font-weight: 800; margin: 40px 0 20px;
    display: flex; align-items: center; gap: 12px;
  }}
  .section-title::after {{
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, var(--border), transparent);
  }}

  /* ── Footer ── */
  footer {{
    text-align: center;
    padding: 30px;
    color: var(--muted);
    font-family: var(--mono);
    font-size: 11px;
    border-top: 1px solid var(--border);
    margin-top: 60px;
  }}
</style>
</head>
<body>

<!-- ── Header ─────────────────────────────────────────────── -->
<div class="header">
  <div class="header-top">
    <div>
      <div class="logo">RECON-DZ v3 · Defensive WAF Analysis</div>
      <h1 class="report-title">WAF <span>Behavior</span> Report</h1>
      <p class="report-meta">
        Target: {profile.target} &nbsp;|&nbsp;
        WAF: {profile.waf_detected or 'Not detected'} &nbsp;|&nbsp;
        Generated: {profile.timestamp}
      </p>
    </div>
    <div class="grade-box">
      <div class="grade-letter">{overall_grade}</div>
      <div class="grade-label">WAF Grade</div>
    </div>
  </div>
</div>

<div class="container">

<!-- ── Stats ─────────────────────────────────────────────── -->
<div class="stat-grid">
  <div class="stat">
    <div class="stat-value">{profile.detection_rate:.0f}%</div>
    <div class="stat-label">Detection Rate</div>
  </div>
  <div class="stat">
    <div class="stat-value">{behavior.get('total_blocked', 0)}</div>
    <div class="stat-label">Attacks Blocked</div>
  </div>
  <div class="stat">
    <div class="stat-value">{behavior.get('total_probes', 0) - behavior.get('total_blocked', 0)}</div>
    <div class="stat-label">Attacks Bypassed</div>
  </div>
  <div class="stat">
    <div class="stat-value">{len(profile.blind_spots)}</div>
    <div class="stat-label">Blind Spots Found</div>
  </div>
</div>

<!-- ── Charts row ─────────────────────────────────────────── -->
<div class="grid-2">
  <div class="card">
    <div class="card-title">Detection Rate by Attack Category</div>
    <canvas id="barChart" height="220"></canvas>
  </div>
  <div class="card">
    <div class="card-title">Overall WAF Coverage</div>
    <div class="donut-wrap">
      <canvas id="donutChart"></canvas>
      <div class="donut-center">
        <div class="donut-pct">{profile.detection_rate:.0f}%</div>
        <div class="donut-sub">blocked</div>
      </div>
    </div>
    <div style="margin-top:16px">
      <p style="font-size:12px;color:var(--muted);margin-bottom:8px">Category Summary</p>
      {"".join(f'<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(30,58,95,.3);font-family:var(--mono);font-size:12px"><span>{cat}</span><span style="color:{"var(--green)" if r>=80 else "var(--yellow)" if r>=50 else "var(--red)"}">{r:.0f}%</span></div>' for cat, r in cat_rates.items())}
    </div>
  </div>
</div>

<!-- ── Evasion Analysis ───────────────────────────────────── -->
{'<h2 class="section-title">Evasion Technique Analysis</h2><div class="card"><div class="card-title">Basic vs Evasion Detection Rate</div><div class="table-wrap"><table><thead><tr><th>Attack Type</th><th>Basic Detection</th><th>Evasion Detection</th><th>Drop</th><th>Status</th></tr></thead><tbody>' + evasion_html + '</tbody></table></div></div>' if evasion_html else ''}

<!-- ── Probe Results Table ────────────────────────────────── -->
<h2 class="section-title">Detailed Probe Results</h2>
<div class="card">
  <div class="card-title">All Probes</div>
  <div class="filter-bar" id="filterBar">
    <button class="filter-btn active" onclick="filterTable('all')">All</button>
    <button class="filter-btn" onclick="filterTable('blocked')">🛡️ Blocked</button>
    <button class="filter-btn" onclick="filterTable('passed')">⚠️ Bypassed</button>
    {"".join(f'<button class="filter-btn" onclick="filterCat(\'{c}\')">{c}</button>' for c in cat_rates.keys())}
  </div>
  <div class="table-wrap">
    <table id="probeTable">
      <thead>
        <tr>
          <th>Status</th><th>Category</th><th>Technique</th>
          <th>Payload</th><th>HTTP</th><th>Time</th><th>WAF Rule</th>
        </tr>
      </thead>
      <tbody>{probe_rows}</tbody>
    </table>
  </div>
</div>

<!-- ── Recommendations ───────────────────────────────────── -->
<h2 class="section-title">Hardening Recommendations</h2>
{rec_html}

</div><!-- /container -->

<footer>
  RECON-DZ v3 · WAF Defensive Analysis · Authorized Use Only<br>
  {profile.timestamp}
</footer>

<script>
// ── Bar Chart ──────────────────────────────────────────────
const categories = {categories_js};
const rates      = {rates_js};
const colors     = rates.map(r => r >= 80 ? '#10b981' : r >= 50 ? '#f59e0b' : '#ef4444');

new Chart(document.getElementById('barChart'), {{
  type: 'bar',
  data: {{
    labels: categories,
    datasets: [{{
      label: 'Detection Rate %',
      data: rates,
      backgroundColor: colors,
      borderRadius: 6,
      borderSkipped: false,
    }}]
  }},
  options: {{
    responsive: true,
    plugins: {{ legend: {{ display: false }}, tooltip: {{ callbacks: {{ label: ctx => ctx.raw + '%' }} }} }},
    scales: {{
      x: {{ ticks: {{ color: '#64748b', font: {{ family: 'JetBrains Mono', size: 10 }} }}, grid: {{ color: '#1e3a5f' }} }},
      y: {{ min: 0, max: 100, ticks: {{ color: '#64748b', callback: v => v + '%' }}, grid: {{ color: '#1e3a5f' }} }}
    }}
  }}
}});

// ── Donut Chart ────────────────────────────────────────────
const blocked = {behavior.get('total_blocked', 0)};
const total   = {behavior.get('total_probes', 1)};
new Chart(document.getElementById('donutChart'), {{
  type: 'doughnut',
  data: {{
    datasets: [{{
      data: [blocked, total - blocked],
      backgroundColor: ['#10b981', '#ef4444'],
      borderWidth: 0,
      hoverOffset: 4,
    }}]
  }},
  options: {{
    responsive: true,
    cutout: '72%',
    plugins: {{ legend: {{ display: false }}, tooltip: {{ callbacks: {{ label: ctx => ctx.label + ': ' + ctx.raw }} }} }}
  }}
}});

// ── Table Filtering ────────────────────────────────────────
function filterTable(type) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#probeTable tbody tr').forEach(row => {{
    row.style.display = (type === 'all' || row.classList.contains(type)) ? '' : 'none';
  }});
}}
function filterCat(cat) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#probeTable tbody tr').forEach(row => {{
    row.style.display = row.cells[1]?.textContent.trim() === cat ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────

def _html_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def _get_category_fix(category: str) -> str:
    fixes = {
        "SQLi":          "Enable SQLi rules in OWASP CRS. Use parameterized queries in code.",
        "XSS":           "Enable XSS rules in OWASP CRS. Implement Content-Security-Policy.",
        "PathTraversal": "Enable path traversal rules. Restrict file access in server config.",
        "CMDi":          "Enable command injection rules. Never pass user input to shell.",
        "SSRF":          "Block private IP ranges in egress firewall. Validate all URLs.",
        "HeaderInjection":"Validate and sanitize all HTTP headers. Strip untrusted headers.",
        "PayloadSize":   "Set max request size limit (e.g. 1MB). Enable slow request protection.",
        "EncodingTricks":"Enable URL decoding normalization before rule matching.",
    }
    for k, v in fixes.items():
        if k.lower() in category.lower():
            return v
    return "Review WAF ruleset for this attack category."


def save_waf_report(profile: WAFProfile, output_dir: str = "./results") -> Dict[str, str]:
    """Save JSON + HTML reports and return file paths."""
    from pathlib import Path
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r'[^\w]', '_', profile.target)[:40]
    stem = f"{ts}_waf_{safe}"

    # JSON
    json_path = out / f"{stem}.json"
    data = {
        "target":            profile.target,
        "waf_detected":      profile.waf_detected,
        "detection_rate":    profile.detection_rate,
        "grade":             ("A" if profile.detection_rate >= 90 else
                              "B" if profile.detection_rate >= 75 else
                              "C" if profile.detection_rate >= 60 else
                              "D" if profile.detection_rate >= 40 else "F"),
        "blind_spots":       profile.blind_spots,
        "strong_categories": profile.strong_categories,
        "weak_categories":   profile.weak_categories,
        "response_behavior": profile.response_behavior,
        "recommendations":   profile.recommendations,
        "probes":            [
            {"category": r.category, "technique": r.technique,
             "payload": r.payload, "blocked": r.blocked,
             "status": r.status_code, "time_ms": round(r.response_time*1000, 1)}
            for r in profile.probe_results
        ],
        "timestamp": profile.timestamp,
    }
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # HTML
    html_path = out / f"{stem}.html"
    html_path.write_text(generate_waf_html_report(profile), encoding="utf-8")

    return {"json": str(json_path), "html": str(html_path)}
