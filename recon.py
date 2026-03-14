#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║    ██████╗ ███████╗ ██████╗ ██████╗ ███╗  ██╗    ██████╗ ███████╗   ║
║    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗ ██║   ██╔══██╗╚════██║   ║
║    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗██║   ██║  ██║    ██╔╝   ║
║    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚████║   ██║  ██║   ██╔╝    ║
║    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚███║   ╚██████╔╝   ██║    ║
║    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚══╝    ╚═════╝    ╚═╝    ║
║                                                                      ║
║          الملف الرئيسي الموحد — Unified Command Center               ║
║          RECON-DZ v3.1 · Algeria Edition · All Tools Integrated      ║
╚══════════════════════════════════════════════════════════════════════╝

الأوامر المتاحة:
  python recon.py scan    → استطلاع كامل (recon + vuln + fingerprint)
  python recon.py waf     → تحليل WAF الدفاعي + تقرير HTML
  python recon.py batch   → مسح جماعي من ملف نصي
  python recon.py report  → إعادة توليد HTML من JSON موجود

التوثيق:
  python recon.py --help
  python recon.py scan --help
  python recon.py waf --help
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  IMPORTS (تم إضافة random, string, hashlib)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
import asyncio
import argparse
import json
import sys
import re
import time
import random          # NEW
import string          # NEW
import hashlib         # NEW
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# ... (بقية الاستيرادات كما هي) ...
from core.async_engine       import AsyncReconEngine, ResponseData, detect_waf_response
from core.algeria_threats    import AlgeriaThreatDatabase
from core.ip_utils           import extract_real_ip
from core.ip_enumerator      import IPEnumerator
from core.host_profiler      import HostProfiler, generate_host_profile_html
from core.stealth_engine     import (
    StealthScanner, CDNBypass, BlockDetector,
    GhostRequester, RateLimitEvader
)
from core.domain_validator   import DomainValidator
from core.subdomain_enum     import SubdomainEnumerator
from core.cms_detector       import CMSDetector
from core.port_scanner       import PortScanner
from core.server_fingerprint import ServerFingerprinter
from core.vuln_scanner       import VulnScanner
from core.intelligence_engine import IntelligenceEngine
from core.waf_analyzer       import (
    WAFAnalyzer, WAF_PROBES, WAFProfile,
    save_waf_report, generate_waf_html_report,
)

# ... (بقية الكود: CONSTANTS, COLOURS, BANNER, ENGINE FACTORY, SHARED HELPERS) ...
# (تم حذفها للاختصار، ولكن في الملف الفعلي تبقى كما هي)

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLASS ScanMode (تمت الإضافات هنا فقط)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class ScanMode:
    """
    Full reconnaissance pipeline.
    Integrates every core module in order.
    """

    def __init__(self, engine: AsyncReconEngine, args):
        self.e       = engine
        self.args    = args
        self.algeria = AlgeriaThreatDatabase()
        self.ts      = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.out     = Path(getattr(args, 'output_dir', './results'))
        self.out.mkdir(parents=True, exist_ok=True)
        self.results: Dict[str, Any] = {}

    # ... (الدوال القديمة: _on, _phase_count, run, _run_reverse_ip, ...) ...
    # (جميعها موجودة كما هي، لم يتم تغييرها)

    # =============== NEW: Smart Validation Functions ===============
    def get_smart_baseline(self, target_url: str) -> Optional[Dict]:
        """
        توليد بصمة مرجعية لصفحة غير موجودة للتعرف على الـ Soft 404
        """
        # توليد اسم ملف عشوائي مستحيل الوجود
        random_path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=15)) + ".html"
        test_url = f"{target_url.rstrip('/')}/{random_path}"
        
        try:
            # استخدام self.e.request مع asyncio.run_coroutine_threadsafe للتوافق
            future = asyncio.run_coroutine_threadsafe(
                self.e.request(test_url, follow_redirects=False),
                asyncio.get_event_loop()
            )
            resp = future.result(timeout=15)
            
            if resp.status == 0:
                return None
            
            baseline = {
                "status_code": resp.status,
                "content_length": len(resp.body),
                "hash": hashlib.md5(resp.body.encode('utf-8', errors='ignore')).hexdigest(),
                "title": "Not Found" if "not found" in resp.body.lower() else "Unknown"
            }
            return baseline
        except Exception as e:
            return None

    def validate_path(self, target_url: str, path: str, baseline: Dict) -> Tuple[bool, str]:
        """
        التحقق من المسار المكتشف ومقارنته بالبصمة المرجعية
        """
        full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
        try:
            future = asyncio.run_coroutine_threadsafe(
                self.e.request(full_url, follow_redirects=False),
                asyncio.get_event_loop()
            )
            res = future.result(timeout=15)
            
            if res.status == 0:
                return False, "Connection Error"

            # 1. إذا كان الكود ليس 200، فهو غالباً غير موجود
            if res.status != 200:
                return False, f"HTTP {res.status}"

            # 2. مقارنة الحجم (Content Length) مع المرجع
            size_diff = abs(len(res.body) - baseline["content_length"])
            if size_diff < (baseline["content_length"] * 0.05):
                return False, "Soft 404 (Size Match)"

            # 3. مقارنة البصمة الرقمية (Hash)
            current_hash = hashlib.md5(res.body.encode('utf-8', errors='ignore')).hexdigest()
            if current_hash == baseline["hash"]:
                return False, "Soft 404 (Hash Match)"

            # 4. إذا تجاوز كل الاختبارات، المسار حقيقي!
            return True, "Valid Path Detected"
        except Exception as e:
            return False, f"Error: {str(e)}"

    # =============== MODIFIED: _run_endpoints with smart validation ===============
    async def _run_endpoints(self, base_url: str, ali) -> List[Dict]:
        # --- NEW: Generate baseline ---
        print(f"  {C}[*]{RS} Generating smart baseline for soft-404 detection...")
        baseline = self.get_smart_baseline(base_url)
        if baseline:
            print(f"      Baseline: status={baseline['status_code']}, size={baseline['content_length']}, hash={baseline['hash'][:8]}")
        else:
            print(f"      {Y}[!]{RS} Could not generate baseline, proceeding without validation.")
        # --- End of NEW ---

        paths = _discovery_paths(ali)
        urls  = [f"{base_url.rstrip('/')}{p}" for p in paths]
        print(f"  {C}[*]{RS} Probing {len(urls)} paths …")
        found: List[Dict] = []
        for url in urls:
            r = await self.e.request(url)
            if r.status == 0:
                continue
            interesting = (r.is_success or
                           r.status in (301, 302, 307, 401, 403))
            if not interesting:
                continue
            ep = {
                'url':    url,
                'status': r.status,
                'size':   len(r.body),
                'title':  _title(r.body),
                'server': r.get_header('server'),
            }

            # --- NEW: Smart validation ---
            if baseline:
                # استخراج المسار من url
                path_part = url.replace(base_url.rstrip('/'), '')
                valid, reason = self.validate_path(base_url, path_part, baseline)
                if not valid:
                    # تجاهل المسار (لا نضيفه إلى found)
                    print(f"      {Y}[!]{RS} Rejected {url} — {reason}")
                    continue
                # إذا كان صحيحاً، نضيفه مع ملاحظة
                ep['validated'] = True
                print(f"      {G}[✓]{RS} Validated {url} — {reason}")
            else:
                # --- Original display ---
                icon = (f"{G}[200]{RS}" if r.status == 200 else
                        f"{C}[{r.status}]{RS}" if r.status in (301,302,307) else
                        f"{Y}[{r.status}]{RS}")
                ti = f'  "{ep["title"][:40]}"' if ep.get('title') else ''
                print(f"      {icon} {url}{ti}")
            # --- End of NEW ---

            found.append(ep)

        # --- NEW: Summary ---
        if baseline:
            print(f"  {G}[+]{RS} Found {len(found)} valid endpoints after smart validation.")
        else:
            print(f"  {G}[+]{RS} Found {len(found)} endpoints.")
        return found

    # ... (بقية دوال الكلاس كما هي) ...