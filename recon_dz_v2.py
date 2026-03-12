# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
RECON-DZ v2 - Ultimate Ghost Edition
التحكم الرئيسي: منسق العمليات السيادي
"""

import asyncio
import argparse
import sys
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List

# استيراد الوحدات المطورة (التي قمنا بتعديلها سابقاً)
from core.async_engine import AsyncReconEngine
from core.algeria_threats import AlgeriaThreatDatabase
from core.ip_utils import extract_real_ip
from core.domain_validator import DomainValidator
from core.subdomain_enum import SubdomainEnumerator
from core.cms_detector import CMSDetector
from core.port_scanner import PortScanner
from core.server_fingerprint import ServerFingerprinter

class RECONDZv2:
    def __init__(self, args):
        self.args = args
        self.engine = AsyncReconEngine()
        self.threat_db = AlgeriaThreatDatabase()
        self.start_time = datetime.now()

    async def run_ghost_recon(self, target_domain: str):
        """تنفيذ عملية الاستطلاع بنمط التسلل غير الخطي"""
        print(f"\n[+] بدء مهمة التوغل للهدف: {target_domain}")
        print(f"[!] وضع الشبح: نشط | نسبة الخطأ المستهدفة: 0%")

        # 1. التحقق الأولي وتصنيف الهدف (Algeria Intel)
        validator = DomainValidator(self.engine, self.threat_db)
        target_info = await validator._validate_one(target_domain, asyncio.Semaphore(1))
        
        if not target_info or not target_info.get('active'):
            print(f"[-] الفشل في الوصول للهدف أو النطاق غير نشط. إيقاف المهمة.")
            return

        print(f"[✓] تم كشف الهدف: {target_info['algerian_context']['sector']} | الحساسية: {target_info['algerian_context']['criticality']}")

        # 2. استخراج النطاقات الفرعية (Ghost Subdomain Enum)
        sub_enum = SubdomainEnumerator(self.engine)
        subdomains = await sub_enum.enumerate(target_domain)
        print(f"[✓] تم العثور على {len(subdomains)} نطاق فرعي.")

        # 3. تخطي الحماية واستخراج الـ IP الحقيقي
        real_ip = await extract_real_ip(target_domain, self.engine)
        print(f"[✓] العنوان الرقمي الحقيقي: {real_ip}")

        # 4. الفحص العشوائي للمنافذ والخدمات
        if self.args.ports:
            scanner = PortScanner()
            open_ports = await scanner.scan(real_ip)
            
            # 5. تحليل البصمة والـ CMS
            fingerprinter = ServerFingerprinter()
            server_profile = fingerprinter.fingerprint(open_ports)
            
            cms_detect = CMSDetector(self.engine)
            cms_info = await cms_detect.detect(f"http://{target_domain}")

            self._generate_final_report(target_domain, real_ip, open_ports, server_profile, cms_info)

    def _generate_final_report(self, domain, ip, ports, profile, cms):
        """توليد التقرير النهائي بصيغة احترافية"""
        print("\n" + "="*50)
        print(f"التقرير الاستخباراتي لمشروع RECON-DZ v2")
        print(f"الهدف: {domain} ({ip})")
        print(f"نظام التشغيل المتوقع: {profile['os']}")
        print(f"نظام إدارة المحتوى: {cms['cms']} (الإصدار: {cms['version']})")
        print("-" * 30)
        print("المنافذ المفتوحة:")
        for p in ports:
            print(f"  - Port {p.port}: {p.banner if p.banner else 'Unknown Service'}")
        print("="*50 + "\n")

async def main():
    parser = argparse.ArgumentParser(description='RECON-DZ v2.0.0')
    parser.add_argument('target', help='Target domain')
    parser.add_argument('--ports', action='store_true', help='Scan ports')
    args = parser.parse_args()

    app = RECONDZv2(args)
    await app.run_ghost_recon(args.target)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] تم قطع المهمة من قبل المستخدم.")

