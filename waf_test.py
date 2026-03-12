#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 — WAF Defensive Tester
===================================
Test your own WAF's detection capabilities and generate
a professional HTML report with hardening recommendations.

Usage:
  python waf_test.py -t https://yoursite.dz/search
  python waf_test.py -t https://yoursite.dz/search --param q --all
  python waf_test.py -t https://yoursite.dz/ --categories SQLi XSS
"""

import asyncio
import argparse
import sys
from pathlib import Path

from core.async_engine import AsyncReconEngine
from core.waf_analyzer import WAFAnalyzer, WAF_PROBES, save_waf_report


BANNER = r"""
╔═══════════════════════════════════════════════════════════╗
║       RECON-DZ v3 — Defensive WAF Analyzer                ║
║  Test your WAF · Find blind spots · Harden defenses        ║
║  Authorized use only — run against systems you own         ║
╚═══════════════════════════════════════════════════════════╝
"""


async def run(args):
    print(BANNER)
    print(f"[*] Target      : {args.target}")
    print(f"[*] Parameter   : {args.param}")
    print(f"[*] Categories  : {args.categories or 'ALL'}")
    print(f"[*] Output dir  : {args.output_dir}\n")

    # Confirmation for safety
    if not args.yes:
        confirm = input("[!] Confirm you have authorization to test this target [y/N]: ")
        if confirm.lower() != 'y':
            print("[-] Aborted.")
            return

    # Initialize engine
    engine = AsyncReconEngine(
        max_concurrent=10,
        enable_stealth=True,
        delay_range=(0.2, 0.5),
    )
    await engine.initialize()

    try:
        analyzer = WAFAnalyzer(engine, delay_between_probes=args.delay)
        profile  = await analyzer.analyze(
            target_url = args.target,
            categories = args.categories or None,
            test_param = args.param,
        )

        # Save reports
        paths = save_waf_report(profile, args.output_dir)

        print(f"\n{'═'*60}")
        print(f"  RESULTS")
        print(f"{'═'*60}")
        print(f"  WAF Detected    : {profile.waf_detected or 'None / Unknown'}")
        print(f"  Detection Rate  : {profile.detection_rate:.1f}%")
        print(f"  Blind Spots     : {len(profile.blind_spots)}")
        print(f"  Recommendations : {len(profile.recommendations)}")
        print(f"\n  📄 JSON Report  : {paths['json']}")
        print(f"  🌐 HTML Report  : {paths['html']}")
        print(f"{'═'*60}\n")

        if profile.blind_spots:
            print("  ⚠️  Blind Spots Found:")
            for bs in profile.blind_spots:
                print(f"     • {bs}")
            print()

        print("  Top Recommendations:")
        for rec in profile.recommendations[:3]:
            print(f"  [{rec['priority']}] {rec['title']}")
            print(f"    → {rec['action']}")
        print()

    finally:
        await engine.close()


def main():
    p = argparse.ArgumentParser(
        description="RECON-DZ — Defensive WAF Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test all attack categories
  python waf_test.py -t https://yoursite.dz/search --all

  # Test specific categories
  python waf_test.py -t https://yoursite.dz/ --categories SQLi XSS SSRF

  # Fast test (no delay, internal network)
  python waf_test.py -t https://192.168.1.1/ --delay 0 -y

Available categories:
  """ + "  ".join(WAF_PROBES.keys()),
    )
    p.add_argument("-t", "--target",     required=True,
                   help="Target URL (e.g. https://yoursite.dz/search)")
    p.add_argument("--param",            default="q",
                   help="GET parameter to inject payloads into (default: q)")
    p.add_argument("--categories",       nargs="+", metavar="CAT",
                   help="Attack categories to test (default: all)")
    p.add_argument("--all",              action="store_true",
                   help="Test all categories (same as omitting --categories)")
    p.add_argument("--delay",            type=float, default=0.3,
                   help="Delay between probes in seconds (default: 0.3)")
    p.add_argument("--output-dir",       default="./results",
                   help="Output directory for reports")
    p.add_argument("-y", "--yes",        action="store_true",
                   help="Skip authorization confirmation prompt")

    args = p.parse_args()

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
