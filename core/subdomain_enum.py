#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RECON-DZ v3 - Subdomain Enumerator
Fixed: aiohttp timeout=10 (raw int) → ClientTimeout object,
       improved crt.sh result parsing, added HackerTarget fallback,
       concurrency safety improvements
"""

import asyncio
import aiohttp
import ssl
import re
from typing import List, Dict, Optional, Set
from pathlib import Path

from core.async_engine import AsyncReconEngine
from core.domain_validator import DomainValidator
from core.algeria_threats import AlgeriaThreatDatabase


class SubdomainEnumerator:
    """
    Enumerate subdomains using multiple techniques:
    1. Certificate Transparency logs (crt.sh)
    2. HackerTarget API (backup source)
    3. Wordlist DNS brute-force via DoH
    """

    _BUILTIN_WORDLIST = [
        "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2",
        "cpanel", "whm", "autodiscover", "m", "imap", "test", "ns",
        "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
        "mail2", "mysql", "old", "support", "mobile", "mx", "static",
        "docs", "beta", "shop", "sql", "secure", "demo", "cp", "wiki",
        "web", "media", "email", "images", "img", "download", "dns",
        "stats", "analytics", "proxy", "api", "live", "portal", "backup",
        "store", "app", "exchange", "owa", "search", "help", "kb",
        "forums", "chat", "community", "git", "svn", "tracker", "bugs",
        "stage", "staging", "prod", "production", "qa", "uat", "sandbox",
        "lab", "cloud", "my", "extranet", "intranet", "partner", "vpn2",
        "remote", "rdp", "ssh", "ftp2", "dev2", "test2", "jenkins",
        "jira", "confluence", "grafana", "prometheus", "kibana",
        "elastic", "logstash", "moodle", "lms", "elearning",
        "student", "staff", "library", "research", "alumni",
        "register", "auth", "login", "sso", "oauth", "accounts",
        "pay", "payment", "checkout", "billing", "invoice",
        "status", "monitor", "health", "ping",
    ]

    def __init__(self, engine: AsyncReconEngine,
                 threat_db: AlgeriaThreatDatabase):
        self.engine     = engine
        self.threat_db  = threat_db
        self.wordlist   = self._load_wordlist()

    def _load_wordlist(self) -> List[str]:
        """Load wordlist from file or use built-in."""
        paths = [
            Path('wordlists/subdomains.txt'),
            Path(__file__).parent.parent / 'wordlists' / 'subdomains.txt',
        ]
        for wl_path in paths:
            if wl_path.exists():
                try:
                    words = [
                        l.strip() for l in wl_path.read_text('utf-8').splitlines()
                        if l.strip() and not l.startswith('#')
                    ]
                    if words:
                        return words
                except Exception:
                    pass
        return self._BUILTIN_WORDLIST

    async def enumerate(self, domain: str,
                        concurrency: int = 50) -> List[Dict]:
        """
        Run all enumeration techniques, deduplicate, validate, and return
        only active subdomains with their metadata.
        """
        # Collect raw subdomain candidates from all sources
        tasks = [
            self._from_crtsh(domain),
            self._from_hackertarget(domain),
            self._bruteforce(domain, concurrency),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        candidates: Set[str] = set()
        for res in results:
            if isinstance(res, (list, set)):
                candidates.update(res)

        # Always include bare domain and www.
        candidates.add(domain)
        candidates.add(f'www.{domain}')

        if not candidates:
            return []

        # Validate all candidates concurrently
        validator = DomainValidator(self.engine, self.threat_db)
        validated = await validator.validate_batch(
            list(candidates), concurrency=min(concurrency, 20)
        )

        return [v for v in validated if v.get('active')]

    # ─────────────────── CT Log Sources ───────────────────────────────

    async def _from_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        subs: Set[str] = set()
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

            connector = aiohttp.TCPConnector(ssl=ssl_ctx)
            # [FIX] Use ClientTimeout object instead of raw int
            timeout   = aiohttp.ClientTimeout(total=20, connect=8)

            async with aiohttp.ClientSession(
                connector=connector, timeout=timeout
            ) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json(content_type=None)
                        except Exception:
                            # crt.sh sometimes returns malformed JSON
                            text = await resp.text()
                            import json
                            data = json.loads(text)

                        for entry in data:
                            name = entry.get('name_value', '')
                            for n in name.split('\n'):
                                n = n.strip().lower()
                                # Remove wildcard prefix
                                if n.startswith('*.'):
                                    n = n[2:]
                                if n and (n.endswith(f'.{domain}') or n == domain):
                                    if _is_valid_hostname(n):
                                        subs.add(n)
        except Exception:
            pass
        return subs

    async def _from_hackertarget(self, domain: str) -> Set[str]:
        """Query HackerTarget API as a backup source."""
        url   = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        subs: Set[str] = set()
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = ssl.CERT_NONE

            timeout = aiohttp.ClientTimeout(total=15, connect=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            parts = line.split(',')
                            if parts:
                                sub = parts[0].strip().lower()
                                if sub.endswith(f'.{domain}') or sub == domain:
                                    if _is_valid_hostname(sub):
                                        subs.add(sub)
        except Exception:
            pass
        return subs

    # ─────────────────── DNS Brute-Force ──────────────────────────────

    async def _bruteforce(self, domain: str, concurrency: int) -> Set[str]:
        """Resolve each wordlist entry via DoH."""
        sem  = asyncio.Semaphore(concurrency)
        tasks = [
            self._resolve_sub(word, domain, sem)
            for word in self.wordlist
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {r for r in results if isinstance(r, str)}

    async def _resolve_sub(self, word: str, domain: str,
                            sem: asyncio.Semaphore) -> Optional[str]:
        """Resolve a single subdomain candidate."""
        full = f"{word}.{domain}"
        async with sem:
            ip = await self.engine.resolve_hostname(full)
            return full if ip else None


# ─────────────────────── Helpers ──────────────────────────────────────

def _is_valid_hostname(hostname: str) -> bool:
    """Basic RFC-compliant hostname validation."""
    if not hostname or len(hostname) > 253:
        return False
    allowed = re.compile(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$')
    return all(allowed.match(part) for part in hostname.split('.') if part)
