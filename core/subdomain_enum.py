# -*- coding: utf-8 -*-
"""
subdomain_enum.py - Enumerate subdomains using multiple techniques
Part of RECON-DZ v2
"""

import asyncio
import aiohttp
import random
from typing import List, Dict, Optional, Set
from pathlib import Path
from core.async_engine import AsyncReconEngine
from core.domain_validator import DomainValidator
from core.algeria_threats import AlgeriaThreatDatabase


class SubdomainEnumerator:
    """
    Enumerate subdomains for a given domain using:
    - Wordlist brute-force
    - Certificate Transparency logs (crt.sh)
    - Additional sources (can be extended)
    """

    def __init__(self, engine: AsyncReconEngine, threat_db: AlgeriaThreatDatabase):
        self.engine = engine
        self.threat_db = threat_db
        self.wordlist: List[str] = []
        self.wordlist_path = Path("wordlists/subdomains.txt")
        self._load_wordlist()

    def _load_wordlist(self):
        """Load wordlist from file or use built-in default"""
        if self.wordlist_path.exists():
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                self.wordlist = [line.strip() for line in f if line.strip()]
        else:
            # Built-in minimal wordlist (most common subdomains)
            self.wordlist = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
                "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
                "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3",
                "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "static",
                "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar", "wiki",
                "web", "media", "email", "images", "img", "download", "dns", "piwik", "stats",
                "analytics", "proxy", "wap", "api", "live", "portal", "backup", "online",
                "store", "app", "exchange", "owa", "meu", "alumni", "virtual", "library",
                "newsletter", "survey", "stage", "id", "ir", "search", "review", "tech",
                "ftp2", "translate", "feedback", "preview", "dokuwiki", "mediawiki", "wiki",
                "help", "kb", "forums", "bbs", "chat", "community", "groups", "network",
                "home", "host", "server", "git", "svn", "cvs", "tracker", "bugs", "issue",
                "trac", "redmine", "test2", "test3", "dev2", "stage2", "staging", "prod",
                "production", "develop", "development", "testing", "qa", "uat", "demo2",
                "sandbox", "lab", "cloud", "my", "portal2", "extranet", "intranet", "partner"
            ]

    async def enumerate(self, domain: str, concurrency: int = 50) -> List[Dict]:
        """
        Enumerate subdomains and return validated results.
        """
        tasks = []
        # Technique 1: Wordlist brute-force
        tasks.append(self._bruteforce(domain, concurrency))

        # Technique 2: Certificate Transparency
        tasks.append(self._from_crtsh(domain))

        # Technique 3: (future) other sources like search engines, etc.

        results = await asyncio.gather(*tasks, return_exceptions=True)

        subdomains_set: Set[str] = set()
        for res in results:
            if isinstance(res, list):
                subdomains_set.update(res)

        if not subdomains_set:
            return []

        # Validate all discovered subdomains
        validator = DomainValidator(self.engine, self.threat_db)
        validated = await validator.validate_batch(list(subdomains_set), concurrency=10)

        # Return only active ones with full info
        return [v for v in validated if v.get('active')]

    async def _bruteforce(self, domain: str, concurrency: int) -> List[str]:
        """Brute-force subdomains using wordlist."""
        semaphore = asyncio.Semaphore(concurrency)
        tasks = [self._check_subdomain(sub, domain, semaphore) for sub in self.wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, str)]

    async def _check_subdomain(self, sub: str, domain: str, semaphore) -> Optional[str]:
        """Resolve a candidate subdomain via DoH."""
        async with semaphore:
            full = f"{sub}.{domain}"
            ip = await self.engine.resolve_hostname(full)
            if ip:
                return full
            return None

    async def _from_crtsh(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency logs."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        subs = set()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if name:
                                # Sometimes multiple names are separated by newlines
                                for n in name.split('\n'):
                                    n = n.strip().lower()
                                    if n.endswith(f".{domain}") or n == domain:
                                        subs.add(n)
                        return list(subs)
        except Exception:
            pass
        return []
