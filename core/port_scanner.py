# -*- coding: utf-8 -*-
import asyncio
import random
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class PortInfo:
    port: int
    state: str
    service: Optional[str] = None
    banner: Optional[str] = None

class PortScanner:
    def __init__(self, timeout: float = 2.5):
        self.timeout = timeout
        self.common_ports = [21, 22, 23, 25, 53, 80, 111, 443, 445, 2049, 3306, 3389, 8080, 8443]

    async def scan(self, ip: str) -> List[PortInfo]:
        """فحص المنافذ بنظام الترتيب العشوائي لتضليل أنظمة المراقبة"""
        open_ports = []
        # بعثرة ترتيب المنافذ لكسر البصمة الزمنية
        ports_to_scan = self.common_ports.copy()
        random.shuffle(ports_to_scan)
        
        semaphore = asyncio.Semaphore(3) # فحص بطيء وصامت جداً
        tasks = [self._probe_port(ip, port, semaphore) for port in ports_to_scan]
        results = await asyncio.gather(*tasks)
        
        return [r for r in results if r]

    async def _probe_port(self, ip: str, port: int, sem) -> Optional[PortInfo]:
        async with sem:
            try:
                # إضافة تأخير عشوائي بين كل منفذ وآخر
                await asyncio.sleep(random.uniform(1.0, 4.0))
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )
                
                # جلب البانر بتخفي (بدون إرسال بيانات مريبة)
                banner = ""
                try:
                    if port in [80, 443]:
                        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    banner_bytes = await asyncio.wait_for(reader.read(512), timeout=1.5)
                    banner = banner_bytes.decode('utf-8', errors='ignore').strip()
                except: pass

                writer.close()
                await writer.wait_closed()
                return PortInfo(port=port, state='open', banner=banner[:100])
            except: return None
