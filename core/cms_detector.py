# -*- coding: utf-8 -*-
import re
from core.async_engine import AsyncReconEngine

class CMSDetector:
    def __init__(self, engine: AsyncReconEngine):
        self.engine = engine

    async def detect(self, url: str) -> dict:
        """كشف نوع نظام الإدارة وإصداره عبر بصمات الملفات الثابتة"""
        results = {'cms': 'Unknown', 'version': 'Unknown'}
        
        # فحص ملفات الإصدار الصامتة التي لا تظهر للزوار عادة
        check_paths = {
            'WordPress': ['/readme.html', '/wp-includes/css/buttons.css'],
            'Joomla': ['/administrator/manifests/files/joomla.xml'],
            'Drupal': ['/core/assets/vendor/jquery/jquery.min.js']
        }
        
        for cms, paths in check_paths.items():
            for path in paths:
                res = await self.engine.request(url.rstrip('/') + path)
                if res and res['status'] == 200:
                    results['cms'] = cms
                    # محرك استخراج الإصدار (Regex)
                    version_match = re.search(r'([0-9]+\.[0-9]+(\.[0-9]+)?)', res['body'])
                    if version_match: results['version'] = version_match.group(1)
                    break
        return results
