import re
import requests
from collections import defaultdict, Counter
import time

class FirewallAnalyzer:
    def __init__(self):
        self.suspicious_patterns = [
            r'.*\.(php|asp|jsp|cgi)',  # File extensions đáng nghi
            r'admin|phpmyadmin|wp-admin',  # Admin paths
            r'\.\./',  # Directory traversal
            r'<script|javascript:|eval\(',  # XSS attempts
            r'union.*select|drop.*table',  # SQL injection
        ]
        self.rate_limits = defaultdict(list)
        
    def is_suspicious_request(self, path, user_agent=''):
        """Kiểm tra request có đáng nghi hay không"""
        combined = f"{path} {user_agent}".lower()
        return any(re.search(pattern, combined, re.IGNORECASE) for pattern in self.suspicious_patterns)
    
    def check_rate_limit(self, ip, limit=100, window=300):  # 100 requests trong 5 phút
        """Kiểm tra rate limiting"""
        now = time.time()
        self.rate_limits[ip] = [req_time for req_time in self.rate_limits[ip] if now - req_time < window]
        self.rate_limits[ip].append(now)
        return len(self.rate_limits[ip]) > limit
