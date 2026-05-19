import http.server
import socketserver
import json
import webbrowser
import os
import re

# بيانات لوحة التحكم (تبدأ من الصفر وتزيد مع كل هجوم حقيقي)
metrics_data = {"total_requests": 0, "blocked": 0, "passed": 0, "block_rate_pct": 0}

# أنماط الهجمات (SQL Injection & SSTI & XSS)
ATTACK_PATTERNS = [
    r"(union.*select)", r"(select.*from)", r"(insert.*into)", # SQLi
    r"\{\{.*\}\}", r"\{%.*%\}",                             # SSTI
    r"<script>", r"alert\(", r"javascript:"                 # XSS
]

class WAFHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # 1. إرسال البيانات للواجهة (Dashboard)
        if self.path == "/__waf/metrics":
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(metrics_data).encode())
            return

        # 2. فحص الهجمات في الرابط (الـ URL)
        metrics_data["total_requests"] += 1
        is_attack = False
        
        for pattern in ATTACK_PATTERNS:
            if re.search(pattern, self.path, re.IGNORECASE):
                is_attack = True
                break
        
        if is_attack:
            metrics_data["blocked"] += 1
            print(f"!!! ALERT: Attack Blocked on {self.path} !!!")
            self.send_response(403) # منوع (Forbidden)
            self.end_headers()
            self.wfile.write(b"<h1>403 Forbidden - WAF Blocked your attack</h1>")
        else:
            metrics_data["passed"] += 1
            # إذا كان الطلب آمن، يفتح صفحة الـ HTML مالتك
            return super().do_GET()

        # تحديث النسبة
        if metrics_data["total_requests"] > 0:
            metrics_data["block_rate_pct"] = round((metrics_data["blocked"] / metrics_data["total_requests"]) * 100)

PORT = 8080
print(f"🛡️ WAF Professional Server started at http://localhost:{PORT}")
webbrowser.open(f"http://localhost:{PORT}")

with socketserver.TCPServer(("", PORT), WAFHandler) as httpd:
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()
