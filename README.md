# 🛡️ py-waf

> Python-based Web Application Firewall with real-time attack detection dashboard.

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

---

## 🎯 What is py-waf?

A lightweight reverse-proxy WAF built in pure Python.
Detects and blocks common web attacks in real-time with a live monitoring dashboard.

---

## ⚔️ Detected Attack Vectors

| Attack | Pattern |
|--------|---------|
| SQL Injection | `union`, `select`, `insert` |
| XSS | `<script>`, `alert()`, `javascript:` |
| SSTI | `{{`, `}}`, `{%`, `%}` |
| SSRF/XXE | Custom pattern matching |
| RCE | Command injection patterns |

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/0x-Mohammed/py-waf.git
cd py-waf

# Run the WAF
python run-waf.py
```

Open your browser at `http://localhost:8080`

---

## 📊 Dashboard Features

- ✅ Real-time attack detection feed
- ✅ Block rate percentage
- ✅ Total requests counter
- ✅ Live chart visualization

---

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**.
The author is not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
