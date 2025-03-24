# API Key Leak Detector

## 📌 Description
This Python project scans source code files for **API keys, tokens, and sensitive information** leaks.  
It detects:
- AWS, GitHub, Google, Stripe, and Slack tokens  
- JWTs, Bearer tokens, and random-looking alphanumeric keys  
- Base64 and custom-format keys  

---

## 🚀 Features
- ✅ Scans individual files or entire directories  
- ✅ Supports multiple file types: `.py`, `.c`, `.java`, `.js`, `.json`, `.env`, `.txt`, etc.  
- ✅ Displays all detected API keys and sensitive tokens  
- ✅ Easy-to-use command-line interface  

---

## ⚙️ Installation
1. Clone the repository:
```bash
git clone https://github.com/mrprohack/apikeyleektester
cd https://github.com/mrprohack/apikeyleektester
```
2. Install Python (if not already installed):
```bash
sudo apt install python3
```
3. Create a single Python file:
```bash
nano api_key_leak_detector.py
```

