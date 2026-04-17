# ScanHexa v2.2.0-ELITE 🔍

**The next evolution in AI-driven reconnaissance and vulnerability intelligence.**

ScanHexa is an elite, high-security cybersecurity reconnaissance framework designed for deep network discovery and automated threat intelligence. By unifying industry-standard security tools into a cohesive, high-performance interface, ScanHexa provides security professionals with immediate, actionable intelligence on any target.

## ✨ NEW: 2.2.0-ELITE Features
- **🌌 3D Attack Surface Graph**: Interactive Three.js-powered visualization of subdomains, ports, and vulnerabilities in a 3D force-directed network.
- **🔒 Hardened Security Core**: Production-ready authentication using **Bcrypt salted password hashing**.
- **🛡️ Anti-Injection Engine**: Sophisticated input validation layer that proactively blocks command injection and shell-level attacks.
- **🔑 Zero-Trust Sessions**: Harden cookie management with `HttpOnly`, `SameSite: Strict`, and adaptive `Secure` flags.

## 🛠 Integrated Tools
ScanHexa leverages a powerful array of industry-standard security tools:
- **Nmap** – Network discovery and port scanning
- **Nikto** – Web server vulnerability scanner
- **SQLMap** – Automated SQL Injection and database takeover
- **OpenVAS** – Comprehensive vulnerability assessment
- **Nuclei** – Fast, template-based vulnerability scanning
- **Httpx** – Multi-purpose HTTP toolkit for bulk probing
- **OWASP Amass** – In-depth asset discovery
- **theHarvester** – OSINT email and subdomain gathering
- **Sherlock** – Social media account forensics
- **Shodan** – Passive reconnaissance search engine
- **WAFW00f** – Firewall fingerprinting
- **WhatWeb** – Tech stack identification
- **Dirsearch** – Web path brute-forcing

## 🏗 Architecture
ScanHexa follows a modular, hardened architecture:
- **Auth Layer**: Bcrypt-secured entry point.
- **Validation Layer**: Strict regex-based input filtering.
- **Engine Layer**: Parallel execution of security binaries.
- **Visualization Layer**: 3D network graphing of findings.

## 📂 Project Structure
```text
ScanHexa/
│── server.js           # Main Express server (Secured)
│── routes/             # API routes (scan, tool-intel, auth)
│── public/             # Frontend (HTML5, CSS, Three.js visualization)
│── utils/              # Core logic (Scanner, Validator, Simulations)
│── reports/            # Encrypted report storage
│── .env.example        # Configuration template
│── package.json        # Node.js dependencies
```

## ⚙️ Installation

1️⃣ **Clone Repository**
```bash
git clone https://github.com/Tanisha-2005/ScanHexa
cd ScanHexa
```

2️⃣ **Install Dependencies**
```bash
npm install
```

3️⃣ **Environment Setup**
```bash
cp .env.example .env
# Fill in your ADMIN_PASSWORD_HASH and session secrets in .env
```

4️⃣ **Start the Platform**
```bash
npm start
```

## 🔐 Security & Ethics
- Designed for ethical hacking and authorized testing only.
- Access is restricted via encrypted credentials.
- All scans should follow local jurisdictional laws and the Computer Misuse Act.

## ⚠️ Disclaimer
This tool is intended strictly for educational and authorized security testing purposes. Unauthorized use against systems without explicit permission is illegal.

## 🌐 Live Demo
Access the deployed project here:  
👉 [https://scanhexa.onrender.com](https://scanhexa.onrender.com)
