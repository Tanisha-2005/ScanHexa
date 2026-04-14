# ScanHexa
A smart cybersecurity scanning tool that helps you discover vulnerabilities, monitor threats, and secure your systems — all in one place.

🔍 Scan Hexa
Scan Hexa is an advanced cybersecurity scanning and reconnaissance framework designed to perform automated security assessments, vulnerability analysis, and intelligence gathering. It integrates industry-standard tools to provide comprehensive insights for ethical hacking and penetration testing.

🚀 Overview
Scan Hexa streamlines the process of identifying security weaknesses by combining multiple reconnaissance and vulnerability assessment tools into a unified platform. It is ideal for cybersecurity students, researchers, and professionals aiming to perform efficient and structured security testing.

🛠 Integrated Tools
ScanHexa leverages a powerful array of industry-standard security tools:
- **Nmap** – Network discovery and port scanning
- **Nikto** – Web server vulnerability scanner
- **SQLMap** – Automated SQL Injection and database takeover
- **OpenVAS** – Comprehensive vulnerability assessment
- **OWASP Amass** – In-depth DNS enumeration and attack surface mapping
- **Nuclei** – Fast, template-based vulnerability scanning
- **Httpx** – Multi-purpose HTTP toolkit for bulk probing
- **theHarvester** – OSINT email and subdomain gathering
- **Sherlock** – Social media account forensics
- **Shodan** – Passive reconnaissance search engine
- **WAFW00f** – Web Application Firewall fingerprinting
- **WhatWeb** – Advanced tech stack identification
- **Sublist3r** – Domain scouting and subdomain discovery
- **Dirsearch** – Web path and directory brute-forcing

✨ Features
- **Interactive Intelligence Modules**: Dynamic "About" section allowing users to explore tool capabilities with a single click.
- **Unified Engine**: Seamlessly switch between 15+ specialized security weapons in one dashboard.
- **IP Intelligence**: Integrated IPinfo module for global geo-location and ASN tracking.
- **High-Fi Simulation**: Smart fallback engine that simulates outputs when local binaries are unavailable.
- **Persistent History**: Local audit logs for every tool scan performed.
- **Pro Reporting**: Export findings as structured JSON or professional security reports.

🏗 Architecture

Scan Hexa follows a modular architecture:
Input Layer – Accepts target (IP/domain)
Processing Layer – Executes integrated tools
Analysis Layer – Aggregates and filters results
Output Layer – Displays reports in readable format

📂 Project Structure
ScanHexa/
│── server.js           # Main Express server
│── routes/             # API routes (scan, report, tools)
│── public/             # Frontend assets (HTML, CSS, JS)
│── utils/              # Core logic (scanner, simulations)
│── reports/            # Persistent storage for scan JSONs
│── package.json        # Dependencies and scripts
│── README.md           # Documentation

⚙️ Installation

1️⃣ Clone Repository
git clone https://github.com/Tanisha-2005/ScanHexa
cd scan-hexa

2️⃣ Install Dependencies
👉 For Node.js:
npm install

👉 For Python:
pip install -r requirements.txt

▶️ Usage
Start the application
Enter target (IP / Domain)
Select scanning modules
Execute scan
Analyze generated reports

🔐 Security & Compliance
Designed for ethical hacking and authorized testing only
Follows best practices in penetration testing workflows
Supports controlled and modular scanning

⚠️ Disclaimer
This tool is intended strictly for educational and authorized security testing purposes.
Unauthorized use against systems without permission is illegal.

🌐 Live Demo
🚀 Access the deployed project here:  
👉 https://scanhexa.onrender.com
> Experience ScanHexa directly in your browser without any setup.
