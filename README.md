# ScanHexa v2.5.0-ELITE 🔍

**A Unified Security Reconnaissance & Vulnerability Intelligence Platform.**

ScanHexa is a professional-grade cybersecurity tool that integrates **six core security modules** into a single, unified interface. It is designed to streamline the workflow for security researchers, providing real-time vulnerability scanning, malware detection, and deep reconnaissance.

## 🛡️ Six Integrated Security Modules
1. **Vulnerability Scanning**: Deep web-app audit using Nuclei, Nikto, and OpenVAS.
2. **Malware Detection**: Integrated **ClamAV** and **Yara** for signature and rule-based threat hunting.
3. **Real-time Analysis**: Live **Threat Intelligence Map** and active terminal monitoring of scanning progress.
4. **Network Discovery**: Port and service enumeration via Nmap and Httpx.
5. **OSINT & Recon**: Automated asset discovery using Amass, Shodan, and social footprinting with Sherlock.
6. **Professional Reporting**: One-click generation of PDF/JSON audit reports for stakeholders.

## ✨ Key Technical Highlights
- **🌌 3D Attack Surface Mapping**: Interactive Three.js engine that visualizes target infrastructure as a dynamic network graph.
- **🔒 Hardened Architecture**: Backend secured with Bcrypt hashing and Zero-Trust session management.
- **🛡️ Command Injection Prevention**: Advanced validation layer utilizing strict regex sanitization for all tool inputs.
- **📡 Real-time Synchronization**: Powered by **Socket.io** to provide millisecond-latency progress updates from scanning binaries.

## 🏗 Modular Architecture
ScanHexa follows a high-performance, asynchronous architecture:
- **Core Engine**: Orchestrates the execution of multiple security binaries (C++/Go/Python) in parallel.
- **Fidelity Layer**: Includes high-fidelity simulation fallbacks for development environments without local binaries.
- **Intelligence Layer**: Aggregates data from diverse tools into a normalized JSON schema for cross-tool analysis.

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
