// =================== GLOBAL STATE ===================
const State = {
    currentScan: null,
    scanHistory: [],
    currentReports: [],
    activeScanId: null,
    scanInProgress: false,
    totalScans: 0,
    criticalVulns: 0,
    openPortsTotal: 0,
    reportsCount: 0
};

// =================== INITIALIZATION ===================
document.addEventListener("DOMContentLoaded", () => {
    // Initial UI Setup
    terminalLog("info", "ScanHexa initialized");
    terminalLog("ok", "Security modules ready");
    loadDashboardStats();

    // Event Listeners
    const targetInput = document.getElementById("scan-target");
    if (targetInput) {
        targetInput.addEventListener("input", debounce(validateTargetInput, 600));
    }

    const quickTarget = document.getElementById("quick-target");
    if (quickTarget) {
        quickTarget.addEventListener("keypress", (e) => {
            if (e.key === "Enter") quickScan();
        });
    }

    // Load actual reports and stats from backend
    loadReports();
    loadDashboardStats();
    loadAllToolHistory();

    // Handle initial hash routing
    const hash = window.location.hash.substring(1);
    if (hash && document.getElementById(hash)) {
        showSection(hash);
    }

    // Hash change listener
    window.addEventListener("hashchange", () => {
        const h = window.location.hash.substring(1);
        if (h && document.getElementById(h)) {
            showSection(h);
        }
    });
});

// =================== MAIN SCAN LOGIC ===================
async function startScan(overrideTools = null) {
    if (State.scanInProgress) {
        showToast("Scan already running", "warning");
        return;
    }

    const target = document.getElementById("scan-target")?.value.trim() || document.getElementById("quick-target")?.value.trim();
    const startBtn = document.getElementById("start-scan-btn");

    if (!target) {
        showToast("Enter target (IP or Domain)", "warning");
        return;
    }

    const tools = overrideTools || getSelectedTools();
    if (tools.length === 0) {
        showToast("Select at least one tool", "warning");
        return;
    }

    State.scanInProgress = true;
    if (startBtn) {
        startBtn.disabled = true;
        startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> SCANNING...';
    }

    terminalLog("info", `Starting scan on ${target}...`);
    showSection("scanner");
    showLoadingModal(true, target);

    try {
        const response = await fetch("/api/scan/start", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target,
                tools,
                profile: document.getElementById("scan-profile")?.value || "standard",
                options: {
                    portRange: document.getElementById("port-range")?.value || "1-1000",
                    osDetect: document.getElementById("os-detect")?.checked || false,
                    serviceVersion: document.getElementById("svc-version")?.checked || false,
                    aggressive: document.getElementById("aggressive")?.checked || false,
                    timeout: document.getElementById("timeout")?.value || 60
                }
            })
        });

        const scanResult = await response.json();

        if (!response.ok) throw new Error(scanResult.error || "Server Error");

        State.currentScan = scanResult;
        
        // Update History
        State.scanHistory.push({ target, time: new Date().toLocaleTimeString(), status: 'Success' });
        State.totalScans++;
        
        // Update Metrics
        if (scanResult.riskAssessment) {
            if (scanResult.riskAssessment.level === 'critical') State.criticalVulns++;
            const nmapResult = scanResult.data.nmap;
            if (nmapResult && nmapResult.data && nmapResult.data.openPorts) {
                State.openPortsTotal += nmapResult.data.openPorts.length;
            }
        }
        updateDashboardStats();
        updateRecentScansUI();
        
        console.log("[ScanHexa] Full scan result received:", scanResult);
        displayScanResults(scanResult);
        loadReports(); // reload to get newly saved remote report

        document.getElementById("report-actions")?.classList.remove("hidden");
        terminalLog("ok", "Scan completed successfully");
        showToast("Scan Complete", "success");

    } catch (err) {
        terminalLog("error", err.message);
        showToast(err.message, "error");
    } finally {
        State.scanInProgress = false;
        showLoadingModal(false);
        if (startBtn) {
            startBtn.disabled = false;
            startBtn.innerHTML = '<i class="fas fa-play"></i> LAUNCH SCAN';
        }
    }
}

function quickScan() {
    const target = document.getElementById("quick-target").value;
    if (!target) return showToast("Enter a target", "warning");
    
    // Auto fill main scanner target
    const mainTarget = document.getElementById("scan-target");
    if (mainTarget) mainTarget.value = target;

    const tools = [];
    if (document.getElementById("q-nmap").checked) tools.push("nmap");
    if (document.getElementById("q-nikto").checked) tools.push("nikto");
    if (document.getElementById("q-whois").checked) tools.push("whois");
    if (document.getElementById("q-dns").checked) tools.push("dns");
    if (document.getElementById("q-harvest").checked) tools.push("theharvester");

    startScan(tools);
}

// =================== UI UPDATES ===================
function displayScanResults(scan) {
    console.log("[ScanHexa] Displaying results for:", scan.target);
    document.getElementById("scan-placeholder").style.display = "none";
    document.getElementById("tab-overview").classList.remove("hidden");
    
    // Overview HTML
    let overviewHtml = `<div class="overview-card"><h3>Target</h3><p>${scan.target}</p></div>`;
    overviewHtml += `<div class="overview-card"><h3>Risk Level</h3><p class="${scan.riskAssessment?.level || 'low'}">${(scan.riskAssessment?.level || 'Low').toUpperCase()}</p></div>`;
    overviewHtml += `<div class="overview-card"><h3>Score</h3><p>${scan.riskAssessment?.score || 0}/100</p></div>`;
    document.getElementById("overview-content").innerHTML = overviewHtml;
    
    // Nmap Results
    if (scan.data.nmap) {
        let nmapHtml = '<h3>Nmap Scan Results</h3>';
        if (scan.data.nmap.error) nmapHtml += `<p class="error" style="color:#ff4757;">${scan.data.nmap.error}</p>`;
        else {
             nmapHtml += `<ul class="result-list">`;
             (scan.data.nmap.data?.openPorts || []).forEach(p => {
                 nmapHtml += `<li><i class="fas fa-plug"></i> <strong>Port ${p.port}</strong> (${p.protocol}): <span class="t-ok">${p.service}</span> - <span class="badge sm success">${p.state}</span></li>`;
             });
             nmapHtml += `</ul><div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.nmap.rawOutput || ''}</pre>`;
        }
        document.getElementById("nmap-result").innerHTML = nmapHtml;
    } else {
        document.getElementById("nmap-result").innerHTML = '<p class="t-warning" style="padding:20px;">Nmap was not selected to run during this scan.</p>';
    }

    // Nikto Results
    if (scan.data.nikto) {
        let niktoHtml = '<h3>Nikto Vulnerability Results</h3>';
        if (scan.data.nikto.error) niktoHtml += `<p class="error" style="color:#ff4757;">${scan.data.nikto.error}</p>`;
        else {
             niktoHtml += `<ul class="result-list">`;
             (scan.data.nikto.data?.vulnerabilities || []).forEach(v => {
                 niktoHtml += `<li><i class="fas fa-exclamation-triangle t-warning"></i> ${v}</li>`;
             });
             niktoHtml += `</ul><div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.nikto.rawOutput || ''}</pre>`;
        }
        document.getElementById("nikto-result").innerHTML = niktoHtml;
    } else {
        document.getElementById("nikto-result").innerHTML = '<p class="t-warning" style="padding:20px;">Nikto was not selected to run during this scan.</p>';
    }

    // SQLMap
    if (scan.data.sqlmap) {
        let sqlHtml = '<h3>SQLMap Injection Results</h3>';
        if (scan.data.sqlmap.error) sqlHtml += `<p class="error" style="color:#ff4757;">${scan.data.sqlmap.error}</p>`;
        else {
             sqlHtml += `<pre>${scan.data.sqlmap.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("sqlmap-result");
        if(el) el.innerHTML = sqlHtml;
    } else {
        const el = document.getElementById("sqlmap-result");
        if(el) el.innerHTML = '<p class="t-warning" style="padding:20px;">SQLMap was not selected to run during this scan.</p>';
    }

    // OpenVAS
    if (scan.data.openvas) {
        let ovHtml = '<h3>OpenVAS Vulnerability Assessment</h3>';
        if (scan.data.openvas.error) ovHtml += `<p class="error" style="color:#ff4757;">${scan.data.openvas.error}</p>`;
        else {
            const findings = scan.data.openvas.data?.findings || [];
            if (findings.length > 0) {
                ovHtml += `<div class="vuln-cards" style="display:grid; gap:10px; margin-bottom:20px;">`;
                findings.forEach(f => {
                    const sevClass = f.severity.toLowerCase();
                    ovHtml += `
                        <div class="vuln-card panel" style="border-left: 4px solid var(--${sevClass === 'critical' ? 'danger' : (sevClass === 'high' ? 'danger' : (sevClass === 'medium' ? 'warning' : 'info'))}); padding:15px; background:rgba(255,255,255,0.03);">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                <h4 style="margin:0; color:var(--text-primary);">${f.name}</h4>
                                <span class="badge ${sevClass}">${f.severity.toUpperCase()}</span>
                            </div>
                            <p style="font-size:12px; color:var(--text-secondary); margin-bottom:8px;">${f.description}</p>
                            <p style="font-size:11px; color:var(--text-muted); margin:0;"><i class="fas fa-shield-alt"></i> Impact: ${f.impact}</p>
                        </div>
                    `;
                });
                ovHtml += `</div>`;
            }
            ovHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.openvas.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("openvas-result");
        if(el) el.innerHTML = ovHtml;
    } else {
        const el = document.getElementById("openvas-result");
        if(el) el.innerHTML = '<p class="t-warning" style="padding:20px;">OpenVAS was not selected to run during this scan.</p>';
    }

    // Grim
    if (scan.data.grim) {
        let grimHtml = '<h3>Grim Social Recon</h3>';
        if (scan.data.grim.error) grimHtml += `<p class="error" style="color:#ff4757;">${scan.data.grim.error}</p>`;
        else {
             grimHtml += `<pre>${scan.data.grim.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("grim-result");
        if(el) el.innerHTML = grimHtml;
    } else {
        const el = document.getElementById("grim-result");
        if(el) el.innerHTML = '<p class="t-warning" style="padding:20px;">Grim was not selected to run during this scan.</p>';
    }

    // theHarvester
    if (scan.data.theharvester) {
        let osintHtml = '<h3>OSINT Results</h3>';
        if (scan.data.theharvester.error) osintHtml += `<p class="error" style="color:#ff4757;">${scan.data.theharvester.error}</p>`;
        else {
            osintHtml += `<pre>${scan.data.theharvester.rawOutput || 'No layout Data'}</pre>`;
        }
        const el = document.getElementById("osint-result");
        if (el) el.innerHTML = osintHtml;
    } else {
        const el = document.getElementById("osint-result");
        if (el) el.innerHTML = '<p class="t-warning" style="padding:20px;">OSINT tools were not selected for this scan.</p>';
    }

    // WAFW00f
    if (scan.data.wafw00f) {
        let wafHtml = '<h3>WAF Detection Results</h3>';
        if (scan.data.wafw00f.error) wafHtml += `<p class="error" style="color:#ff4757;">${scan.data.wafw00f.error}</p>`;
        else {
            const detected = scan.data.wafw00f.data?.detected;
            if (detected) {
                wafHtml += `<div class="t-ok" style="margin-bottom:15px;"><i class="fas fa-shield-alt"></i> Firewall Detected: <span class="badge success">${scan.data.wafw00f.data.waf}</span></div>`;
            } else {
                wafHtml += `<p class="t-info"><i class="fas fa-unlock"></i> No Web Application Firewall detected.</p>`;
            }
            wafHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.wafw00f.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("wafw00f-result");
        if (el) el.innerHTML = wafHtml;
    }

    // WhatWeb
    if (scan.data.whatweb) {
        let whatHtml = '<h3>Tech Stack Analysis</h3>';
        if (scan.data.whatweb.error) whatHtml += `<p class="error" style="color:#ff4757;">${scan.data.whatweb.error}</p>`;
        else {
            const techs = scan.data.whatweb.data?.tech || [];
            if (techs.length > 0) {
                whatHtml += `<div style="display:flex; gap:8px; flex-wrap:wrap; margin-bottom:15px;">`;
                techs.forEach(t => {
                    whatHtml += `<span class="badge info">${t}</span>`;
                });
                whatHtml += `</div>`;
            }
            whatHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.whatweb.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("whatweb-result");
        if (el) el.innerHTML = whatHtml;
    }

    // Sublist3r
    if (scan.data.sublist3r) {
        let subHtml = '<h3>Subdomain Enumeration</h3>';
        if (scan.data.sublist3r.error) subHtml += `<p class="error" style="color:#ff4757;">${scan.data.sublist3r.error}</p>`;
        else {
            const domains = scan.data.sublist3r.data?.domains || [];
            if (domains.length > 0) {
                subHtml += `<ul class="result-list">`;
                domains.forEach(d => {
                    subHtml += `<li><i class="fas fa-sitemap"></i> ${d}</li>`;
                });
                subHtml += `</ul>`;
            }
            subHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.sublist3r.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("sublist3r-result");
        if (el) el.innerHTML = subHtml;
    }

    // Dirsearch
    if (scan.data.dirsearch) {
        let dirHtml = '<h3>Directory Brute Force Results</h3>';
        if (scan.data.dirsearch.error) dirHtml += `<p class="error" style="color:#ff4757;">${scan.data.dirsearch.error}</p>`;
        else {
            const paths = scan.data.dirsearch.data?.paths || [];
            if (paths.length > 0) {
                dirHtml += `<ul class="result-list">`;
                paths.forEach(p => {
                    dirHtml += `<li><i class="fas fa-folder"></i> <strong>${p}</strong> - <span class="badge sm success">FOUND</span></li>`;
                });
                dirHtml += `</ul>`;
            }
            dirHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.dirsearch.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("dirsearch-result");
        if (el) el.innerHTML = dirHtml;
    }

    // Sherlock
    if (scan.data.sherlock) {
        let sherlockHtml = '<h3>Sherlock Account Search Results</h3>';
        if (scan.data.sherlock.error) sherlockHtml += `<p class="error" style="color:#ff4757;">${scan.data.sherlock.error}</p>`;
        else {
            const results = scan.data.sherlock.data?.results || [];
            if (results.length > 0) {
                sherlockHtml += `<p class="t-ok" style="margin-bottom:15px;">Target found on ${results.length} platforms:</p>`;
                sherlockHtml += `<div style="display:grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap:10px;">`;
                results.forEach(url => {
                    const platform = url.split('.')[1];
                    const siteName = platform?.charAt(0).toUpperCase() + platform?.slice(1);
                    sherlockHtml += `
                        <a href="${url}" target="_blank" style="background:rgba(0,0,0,0.3); border:1px solid var(--border); border-radius:8px; padding:12px; text-decoration:none; display:flex; align-items:center; gap:10px; transition:0.3s; color:var(--text-primary);">
                            <i class="fas fa-external-link-alt" style="color:#9b59b6;"></i>
                            <div style="display:flex; flex-direction:column;">
                                <span style="font-size:11px; color:#9b59b6; font-weight:700;">${siteName?.toUpperCase() || 'PROFILE'}</span>
                                <span style="font-size:12px; color:var(--text-secondary); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:150px;">${url}</span>
                            </div>
                        </a>
                    `;
                });
                sherlockHtml += `</div>`;
            } else {
                sherlockHtml += `<p class="t-warning">No social profiles found for this username.</p>`;
            }
        }
        const el = document.getElementById("sherlock-result");
        if (el) el.innerHTML = sherlockHtml;
    }

    // Amass
    if (scan.data.amass) {
        let amassHtml = '<h3>Amass Discovery Results</h3>';
        if (scan.data.amass.error) amassHtml += `<p class="error" style="color:#ff4757;">${scan.data.amass.error}</p>`;
        else {
            const subdomains = scan.data.amass.data?.subdomains || [];
            if (subdomains.length > 0) {
                amassHtml += `<ul class="result-list">`;
                subdomains.forEach(s => {
                    amassHtml += `<li><i class="fas fa-link"></i> <strong>${s.domain}</strong> - <span class="t-info">${s.ip}</span> <span class="badge sm">${s.source}</span></li>`;
                });
                amassHtml += `</ul>`;
            }
            amassHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.amass.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("amass-result");
        if (el) el.innerHTML = amassHtml;
    }

    // Httpx
    if (scan.data.httpx) {
        let httpxHtml = '<h3>Httpx Probing Results</h3>';
        if (scan.data.httpx.error) httpxHtml += `<p class="error" style="color:#ff4757;">${scan.data.httpx.error}</p>`;
        else {
            const results = scan.data.httpx.data?.results || [];
            if (results.length > 0) {
                httpxHtml += `<ul class="result-list">`;
                results.forEach(r => {
                    const statusClass = r.status >= 200 && r.status < 300 ? 't-ok' : (r.status >= 300 && r.status < 400 ? 't-info' : 't-warning');
                    httpxHtml += `<li><i class="fas fa-globe"></i> <a href="${r.url}" target="_blank">${r.url}</a> [<span class="${statusClass}">${r.status}</span>] <strong>${r.title}</strong> - <small>${r.server}</small></li>`;
                });
                httpxHtml += `</ul>`;
            }
            httpxHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.httpx.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("httpx-result");
        if (el) el.innerHTML = httpxHtml;
    }

    // Nuclei
    if (scan.data.nuclei) {
        let nucleiHtml = '<h3>Nuclei Vulnerability Findings</h3>';
        if (scan.data.nuclei.error) nucleiHtml += `<p class="error" style="color:#ff4757;">${scan.data.nuclei.error}</p>`;
        else {
            const findings = scan.data.nuclei.data?.findings || [];
            if (findings.length > 0) {
                nucleiHtml += `<div class="vuln-cards" style="display:grid; gap:10px; margin-bottom:20px;">`;
                findings.forEach(f => {
                    const sevClass = f.severity.toLowerCase();
                    nucleiHtml += `
                        <div class="vuln-card panel" style="border-left: 4px solid var(--${sevClass === 'critical' ? 'danger' : (sevClass === 'high' ? 'danger' : (sevClass === 'medium' ? 'warning' : 'info'))}); padding:15px; background:rgba(255,255,255,0.03);">
                            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                                <h4 style="margin:0; color:var(--text-primary);">${f.name}</h4>
                                <span class="badge ${sevClass}">${f.severity.toUpperCase()}</span>
                            </div>
                            <p style="font-size:12px; color:var(--text-secondary); margin-bottom:10px;">${f.description}</p>
                            <div style="font-family:monospace; font-size:11px; color:#a29bfe; word-break:break-all;">${f.match}</div>
                        </div>
                    `;
                });
                nucleiHtml += `</div>`;
            }
            nucleiHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.nuclei.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("nuclei-result");
        if (el) el.innerHTML = nucleiHtml;
    }

    // Shodan
    if (scan.data.shodan) {
        let shodanHtml = '<h3>Shodan Intelligence</h3>';
        if (scan.data.shodan.error) shodanHtml += `<p class="error" style="color:#ff4757;">${scan.data.shodan.error}</p>`;
        else {
            const intel = scan.data.shodan.data || {};
            if (intel.ip) {
                shodanHtml += `
                    <div class="intel-overview" style="display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:20px;">
                        <div class="intel-stats panel">
                            <p><strong>IP:</strong> ${intel.ip}</p>
                            <p><strong>OS:</strong> ${intel.os}</p>
                            <p><strong>ISP:</strong> ${intel.isp}</p>
                            <p><strong>Org:</strong> ${intel.org}</p>
                        </div>
                        <div class="intel-ports panel">
                            <p><strong>Open Ports:</strong></p>
                            <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:10px;">
                                ${(intel.ports || []).map(p => `<span class="badge sm">${p}</span>`).join('')}
                            </div>
                        </div>
                    </div>
                    <div class="intel-vulns panel" style="margin-bottom:20px;">
                        <p><strong>Potential Vulnerabilities:</strong></p>
                        <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:10px;">
                            ${(intel.vulns || []).map(v => `<span class="badge sm danger">${v}</span>`).join('')}
                        </div>
                    </div>
                `;
            }
            shodanHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.shodan.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("shodan-result");
        if (el) el.innerHTML = shodanHtml;
    }

    // Whois
    if (scan.data.whois) {
        let whoisHtml = '<h3>Whois Registration Data</h3>';
        if (scan.data.whois.error) whoisHtml += `<p class="error" style="color:#ff4757;">${scan.data.whois.error}</p>`;
        else {
            const d = scan.data.whois.data || {};
            whoisHtml += `<div class="panel" style="margin-bottom:15px; background:rgba(255,255,255,0.03);">
                <p><strong>Registrar:</strong> ${d.registrar || 'N/A'}</p>
                <p><strong>Expiry:</strong> ${d.expiry || 'N/A'}</p>
            </div>`;
            whoisHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.whois.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("whois-result");
        if (el) el.innerHTML = whoisHtml;
    }

    // DNS
    if (scan.data.dns) {
        let dnsHtml = '<h3>DNS Record Analysis</h3>';
        if (scan.data.dns.error) dnsHtml += `<p class="error" style="color:#ff4757;">${scan.data.dns.error}</p>`;
        else {
            const records = scan.data.dns.data?.records || {};
            dnsHtml += `<ul class="result-list" style="margin-bottom:15px;">`;
            if (records.A) records.A.forEach(ip => dnsHtml += `<li><span class="badge sm info">A</span> <strong>${ip}</strong></li>`);
            if (records.MX) records.MX.forEach(mx => dnsHtml += `<li><span class="badge sm warning">MX</span> <strong>${mx}</strong></li>`);
            dnsHtml += `</ul>`;
            dnsHtml += `<div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.dns.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("dns-result");
        if (el) el.innerHTML = dnsHtml;
    }

    // SSL
    if (scan.data.ssl) {
        let sslHtml = '<h3>SSL/TLS Certificate Analysis</h3>';
        if (scan.data.ssl.error) sslHtml += `<p class="error" style="color:#ff4757;">${scan.data.ssl.error}</p>`;
        else {
            const d = scan.data.ssl.data || {};
            sslHtml += `
                <div class="panel" style="margin-bottom:15px; border-left:4px solid var(--success); background:rgba(255,255,255,0.03);">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-weight:700; color:var(--text-primary);">Overall Grade</span>
                        <span class="badge success" style="font-size:18px; width:40px; height:40px; border-radius:50%; display:flex; align-items:center; justify-content:center;">${d.score}</span>
                    </div>
                </div>
                <div class="panel" style="margin-bottom:15px; background:rgba(255,255,255,0.03);">
                    <p><strong>Subject:</strong> ${d.subject}</p>
                    <p><strong>Issuer:</strong> ${d.issuer}</p>
                    <p><strong>Expiry:</strong> ${d.valid_to}</p>
                    <p><strong>Cipher:</strong> <code>${d.cipher}</code></p>
                </div>
                <div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.ssl.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("ssl-result");
        if (el) el.innerHTML = sslHtml;
    }

    // Headers
    if (scan.data.headers) {
        let headHtml = '<h3>Security Header Audit</h3>';
        if (scan.data.headers.error) headHtml += `<p class="error" style="color:#ff4757;">${scan.data.headers.error}</p>`;
        else {
            const items = scan.data.headers.data?.items || [];
            headHtml += `<div style="display:grid; gap:8px; margin-bottom:15px;">`;
            items.forEach(h => {
                const isMissing = h.status === 'missing';
                headHtml += `
                    <div style="display:flex; justify-content:space-between; align-items:center; padding:10px; background:rgba(255,255,255,0.03); border-radius:6px; border:1px solid ${isMissing ? 'rgba(231,76,60,0.2)' : 'rgba(46,204,113,0.2)'};">
                        <div>
                            <span style="font-weight:600; font-size:13px; color:var(--text-primary);">${h.name}</span>
                            ${!isMissing ? `<div style="font-size:11px; color:var(--text-muted);">${h.value}</div>` : ''}
                        </div>
                        <span class="badge ${isMissing ? h.severity : 'safe'}" style="font-size:10px;">${isMissing ? 'MISSING' : 'PRESENT'}</span>
                    </div>
                `;
            });
            headHtml += `</div><div class="raw-output-header">Raw Console Output</div><pre class="terminal-box">${scan.data.headers.rawOutput || 'No output Data'}</pre>`;
        }
        const el = document.getElementById("headers-result");
        if (el) el.innerHTML = headHtml;
    }

    // Switch to Overview
    showResultTab('overview');
}

function showResultTab(tabId) {
    document.querySelectorAll(".result-tab").forEach(el => el.classList.add("hidden"));
    document.querySelectorAll(".rtab").forEach(el => el.classList.remove("active"));
    
    const targetTab = document.getElementById(`tab-${tabId}`);
    if (targetTab) targetTab.classList.remove("hidden");
    
    const targetBtn = document.querySelector(`.rtab[onclick="showResultTab('${tabId}')"]`);
    if (targetBtn) targetBtn.classList.add("active");
}

function showSection(sectionId) {
    if (!sectionId) return;
    
    // Hide all sections
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    // Remove active class from all links
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    
    // Show target section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
        // Update URL hash without jumping if possible, but standard behavior is fine
        if (window.location.hash !== `#${sectionId}`) {
            window.location.hash = sectionId;
        }
    }
    
    // Activate nav link
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        if (link.getAttribute('href') === `#${sectionId}` || 
            link.getAttribute('onclick')?.includes(`'${sectionId}'`)) {
            link.classList.add('active');
        }
    });
}

function toggleAdvanced() {
    const adv = document.getElementById("advanced-options");
    const chev = document.getElementById("adv-chevron");
    if (adv) {
        adv.classList.toggle("hidden");
        if (chev) {
            chev.style.transform = adv.classList.contains("hidden") ? "rotate(0deg)" : "rotate(180deg)";
        }
    }
}

function validateTargetInput(e) {
    const val = e.target.value;
    const info = document.getElementById("target-info");
    if (!info) return;
    if (val.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) {
        info.innerHTML = '<span class="t-ok">Valid IP Address format detected.</span>';
    } else if (val.includes(".")) {
        info.innerHTML = '<span class="t-warning">Domain format detected.</span>';
    } else {
        info.innerHTML = '';
    }
}

// =================== REPORTS & DASHBOARD ===================
async function loadReports() {
    try {
        const res = await fetch("/api/report/list");
        const data = await res.json();
        const grid = document.getElementById("reports-grid");
        
        State.currentReports = data.reports || [];
        State.reportsCount = State.currentReports.length;
        updateDashboardStats();

        renderReports(State.currentReports);
    } catch(e) {
        console.error("Failed to load reports", e);
    }
}

function renderReports(reportsList) {
    const grid = document.getElementById("reports-grid");
    if (!grid) return;

    if (reportsList.length === 0) {
        grid.innerHTML = `<div class="empty-state center"><i class="fas fa-folder-open"></i><p>No reports matching your criteria.</p></div>`;
        return;
    }

    grid.innerHTML = "";
    reportsList.forEach(r => {
        const card = document.createElement("div");
        card.className = "report-card panel";
        card.innerHTML = `
            <h3>Target: ${r.target}</h3>
            <p>Date: ${new Date(r.timestamp).toLocaleString()}</p>
            <div style="margin-top:10px;">
                <span class="badge ${r.riskAssessment?.level || 'low'}" style="padding:4px 8px; border-radius:4px; font-weight:bold; background:rgba(255,255,255,0.1);">${(r.riskAssessment?.level || 'Low').toUpperCase()} RISK</span>
                <span style="margin-left:8px;">Score: ${r.riskAssessment?.score || 0}</span>
            </div>
        `;

        const actions = document.createElement("div");
        actions.style.marginTop = "15px";
        actions.style.display = "flex";
        actions.style.gap = "10px";

        const downloadBtn = document.createElement("button");
        downloadBtn.className = "cyber-btn primary sm";
        downloadBtn.innerHTML = '<i class="fas fa-download"></i> Download JSON';
        downloadBtn.onclick = () => downloadFile(JSON.stringify(r), `${r.id}.json`, 'application/json');

        const deleteBtn = document.createElement("button");
        deleteBtn.className = "cyber-btn danger sm";
        deleteBtn.innerHTML = '<i class="fas fa-trash"></i> Delete';
        deleteBtn.onclick = () => deleteReport(r.id);

        actions.appendChild(downloadBtn);
        actions.appendChild(deleteBtn);
        card.appendChild(actions);
        grid.appendChild(card);
    });
}

function filterReportsByLevel(level) {
    if (level === 'all') {
        renderReports(State.currentReports);
    } else {
        const filtered = State.currentReports.filter(r => (r.riskAssessment?.level || 'low').toLowerCase() === level.toLowerCase());
        renderReports(filtered);
    }
    
    // Update the dropdown if it exists
    const filterSelect = document.getElementById("report-filter");
    if (filterSelect) filterSelect.value = level;
}

function filterReportsByPorts() {
    // Show reports that likely have ports (this is a simplified check for now)
    showSection('reports');
    renderReports(State.currentReports);
    showToast("Showing all reports. Specific port filtering coming soon.", "info");
}

async function deleteReport(id) {
    console.log("Deleting report:", id);
    try {
        const res = await fetch(`/api/report/${id}`, { method: 'DELETE' });
        if (res.ok) {
            showToast("Report deleted", "success");
            loadReports();
            loadDashboardStats(); // Refresh stats too
        } else {
            const err = await res.json();
            showToast(err.error || "Failed to delete report", "error");
        }
    } catch(e) {
        console.error("Delete Error:", e);
        showToast("Error deleting report", "error");
    }
}


async function loadDashboardStats() {
    try {
        const res = await fetch("/api/report/stats");
        const stats = await res.json();
        
        State.totalScans = stats.totalScans || 0;
        State.criticalVulns = stats.criticalVulns || 0;
        State.openPortsTotal = stats.openPorts || 0;
        State.reportsCount = stats.reportsCount || 0;
        
        updateDashboardStats();
    } catch(e) {
        console.error("Failed to load stats", e);
    }
    updateRecentScansUI();
}

function updateDashboardStats() {
    document.getElementById("total-scans").textContent = State.totalScans;
    document.getElementById("critical-vulns").textContent = State.criticalVulns;
    document.getElementById("open-ports").textContent = State.openPortsTotal;
    document.getElementById("reports-count").textContent = State.reportsCount;
}

function updateRecentScansUI() {
    const list = document.getElementById("recent-scans-list");
    if (!list) return;
    if (State.scanHistory.length === 0) {
        list.innerHTML = `<div class="empty-state"><i class="fas fa-search"></i><p>No scans yet.</p></div>`;
        return;
    }
    list.innerHTML = State.scanHistory.map(s => `
        <div class="scan-history-item" style="display:flex; justify-content:space-between; padding: 10px; border-bottom:1px solid rgba(0,255,255,0.1);">
            <span><strong>${s.target}</strong></span>
            <span>${s.time}</span>
            <span class="t-ok">${s.status}</span>
        </div>
    `).reverse().join("");
}

function clearHistory() {
    State.scanHistory = [];
    updateRecentScansUI();
    showToast("History cleared", "info");
}

// =================== TOOLS AREA ===================
async function runSingleTool(toolName) {
    const targetEl = document.getElementById(`${toolName}-target`);
    const target = targetEl ? targetEl.value : null;

    if (!target) {
        return showToast(`Enter a target for ${toolName}`, "warning");
    }

    let extraOptions = {};
    const typeIds = {
        'nmap': 'nmap-type',
        'nikto': 'nikto-type',
        'sqlmap': 'sqlmap-level',
        'openvas': 'openvas-scan',
        'grim': 'grim-type',
        'theharvester': 'harvester-source'
    };
    
    if (typeIds[toolName]) {
        const sel = document.getElementById(typeIds[toolName]);
        if (sel) extraOptions.profile = sel.value;
    }

    toolTerminalLog(`Running ${toolName} on ${target}...`);
    try {
        let endpoint = "/api/tools/run";
        let method = "POST";
        let body = JSON.stringify({ tool: toolName, domain: target, options: extraOptions });

        if (toolName === 'ipinfo') {
            endpoint = `/api/ipinfo/${target}`;
            method = "GET";
            body = null;
        }

        const res = await fetch(endpoint, {
            method: method,
            headers: { "Content-Type": "application/json" },
            body: body
        });
        const data = await res.json();
        
        if (data.error) {
            toolTerminalLog(`Error: ${data.error}`, "error");
        } else {
            let output = data.output;
            if (toolName === 'ipinfo' && data.data) {
                const d = data.data;
                output = `
IP Lookup: ${d.query}
---------------------------
Location: ${d.city}, ${d.regionName}, ${d.country}
ISP:      ${d.isp}
Org:      ${d.org}
ASN:      ${d.as}
Lat/Lon:  ${d.lat}, ${d.lon}
Timezone: ${d.timezone}
---------------------------`;
            }
            toolTerminalLog(output || "Completed with no output.", "ok");
            // Save to history
            saveToolHistory(toolName, target, output || "Completed with no output.");
        }
    } catch(e) {
        toolTerminalLog(`Exception: ${e.message}`, "error");
    }
}

// =================== TOOL HISTORY LOGIC ===================
async function loadAllToolHistory() {
    const tools = ['nmap', 'nikto', 'sqlmap', 'openvas', 'grim', 'theharvester', 'ipinfo', 'headers', 'wafw00f', 'whatweb', 'sublist3r', 'dirsearch', 'sherlock', 'amass', 'httpx', 'nuclei', 'shodan'];
    tools.forEach(tool => loadToolHistory(tool));
}

async function loadToolHistory(tool) {
    try {
        const res = await fetch(`/api/tool-history/${tool}`);
        const data = await res.json();
        const container = document.querySelector(`#${tool}-history .history-items`);
        if (!container) return;

        if (!data.history || data.history.length === 0) {
            container.innerHTML = '<div class="empty-state" style="font-size:10px; color:var(--text-muted);">No history.</div>';
            return;
        }

        container.innerHTML = data.history.map(entry => `
            <div class="history-item" onclick="viewHistoryItem('${tool}', '${entry.id}')">
                <div class="history-item-left">
                    <span class="history-item-target">${entry.target}</span>
                    <span class="history-item-time">${new Date(entry.timestamp).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}</span>
                </div>
                <button class="history-delete-btn" onclick="deleteHistoryItem(event, '${tool}', '${entry.id}')" title="Delete scan">
                    <i class="fas fa-trash-alt"></i>
                </button>
            </div>
        `).join('');

        // Store history in memory for easy viewing
        if (!State.toolHistory) State.toolHistory = {};
        State.toolHistory[tool] = data.history;

    } catch (e) {
        console.error(`Failed to load history for ${tool}`, e);
    }
}

async function saveToolHistory(tool, target, output) {
    try {
        await fetch('/api/tool-history/save', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool, target, output })
        });
        loadToolHistory(tool); // Reload this tool's history
    } catch (e) {
        console.error('Failed to save tool history', e);
    }
}

// Define globally on window to ensure availability from inline onclick
window.deleteHistoryItem = async function(event, tool, id) {
    console.log(`[ScanHexa] Deletion triggered for tool: ${tool}, id: ${id}`);
    event.stopPropagation(); // Prevent triggering viewHistoryItem
    
    showToast(`Removing ${tool} record...`, 'info');

    try {
        const url = `/api/tool-history/${tool}/${id}`;
        console.log(`[ScanHexa] Sending DELETE request to: ${url}`);
        
        const res = await fetch(url, { method: 'DELETE' });
        const data = await res.json();
        
        if (data.success) {
            console.log(`[ScanHexa] Deletion successful for id: ${id}`);
            loadToolHistory(tool); // Reload this tool's history
        } else {
            console.error(`[ScanHexa] Deletion failed:`, data.error);
            showToast('Deletion failed', 'error');
        }
    } catch (e) {
        console.error('[ScanHexa] Error in deleteHistoryItem:', e);
    }
};

function viewHistoryItem(tool, entryId) {
    if (!State.toolHistory || !State.toolHistory[tool]) return;
    const entry = State.toolHistory[tool].find(e => e.id === entryId);
    if (entry) {
        clearOutput();
        toolTerminalLog(`Restoring historical report for ${tool} on ${entry.target}...`, 'info');
        toolTerminalLog(`Timestamp: ${new Date(entry.timestamp).toLocaleString()}`, 'info');
        toolTerminalLog('-------------------------------------------', 'info');
        toolTerminalLog(entry.output, 'ok');
        
        // Scroll to terminal
        document.querySelector('.tool-output-panel').scrollIntoView({ behavior: 'smooth' });
    }
}

function toolTerminalLog(text, type='info') {
    const t = document.getElementById("tool-terminal");
    if (!t) return;
    t.innerHTML += `<div class="terminal-line"><span class="t-prompt">scanhexa@tools:~$</span> <span class="t-${type}">${text}</span></div>`;
    t.scrollTop = t.scrollHeight;
}

function clearOutput() {
    const t = document.getElementById("tool-terminal");
    if (t) t.innerHTML = `<div class="terminal-line"><span class="t-prompt">scanhexa@tools:~$</span> <span class="t-text">Cleared.</span></div>`;
}

function copyOutput() {
    const t = document.getElementById("tool-terminal");
    if (t) {
        navigator.clipboard.writeText(t.innerText);
        showToast("Copied to clipboard", "success");
    }
}

// =================== REPORT DOWNLOADS ===================
function generateReport(format) {
    if (!State.currentScan) {
        showToast("No scan data available", "error");
        return;
    }

    const data = State.currentScan;
    const filename = `ScanHexa_Report_${data.target}_${Date.now()}`;

    if (format === 'json') {
        downloadFile(JSON.stringify(data, null, 2), `${filename}.json`, 'application/json');
    } else if (format === 'html') {
        const html = `<html><body style="font-family:sans-serif;"><h1>ScanHexa Report: ${data.target}</h1><pre>${JSON.stringify(data, null, 2)}</pre></body></html>`;
        downloadFile(html, `${filename}.html`, 'text/html');
    } else if (format === 'pdf') {
        window.print();
    }
}

function downloadFile(content, fileName, contentType) {
    const a = document.createElement("a");
    const file = new Blob([content], { type: contentType });
    a.href = URL.createObjectURL(file);
    a.download = fileName;
    a.click();
}

function filterReports(query) {
    const q = query.toLowerCase();
    const filtered = State.currentReports.filter(r => 
        r.target.toLowerCase().includes(q) || 
        (r.riskAssessment?.level || '').toLowerCase().includes(q)
    );
    renderReports(filtered);
}

function filterReportsByType() {
    const level = document.getElementById("report-filter").value;
    filterReportsByLevel(level);
}


function exportAllReports() {
    showToast("Exporting all reports...", "info");
    State.currentReports.forEach(r => {
        downloadFile(JSON.stringify(r), `report_${r.id}.json`, 'application/json');
    });
}

function shareReport() {
    showToast("Share link copied!", "success");
}

// =================== UTILS ===================
function terminalLog(type, text) {
    const terminal = document.getElementById("terminal-output");
    if (!terminal) return;
    const line = document.createElement("div");
    line.className = `terminal-line t-${type}`;
    line.innerHTML = `<span class="t-prompt">scanhexa@cyber:~$</span> <span class="t-${type === 'error' ? 'text' : type}" ${type === 'error' ? 'style="color:#ff4757;"' : ''}>${text}</span>`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

function showToast(msg, type="info") {
    const cont = document.getElementById("toast-container");
    if (!cont) {
        const div = document.createElement("div");
        div.id = "toast-container";
        div.className = "toast-container";
        document.body.appendChild(div);
    }
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.style.padding = "10px 20px";
    toast.style.margin = "10px";
    toast.style.borderRadius = "4px";
    toast.style.color = "#fff";
    toast.style.background = type === "error" ? "#e74c3c" : type === "warning" ? "#f39c12" : type === "success" ? "#2ecc71" : "#3498db";
    toast.innerHTML = `<i class="fas fa-info-circle"></i> ${msg}`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

function showLoadingModal(show, target="") {
    const modal = document.getElementById("loading-modal");
    if (!modal) return;
    if (show) {
        document.getElementById("loading-msg").textContent = `Running security reconnaissance on ${target}...`;
        modal.classList.remove("hidden");
        modal.style.display = "flex"; // Ensure it shows
    } else {
        modal.classList.add("hidden");
        modal.style.display = "none";
    }
}

function getSelectedTools() {
    return [...document.querySelectorAll('input[name="tools"]:checked')].map(el => el.value);
}

function debounce(fn, delay) {
    let timeout;
    return (...args) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => fn(...args), delay);
    };
}