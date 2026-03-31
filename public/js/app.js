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

    // Load actual reports from backend
    loadReports();
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
                    osDetect: document.getElementById("os-detect")?.checked || false
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
            if (scanResult.data.nmap && scanResult.data.nmap.openPorts) {
                State.openPortsTotal += scanResult.data.nmap.openPorts.length;
            }
        }
        updateDashboardStats();
        
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
             nmapHtml += `<ul>`;
             (scan.data.nmap.openPorts || []).forEach(p => {
                 nmapHtml += `<li>Port ${p.port} (${p.protocol}): ${p.service} - ${p.state}</li>`;
             });
             nmapHtml += `</ul><pre>${scan.data.nmap.rawOutput || ''}</pre>`;
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
             niktoHtml += `<ul>`;
             (scan.data.nikto.vulnerabilities || []).forEach(v => {
                 niktoHtml += `<li>${v}</li>`;
             });
             niktoHtml += `</ul><pre>${scan.data.nikto.rawOutput || ''}</pre>`;
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
        let ovHtml = '<h3>OpenVAS Assessment</h3>';
        if (scan.data.openvas.error) ovHtml += `<p class="error" style="color:#ff4757;">${scan.data.openvas.error}</p>`;
        else {
             ovHtml += `<pre>${scan.data.openvas.rawOutput || 'No output Data'}</pre>`;
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
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    
    document.getElementById(sectionId).classList.add('active');
    const navLink = document.querySelector(`.nav-link[onclick="showSection('${sectionId}')"]`);
    if (navLink) navLink.classList.add('active');
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

        if (State.currentReports.length === 0) {
            if(grid) grid.innerHTML = `<div class="empty-state center"><i class="fas fa-folder-open"></i><p>No reports generated yet.</p></div>`;
            return;
        }

        if(grid) grid.innerHTML = State.currentReports.map(r => `
            <div class="report-card panel">
                <h3>Target: ${r.target}</h3>
                <p>Date: ${new Date(r.timestamp).toLocaleString()}</p>
                <div style="margin-top:10px;">
                <span class="badge ${r.riskAssessment?.level || 'low'}" style="padding:4px 8px; border-radius:4px; font-weight:bold; background:rgba(255,255,255,0.1);">${(r.riskAssessment?.level || 'Low').toUpperCase()} RISK</span>
                <span style="margin-left:8px;">Score: ${r.riskAssessment?.score || 0}</span>
                </div>
                <div style="margin-top:15px; display:flex; gap:10px;">
                    <button onclick="downloadFile(JSON.stringify(${JSON.stringify(r).replace(/"/g, '&quot;')}), '${r.id}.json', 'application/json')" class="cyber-btn primary sm"><i class="fas fa-download"></i> Download JSON</button>
                    <button onclick="deleteReport('${r.id}')" class="cyber-btn danger sm"><i class="fas fa-trash"></i> Delete</button>
                </div>
            </div>
        `).join("");

    } catch(e) {
        console.error("Failed to load reports", e);
    }
}

async function deleteReport(id) {
    if (!confirm("Are you sure you want to delete this report?")) return;
    try {
        const res = await fetch(`/api/report/${id}`, { method: 'DELETE' });
        if (res.ok) {
            showToast("Report deleted", "success");
            loadReports();
        } else {
            showToast("Failed to delete report", "error");
        }
    } catch(e) {
        showToast("Error deleting report", "error");
    }
}

function loadDashboardStats() {
    updateDashboardStats();
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
        const res = await fetch("/api/tools/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ tool: toolName, domain: target, options: extraOptions })
        });
        const data = await res.json();
        
        if (data.error) {
            toolTerminalLog(`Error: ${data.error}`, "error");
        } else {
            toolTerminalLog(data.output || "Completed with no output.", "ok");
        }
    } catch(e) {
        toolTerminalLog(`Exception: ${e.message}`, "error");
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
    showToast("Filter functionality available on full version", "info");
}

function filterReportsByType() {
    showToast("Filter functionality available on full version", "info");
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