const express = require("express");
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { runScan } = require("../utils/scanner");

function calculateRiskAssessment(scanData) {
    let score = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;

    // Check for tool errors
    const toolsWithErrors = Object.values(scanData).filter(result => result && result.error).length;
    if (toolsWithErrors > 0) {
        score += toolsWithErrors * 10;
    }

    // Nmap results
    if (scanData.nmap && !scanData.nmap.error) {
        const openPorts = scanData.nmap.openPorts || [];
        const dangerousPorts = [21, 23, 3389, 445, 6379, 27017, 1433, 5900];
        const dangerousOpen = openPorts.filter(p => dangerousPorts.includes(parseInt(p.port))).length;

        score += openPorts.length * 2;
        score += dangerousOpen * 15;
        if (dangerousOpen > 0) criticalCount++;
    }

    // Nikto results
    if (scanData.nikto && !scanData.nikto.error) {
        const findings = scanData.nikto.vulnerabilities || [];
        score += findings.length * 5;
        if (findings.length > 10) highCount++;
        else if (findings.length > 5) mediumCount++;
    }

    // theHarvester results
    if (scanData.theharvester && !scanData.theharvester.error) {
        const findings = scanData.theharvester.rawOutput || "";
        const emailMatches = findings.match(/@/g) || [];
        score += emailMatches.length * 3;
        if (emailMatches.length > 20) mediumCount++;
    }

    // Cap score at 100
    score = Math.min(score, 100);

    // Determine level
    let level = 'low';
    if (score >= 80 || criticalCount > 0) level = 'critical';
    else if (score >= 60 || highCount > 0) level = 'high';
    else if (score >= 30 || mediumCount > 0) level = 'medium';

    return { level, score };
}

// Start scan
router.post("/start", async(req, res) => {
    try {
        const { target, tools, profile, options } = req.body;

        if (!target) {
            return res.status(400).json({
                error: "Target is required"
            });
        }

        if (!tools || tools.length === 0) {
            return res.status(400).json({
                error: "At least one tool must be selected"
            });
        }

        const result = await runScan(target, tools, profile, options);

        // Calculate risk assessment based on results
        const riskAssessment = calculateRiskAssessment(result);

        const scanId = Date.now().toString();
        const responseData = {
            success: true,
            target,
            id: scanId,
            data: result,
            riskAssessment,
            timestamp: new Date().toISOString()
        };

        // Save report to disk
        try {
            const reportsDir = path.join(__dirname, '..', 'reports');
            if (!fs.existsSync(reportsDir)) {
                fs.mkdirSync(reportsDir, { recursive: true });
            }
            fs.writeFileSync(path.join(reportsDir, `report_${scanId}.json`), JSON.stringify(responseData, null, 2));
        } catch (saveError) {
            console.error("Failed to save report:", saveError);
        }

        res.json(responseData);

    } catch (error) {
        console.error('Scan error:', error);
        res.status(500).json({
            error: "Scan failed",
            message: error.message
        });
    }
});

module.exports = router;