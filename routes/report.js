const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

// Helper to get reports directory
const getReportsDir = () => path.join(__dirname, '..', 'reports');

router.get('/list', (req, res) => {
    try {
        const reportsDir = getReportsDir();
        if (!fs.existsSync(reportsDir)) {
            return res.json({ reports: [] });
        }

        const files = fs.readdirSync(reportsDir).filter(f => f.startsWith('report_') && f.endsWith('.json'));

        const userRole = req.session && req.session.user ? req.session.user.role : 'user';
        const username = req.session && req.session.user ? req.session.user.username : 'unknown';

        const reports = files.map(file => {
            try {
                const filePath = path.join(reportsDir, file);
                const data = fs.readFileSync(filePath, 'utf8');
                const parsed = JSON.parse(data);
                
                if (userRole !== 'admin' && userRole !== 'administrator' && parsed.user !== username) {
                    return null;
                }
                
                // Return a summary of the report to the list
                return {
                    id: parsed.id || file.replace('report_', '').replace('.json', ''),
                    target: parsed.target || 'Unknown',
                    timestamp: parsed.timestamp || new Date().toISOString(),
                    riskAssessment: parsed.riskAssessment || { level: 'low', score: 0 },
                    success: parsed.success !== undefined ? parsed.success : true,
                    user: parsed.user || 'unknown'
                };
            } catch (e) {
                console.error(`Error reading report file ${file}:`, e);
                return null;
            }
        }).filter(r => r !== null).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        res.json({ reports });
    } catch (err) {
        console.error("Error fetching reports list:", err);
        res.status(500).json({ error: "Failed to fetch reports" });
    }
});

// Get aggregate stats
router.get('/stats', (req, res) => {
    try {
        const reportsDir = getReportsDir();
        if (!fs.existsSync(reportsDir)) {
            return res.json({ totalScans: 0, criticalVulns: 0, openPorts: 0, reportsCount: 0 });
        }

        const files = fs.readdirSync(reportsDir).filter(f => f.startsWith('report_') && f.endsWith('.json'));
        
        let totalScans = 0;
        let criticalVulns = 0;
        let openPorts = 0;
        let reportsCount = 0;

        const userRole = req.session && req.session.user ? req.session.user.role : 'user';
        const username = req.session && req.session.user ? req.session.user.username : 'unknown';

        files.forEach(file => {
            try {
                const data = JSON.parse(fs.readFileSync(path.join(reportsDir, file), 'utf8'));
                
                if (userRole !== 'admin' && userRole !== 'administrator' && data.user !== username) {
                    return;
                }

                totalScans++;
                reportsCount++;

                const level = (data.riskAssessment?.level || '').toLowerCase();
                if (level === 'critical') {
                    criticalVulns++;
                }
                if (data.data && data.data.nmap && data.data.nmap.openPorts) {
                    openPorts += (data.data.nmap.openPorts.length || 0);
                }
            } catch (e) {}
        });

        res.json({ totalScans, criticalVulns, openPorts, reportsCount });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch stats" });
    }
});

// Get specific report full data
router.get('/:id', (req, res) => {
    try {
        const id = req.params.id;
        if (!id || id === 'stats' || id === 'list') return; 

        const filePath = path.join(getReportsDir(), `report_${id}.json`);

        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            const parsed = JSON.parse(data);
            
            const userRole = req.session && req.session.user ? req.session.user.role : 'user';
            const username = req.session && req.session.user ? req.session.user.username : 'unknown';

            if (userRole !== 'admin' && userRole !== 'administrator' && parsed.user !== username) {
                return res.status(403).json({ error: "Access denied" });
            }

            res.json(parsed);
        } else {
            res.status(404).json({ error: "Report not found" });
        }
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch report" });
    }
});

// Delete specific report
router.delete('/:id', (req, res) => {
    try {
        const id = req.params.id;
        const filePath = path.join(getReportsDir(), `report_${id}.json`);

        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            const parsed = JSON.parse(data);
            
            const userRole = req.session && req.session.user ? req.session.user.role : 'user';
            const username = req.session && req.session.user ? req.session.user.username : 'unknown';

            if (userRole !== 'admin' && userRole !== 'administrator' && parsed.user !== username) {
                return res.status(403).json({ error: "Access denied" });
            }

            fs.unlinkSync(filePath);
            res.json({ success: true, message: "Report deleted successfully" });
        } else {
            res.status(404).json({ error: "Report not found" });
        }
    } catch (err) {
        res.status(500).json({ error: "Failed to delete report" });
    }
});

module.exports = router;