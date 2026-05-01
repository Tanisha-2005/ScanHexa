const express = require('express');
const router = express.Router();
const Report = require('../models/Report');

router.get('/list', async (req, res) => {
    try {
        const userRole = req.session && req.session.user ? req.session.user.role : 'user';
        const username = req.session && req.session.user ? req.session.user.username : 'unknown';

        let query = {};
        if (userRole !== 'admin' && userRole !== 'administrator') {
            query.user = username;
        }

        const dbReports = await Report.find(query).sort({ createdAt: -1 });

        const reports = dbReports.map(parsed => ({
            id: parsed.scanId,
            target: parsed.target || 'Unknown',
            timestamp: parsed.createdAt || new Date().toISOString(),
            riskAssessment: parsed.riskAssessment || { level: 'low', score: 0 },
            success: parsed.success !== undefined ? parsed.success : true,
            user: parsed.user || 'unknown'
        }));

        res.json({ reports });
    } catch (err) {
        console.error("Error fetching reports list:", err);
        res.status(500).json({ error: "Failed to fetch reports" });
    }
});

// Get aggregate stats
router.get('/stats', async (req, res) => {
    try {
        const userRole = req.session && req.session.user ? req.session.user.role : 'user';
        const username = req.session && req.session.user ? req.session.user.username : 'unknown';

        let query = {};
        if (userRole !== 'admin' && userRole !== 'administrator') {
            query.user = username;
        }

        const dbReports = await Report.find(query);
        
        let totalScans = dbReports.length;
        let criticalVulns = 0;
        let openPorts = 0;
        let reportsCount = dbReports.length;

        dbReports.forEach(data => {
            const level = (data.riskAssessment?.level || '').toLowerCase();
            if (level === 'critical') {
                criticalVulns++;
            }
            if (data.data && data.data.nmap && data.data.nmap.openPorts) {
                openPorts += (data.data.nmap.openPorts.length || 0);
            }
        });

        res.json({ totalScans, criticalVulns, openPorts, reportsCount });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch stats" });
    }
});

// Get specific report full data
router.get('/:id', async (req, res) => {
    try {
        const id = req.params.id;
        if (!id || id === 'stats' || id === 'list') return; 

        const parsed = await Report.findOne({ scanId: id });

        if (parsed) {
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
router.delete('/:id', async (req, res) => {
    try {
        const id = req.params.id;
        
        const parsed = await Report.findOne({ scanId: id });

        if (parsed) {
            const userRole = req.session && req.session.user ? req.session.user.role : 'user';
            const username = req.session && req.session.user ? req.session.user.username : 'unknown';

            if (userRole !== 'admin' && userRole !== 'administrator' && parsed.user !== username) {
                return res.status(403).json({ error: "Access denied" });
            }

            await Report.deleteOne({ scanId: id });
            res.json({ success: true, message: "Report deleted successfully" });
        } else {
            res.status(404).json({ error: "Report not found" });
        }
    } catch (err) {
        res.status(500).json({ error: "Failed to delete report" });
    }
});

module.exports = router;