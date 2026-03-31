const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

router.get('/list', (req, res) => {
    try {
        const reportsDir = path.join(__dirname, '..', 'reports');
        if (!fs.existsSync(reportsDir)) {
            return res.json({ reports: [] });
        }

        const files = fs.readdirSync(reportsDir).filter(f => f.startsWith('report_') && f.endsWith('.json'));

        const reports = files.map(file => {
            const data = fs.readFileSync(path.join(reportsDir, file), 'utf8');
            try {
                const parsed = JSON.parse(data);
                // Return a summary of the report to the list
                return {
                    id: parsed.id,
                    target: parsed.target,
                    timestamp: parsed.timestamp,
                    riskAssessment: parsed.riskAssessment,
                    success: parsed.success
                };
            } catch (e) {
                return null;
            }
        }).filter(r => r !== null).sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        res.json({ reports });
    } catch (err) {
        console.error("Error fetching reports list:", err);
        res.status(500).json({ error: "Failed to fetch reports" });
    }
});

// Get specific report full data
router.get('/:id', (req, res) => {
    try {
        const id = req.params.id;
        const filePath = path.join(__dirname, '..', 'reports', `report_${id}.json`);

        if (fs.existsSync(filePath)) {
            const data = fs.readFileSync(filePath, 'utf8');
            res.json(JSON.parse(data));
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
        const filePath = path.join(__dirname, '..', 'reports', `report_${id}.json`);

        if (fs.existsSync(filePath)) {
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