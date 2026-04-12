const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');

const HISTORY_DIR = path.join(__dirname, '../data/tool_history');

// Ensure history directory exists
if (!fs.existsSync(HISTORY_DIR)) {
    fs.mkdirSync(HISTORY_DIR, { recursive: true });
}

// Get history for a specific tool
router.get('/:tool', (req, res) => {
    try {
        const { tool } = req.params;
        const toolFilePath = path.join(HISTORY_DIR, `${tool}.json`);

        if (!fs.existsSync(toolFilePath)) {
            return res.json({ history: [] });
        }

        const data = JSON.parse(fs.readFileSync(toolFilePath, 'utf8'));
        res.json({ history: data });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch history' });
    }
});

// Save history for a specific tool
router.post('/save', (req, res) => {
    try {
        const { tool, target, output } = req.body;
        if (!tool || !target) {
            return res.status(400).json({ error: 'Missing tool or target' });
        }

        const toolFilePath = path.join(HISTORY_DIR, `${tool}.json`);
        let history = [];

        if (fs.existsSync(toolFilePath)) {
            history = JSON.parse(fs.readFileSync(toolFilePath, 'utf8'));
        }

        const newEntry = {
            id: Date.now().toString(),
            target,
            timestamp: new Date().toISOString(),
            output
        };

        // Keep only last 10 scans per tool
        history.unshift(newEntry);
        history = history.slice(0, 10);

        fs.writeFileSync(toolFilePath, JSON.stringify(history, null, 2));
        res.json({ success: true, entry: newEntry });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save history' });
    }
});

module.exports = router;
