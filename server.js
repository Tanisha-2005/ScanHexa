require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// =================== MIDDLEWARE ===================
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Too many requests, please slow down.' }
});
app.use('/api/', limiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// Ensure reports directory exists
const reportsDir = path.join(__dirname, 'reports');
if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

// =================== ROUTES ===================
const scanRoutes = require('./routes/scan');
const reportRoutes = require('./routes/report');
const toolRoutes = require('./routes/tools');
const ipinfoRoutes = require('./routes/ipinfo');
const toolHistoryRoutes = require('./routes/tool_history');

app.use('/api/scan', scanRoutes);
app.use('/api/report', reportRoutes);
app.use('/api/tools', toolRoutes);
app.use('/api/ipinfo', ipinfoRoutes);
app.use('/api/tool-history', toolHistoryRoutes);

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'online',
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Serve main HTML
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error Handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Internal server error', details: err.message });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`
  ╔═══════════════════════════════════════════════╗
  ║   SCANHEXA - Cybersecurity Recon Platform     ║
  ║   Server running on http://localhost:${PORT}       ║
  ║   Version: 1.0.0                             ║
  ╚═══════════════════════════════════════════════╝
  `);
});

module.exports = app;