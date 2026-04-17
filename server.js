require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');

const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;

// Attach io to app to make it accessible in routes
app.set('io', io);

io.on('connection', (socket) => {
    console.log('[Socket] New client connected:', socket.id);
    socket.on('disconnect', () => {
        console.log('[Socket] Client disconnected');
    });
});

// =================== MIDDLEWARE ===================
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));
app.use(cors());
app.use(morgan('dev'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'scanhexa-secret-99',
    resave: false,
    saveUninitialized: false,
    name: 'SCANHEXA_SESSION', // Robust name for dev/prod
    cookie: { 
        secure: process.env.NODE_ENV === 'production', // true if HTTPS
        httpOnly: true, // Prevents XSS script access
        sameSite: 'strict', // Mitigates CSRF
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Too many requests, please slow down.' }
});
app.use('/api/', limiter);

// =================== AUTHENTICATION ===================
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const storedHash = process.env.ADMIN_PASSWORD_HASH;

        // Verify username and check password against hash
        if (username === 'admin' && storedHash) {
            const isMatch = await bcrypt.compare(password, storedHash);
            
            if (isMatch) {
                req.session.authenticated = true;
                req.session.user = { username: 'admin', role: 'administrator' };
                return res.json({ success: true, message: 'Login successful' });
            }
        }
        
        res.status(401).json({ error: 'Invalid username or password' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Authentication service error' });
    }
});

app.get('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) return res.status(500).json({ error: 'Could not log out' });
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

// Middleware to protect routes
const protectRoute = (req, res, next) => {
    // List of public paths
    const publicPaths = ['/login.html', '/api/login'];
    
    if (req.session.authenticated || publicPaths.includes(req.path)) {
        return next();
    }

    // Allow static assets (optional, depending on if you want to hide CSS/JS)
    if (req.path.match(/\.(css|js|png|jpg|jpeg|svg|ico)$/)) {
        return next();
    }

    if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    
    res.redirect('/login.html');
};

app.use(protectRoute);

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

server.listen(PORT, '0.0.0.0', () => {
    console.log(`
  ╔═══════════════════════════════════════════════╗
  ║   SCANHEXA - Cybersecurity Recon Platform     ║
  ║   Server running on http://localhost:${PORT}       ║
  ║   Version: 1.0.0                             ║
  ╚═══════════════════════════════════════════════╝
  `);
});

module.exports = app;