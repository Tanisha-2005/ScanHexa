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
app.set('trust proxy', true);
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

// =================== USER MANAGEMENT ===================
const usersFilePath = path.join(__dirname, 'data', 'users.json');

// Helper to read users
const getUsers = () => {
    try {
        if (!fs.existsSync(usersFilePath)) {
            // Generate default admin if not exists (especially for fresh Render deployments)
            const defaultAdmin = [{
                username: "admin",
                passwordHash: "$2b$10$uVdX.H25VwOXI24/WeuMUeSLrdEShcRRA3x8YHbvwpYIPounJZNR2", // Hash for @helloadmin123
                role: "admin",
                contact: "admin@scanhexa.com"
            }];
            const dir = path.dirname(usersFilePath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            fs.writeFileSync(usersFilePath, JSON.stringify(defaultAdmin, null, 2));
            return defaultAdmin;
        }
        const data = fs.readFileSync(usersFilePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Error reading users.json:', err);
        return [];
    }
};

// Helper to save users
const saveUsers = (users) => {
    try {
        const dir = path.dirname(usersFilePath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2));
    } catch (err) {
        console.error('Error writing users.json:', err);
    }
};

// =================== AUTHENTICATION ===================
app.post('/api/login', async (req, res) => {
    try {
        const username = req.body.username ? req.body.username.toLowerCase().trim() : '';
        const password = req.body.password;
        
        const users = getUsers();
        const user = users.find(u => u.username === username);

        if (user) {
            if (user.blocked) {
                return res.status(403).json({ error: 'Account has been blocked by Administrator' });
            }
            const isMatch = await bcrypt.compare(password, user.passwordHash);
            
            if (isMatch) {
                console.log(`[Auth-Diagnostic] SUCCESS: ${username} authenticated`);
                req.session.authenticated = true;
                req.session.user = { username: user.username, role: user.role };
                return res.json({ success: true, message: 'Login successful', role: user.role });
            } else {
                console.warn(`[Auth-Diagnostic] FAILED: Password mismatch for ${username}`);
            }
        } else {
            console.warn(`[Auth-Diagnostic] FAILED: User not found: ${username}`);
        }
        
        res.status(401).json({ error: 'Invalid username or password' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Authentication service error' });
    }
});

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, contact } = req.body;
        if (!username || !password || !contact) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const normalizedUsername = username.toLowerCase().trim();
        const users = getUsers();
        
        if (users.find(u => u.username === normalizedUsername)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        users.push({
            username: normalizedUsername,
            passwordHash,
            role: 'user', // Default role is user
            contact: contact.trim()
        });
        
        saveUsers(users);
        res.json({ success: true, message: 'Registration successful' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration service error' });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { username, contact, newPassword } = req.body;
        if (!username || !contact || !newPassword) {
            return res.status(400).json({ error: 'Username, contact details, and new password are required' });
        }

        const normalizedUsername = username.toLowerCase().trim();
        const users = getUsers();
        const userIndex = users.findIndex(u => u.username === normalizedUsername && u.contact === contact);

        if (userIndex !== -1) {
            const passwordHash = await bcrypt.hash(newPassword, 10);
            users[userIndex].passwordHash = passwordHash;
            saveUsers(users);
            return res.json({ success: true, message: 'Password updated successfully' });
        } else {
            return res.status(404).json({ error: 'User details not found or contact info mismatch' });
        }
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Forgot password service error' });
    }
});

app.get('/api/users', (req, res) => {
    if (req.session.authenticated && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'administrator')) {
        const users = getUsers().map(u => ({
            username: u.username,
            role: u.role,
            contact: u.contact,
            blocked: u.blocked || false
        }));
        res.json({ success: true, users });
    } else {
        res.status(403).json({ error: 'Access denied. Administrator privileges required.' });
    }
});

app.delete('/api/users/:username', (req, res) => {
    if (req.session.authenticated && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'administrator')) {
        const usernameToDelete = req.params.username;
        if (usernameToDelete === 'admin') return res.status(400).json({ error: 'Cannot delete the master admin.' });
        
        let users = getUsers();
        const initialLength = users.length;
        users = users.filter(u => u.username !== usernameToDelete);
        
        if (users.length < initialLength) {
            saveUsers(users);
            res.json({ success: true, message: 'User deleted successfully' });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

app.post('/api/users/:username/toggle-block', (req, res) => {
    if (req.session.authenticated && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'administrator')) {
        const usernameToBlock = req.params.username;
        if (usernameToBlock === 'admin') return res.status(400).json({ error: 'Cannot block the master admin.' });
        
        let users = getUsers();
        const user = users.find(u => u.username === usernameToBlock);
        
        if (user) {
            user.blocked = !user.blocked;
            saveUsers(users);
            res.json({ success: true, blocked: user.blocked, message: `User ${user.blocked ? 'blocked' : 'unblocked'}` });
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

app.get('/api/me', (req, res) => {
    if (req.session.authenticated && req.session.user) {
        res.json({ success: true, user: req.session.user });
    } else {
        res.status(401).json({ error: 'Not authenticated' });
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
  ║   Trust Proxy: ${app.get('trust proxy')}                 ║
  ║   Version: 1.0.0                             ║
  ╚═══════════════════════════════════════════════╝
  `);
});

module.exports = app;