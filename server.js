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
const mongoose = require('mongoose');

const User = require('./models/User');

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

// =================== DATABASE CONNECTION ===================
const mongoURI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/scanhexa';
mongoose.connect(mongoURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(async () => {
    console.log('[MongoDB] Connected successfully');
    
    // Auto-generate default admin if no users exist
    const adminExists = await User.findOne({ username: 'admin' });
    if (!adminExists) {
        const passwordHash = await bcrypt.hash('helloadmin123', 10);
        await User.create({
            username: 'admin',
            passwordHash,
            role: 'admin',
            contact: 'admin@scanhexa.com'
        });
        console.log('[MongoDB] Default admin user created.');
    }
}).catch(err => {
    console.error('[MongoDB] Connection error:', err);
});


// =================== AUTHENTICATION ===================
app.post('/api/login', async (req, res) => {
    try {
        const username = req.body.username ? req.body.username.toLowerCase().trim() : '';
        const password = req.body.password;
        
        const user = await User.findOne({ username });

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
        const existingUser = await User.findOne({ username: normalizedUsername });
        
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        const user = new User({
            username: normalizedUsername,
            passwordHash,
            role: 'user', // Default role is user
            contact: contact.trim()
        });
        
        await user.save();
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
        const user = await User.findOne({ username: normalizedUsername, contact });

        if (user) {
            const passwordHash = await bcrypt.hash(newPassword, 10);
            user.passwordHash = passwordHash;
            await user.save();
            return res.json({ success: true, message: 'Password updated successfully' });
        } else {
            return res.status(404).json({ error: 'User details not found or contact info mismatch' });
        }
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'Forgot password service error' });
    }
});

app.get('/api/users', async (req, res) => {
    if (req.session.authenticated && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'administrator')) {
        try {
            const allUsers = await User.find({}, 'username role contact blocked');
            res.json({ success: true, users: allUsers });
        } catch (error) {
            res.status(500).json({ error: 'Failed to fetch users' });
        }
    } else {
        res.status(403).json({ error: 'Access denied. Administrator privileges required.' });
    }
});

app.delete('/api/users/:username', async (req, res) => {
    if (req.session.authenticated && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'administrator')) {
        const usernameToDelete = req.params.username;
        if (usernameToDelete === 'admin') return res.status(400).json({ error: 'Cannot delete the master admin.' });
        
        try {
            const result = await User.deleteOne({ username: usernameToDelete });
            if (result.deletedCount > 0) {
                res.json({ success: true, message: 'User deleted successfully' });
            } else {
                res.status(404).json({ error: 'User not found' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Failed to delete user' });
        }
    } else {
        res.status(403).json({ error: 'Access denied' });
    }
});

app.post('/api/users/:username/toggle-block', async (req, res) => {
    if (req.session.authenticated && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'administrator')) {
        const usernameToBlock = req.params.username;
        if (usernameToBlock === 'admin') return res.status(400).json({ error: 'Cannot block the master admin.' });
        
        try {
            const user = await User.findOne({ username: usernameToBlock });
            if (user) {
                user.blocked = !user.blocked;
                await user.save();
                res.json({ success: true, blocked: user.blocked, message: `User ${user.blocked ? 'blocked' : 'unblocked'}` });
            } else {
                res.status(404).json({ error: 'User not found' });
            }
        } catch (error) {
            res.status(500).json({ error: 'Failed to block user' });
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