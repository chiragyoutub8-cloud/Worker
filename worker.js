// DroxPlays Cloudflare Worker
// Deploy at: Cloudflare Dashboard → Workers & Pages → Create Worker → paste this → Save & Deploy
// Then: Settings → Variables → Add binding: D1 Database → name: DB → select droxdata

const GOOGLE_CLIENT_ID = '622183515990-j6gab5nn8dfonkljilne9skkahdtj566.apps.googleusercontent.com';
const OWNER_EMAIL = 'droxowner@gmail.com';
const ALLOWED_ORIGINS = [
  'https://droxplays.qzz.io',
  'https://droxplays-api.droxteams.workers.dev',
];

// ─── JWT helpers (simple, no crypto deps needed for Google token verification) ───
function b64decode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

function parseJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    return JSON.parse(b64decode(parts[1]));
  } catch { return null; }
}

async function verifyGoogleToken(token) {
  try {
    // Verify with Google's tokeninfo endpoint
    const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${token}`);
    if (!res.ok) return null;
    const data = await res.json();
    if (data.aud !== GOOGLE_CLIENT_ID) return null;
    return data;
  } catch { return null; }
}

// ─── Simple session token (stored in DB) ───
function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

async function getSession(request, db) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return null;
  const token = auth.slice(7);
  const row = await db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?')
    .bind(token, Date.now()).first();
  if (!row) return null;
  return row;
}

// ─── CORS ───
function corsHeaders(request) {
  const origin = request.headers.get('Origin') || '';
  // Allow all origins — safe because we use Bearer tokens, not cookies.
  // This also fixes "Failed to fetch" when the HTML is opened as a local file
  // (which sends Origin: null, not matched by the allowlist).
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : '*';
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
  };
}

function json(data, status = 200, request) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request) },
  });
}

function err(msg, status = 400, request) {
  return json({ error: msg }, status, request);
}

// ─── MAIN HANDLER ───
export default {
  async fetch(request, env) {
    const db = env.DB;

    // Ensure sessions table exists
    await db.exec(`CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      user_email TEXT,
      expires_at INTEGER
    )`);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // ─── AUTH ROUTES ───
      if (path === '/auth/google' && method === 'POST') {
        const { token } = await request.json();
        if (!token) return err('Missing token', 400, request);

        const gUser = await verifyGoogleToken(token);
        if (!gUser) return err('Invalid Google token', 401, request);

        const { sub: googleId, email, name, picture } = gUser;
        const userId = 'g_' + googleId;

        // Upsert user
        await db.prepare(`INSERT INTO users (id, email, name, avatar_url, last_login)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(id) DO UPDATE SET last_login=excluded.last_login, avatar_url=excluded.avatar_url`)
          .bind(userId, email, name || email.split('@')[0], picture || null, Date.now()).run();

        const sessionToken = generateToken();
        const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
        await db.prepare('INSERT INTO sessions (token, user_id, user_email, expires_at) VALUES (?, ?, ?, ?)')
          .bind(sessionToken, userId, email, expiresAt).run();

        const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
        return json({ token: sessionToken, user }, 200, request);
      }

      if (path === '/auth/register' && method === 'POST') {
        const { email, password, name } = await request.json();
        if (!email || !password || !name) return err('Missing fields', 400, request);
        if (password.length < 6) return err('Password too short', 400, request);

        const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
        if (existing) return err('Email already in use', 409, request);

        const passwordHash = await hashPassword(password);
        const userId = 'u_' + generateId();

        await db.prepare('INSERT INTO users (id, email, name, created_at) VALUES (?, ?, ?, ?)')
          .bind(userId, email, name, Date.now()).run();

        // Store password separately
        await db.exec(`CREATE TABLE IF NOT EXISTS passwords (user_id TEXT PRIMARY KEY, hash TEXT)`);
        await db.prepare('INSERT INTO passwords (user_id, hash) VALUES (?, ?)').bind(userId, passwordHash).run();

        const sessionToken = generateToken();
        const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
        await db.prepare('INSERT INTO sessions (token, user_id, user_email, expires_at) VALUES (?, ?, ?, ?)')
          .bind(sessionToken, userId, email, expiresAt).run();

        const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
        return json({ token: sessionToken, user }, 201, request);
      }

      if (path === '/auth/login' && method === 'POST') {
        const { email, password } = await request.json();
        if (!email || !password) return err('Missing fields', 400, request);

        await db.exec(`CREATE TABLE IF NOT EXISTS passwords (user_id TEXT PRIMARY KEY, hash TEXT)`);

        const user = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
        if (!user) return err('Account not found', 404, request);

        const pwRow = await db.prepare('SELECT hash FROM passwords WHERE user_id = ?').bind(user.id).first();
        if (!pwRow) return err('Use Google sign-in for this account', 400, request);

        const valid = await verifyPassword(password, pwRow.hash);
        if (!valid) return err('Incorrect password', 401, request);

        await db.prepare('UPDATE users SET last_login = ? WHERE id = ?').bind(Date.now(), user.id).run();

        const sessionToken = generateToken();
        const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;
        await db.prepare('INSERT INTO sessions (token, user_id, user_email, expires_at) VALUES (?, ?, ?, ?)')
          .bind(sessionToken, user.id, email, expiresAt).run();

        return json({ token: sessionToken, user }, 200, request);
      }

      if (path === '/auth/logout' && method === 'POST') {
        const auth = request.headers.get('Authorization');
        if (auth) {
          const token = auth.slice(7);
          await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
        }
        return json({ ok: true }, 200, request);
      }

      if (path === '/auth/forgot-password' && method === 'POST') {
        // In a real app you'd send an email; for now just confirm
        return json({ ok: true, message: 'If that email exists, a reset link was sent' }, 200, request);
      }

      if (path === '/auth/me' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(session.user_id).first();
        return json({ user }, 200, request);
      }

      // ─── SONGS ───
      if (path === '/songs' && method === 'GET') {
        const status = url.searchParams.get('status') || 'approved';
        const songs = await db.prepare('SELECT * FROM songs WHERE status = ? ORDER BY uploaded_at DESC').bind(status).all();
        return json({ songs: songs.results }, 200, request);
      }

      if (path === '/songs' && method === 'POST') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const { title, artist, genre, audio_url, thumb_url } = await request.json();
        if (!title || !artist || !audio_url) return err('Missing fields', 400, request);
        const id = generateId();
        await db.prepare(`INSERT INTO songs (id, title, artist, genre, audio_url, thumb_url, status, uploaded_by, uploader_email, uploaded_at)
          VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)`)
          .bind(id, title, artist, genre || 'Other', audio_url, thumb_url || null, session.user_id, session.user_email, Date.now()).run();
        return json({ id, message: 'Song submitted for review' }, 201, request);
      }

      if (path.startsWith('/songs/') && method === 'PUT') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const id = path.split('/')[2];
        const body = await request.json();
        if (body.status) {
          await db.prepare('UPDATE songs SET status = ? WHERE id = ?').bind(body.status, id).run();
        }
        return json({ ok: true }, 200, request);
      }

      if (path.startsWith('/songs/') && method === 'DELETE') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const id = path.split('/')[2];
        await db.prepare('DELETE FROM songs WHERE id = ?').bind(id).run();
        return json({ ok: true }, 200, request);
      }

      if (path.startsWith('/songs/') && path.endsWith('/play') && method === 'POST') {
        const id = path.split('/')[2];
        await db.prepare('UPDATE songs SET plays = plays + 1 WHERE id = ?').bind(id).run();
        return json({ ok: true }, 200, request);
      }

      // ─── LIKES ───
      if (path === '/likes' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const likes = await db.prepare('SELECT song_id FROM likes WHERE user_id = ?').bind(session.user_id).all();
        return json({ likes: likes.results.map(r => r.song_id) }, 200, request);
      }

      if (path.startsWith('/likes/') && method === 'POST') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const songId = path.split('/')[2];
        await db.prepare('INSERT OR IGNORE INTO likes (user_id, song_id, liked_at) VALUES (?, ?, ?)')
          .bind(session.user_id, songId, Date.now()).run();
        await db.prepare('UPDATE songs SET likes = likes + 1 WHERE id = ?').bind(songId).run();
        return json({ ok: true }, 200, request);
      }

      if (path.startsWith('/likes/') && method === 'DELETE') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const songId = path.split('/')[2];
        await db.prepare('DELETE FROM likes WHERE user_id = ? AND song_id = ?').bind(session.user_id, songId).run();
        await db.prepare('UPDATE songs SET likes = MAX(0, likes - 1) WHERE id = ?').bind(songId).run();
        return json({ ok: true }, 200, request);
      }

      // ─── PLAYLISTS ───
      if (path === '/playlists' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const playlists = await db.prepare('SELECT * FROM playlists WHERE user_id = ? ORDER BY created_at DESC').bind(session.user_id).all();
        return json({ playlists: playlists.results }, 200, request);
      }

      if (path === '/playlists' && method === 'POST') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const { name } = await request.json();
        if (!name) return err('Missing name', 400, request);
        const id = generateId();
        await db.prepare('INSERT INTO playlists (id, user_id, name, created_at) VALUES (?, ?, ?, ?)')
          .bind(id, session.user_id, name, Date.now()).run();
        return json({ id }, 201, request);
      }

      // ─── HISTORY ───
      if (path === '/history' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const history = await db.prepare('SELECT * FROM history WHERE user_id = ? ORDER BY played_at DESC LIMIT 50').bind(session.user_id).all();
        return json({ history: history.results }, 200, request);
      }

      if (path === '/history' && method === 'POST') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const { song_id, title, artist } = await request.json();
        await db.prepare('INSERT INTO history (user_id, song_id, title, artist, played_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, song_id) DO UPDATE SET played_at=excluded.played_at')
          .bind(session.user_id, song_id, title, artist, Date.now()).run();
        return json({ ok: true }, 200, request);
      }

      // ─── SETTINGS ───
      if (path === '/settings' && method === 'GET') {
        const rows = await db.prepare('SELECT key, value FROM settings').all();
        const settings = {};
        rows.results.forEach(r => settings[r.key] = r.value);
        return json({ settings }, 200, request);
      }

      if (path === '/settings' && method === 'POST') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const body = await request.json();
        for (const [key, value] of Object.entries(body)) {
          await db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
            .bind(key, String(value)).run();
        }
        return json({ ok: true }, 200, request);
      }

      // ─── ADMIN: all songs ───
      if (path === '/admin/songs' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const songs = await db.prepare('SELECT * FROM songs ORDER BY uploaded_at DESC').all();
        return json({ songs: songs.results }, 200, request);
      }

      if (path === '/admin/stats' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const users = await db.prepare('SELECT COUNT(*) as count FROM users').first();
        const songs = await db.prepare('SELECT COUNT(*) as count FROM songs').first();
        const pending = await db.prepare("SELECT COUNT(*) as count FROM songs WHERE status='pending'").first();
        return json({ users: users.count, songs: songs.count, pending: pending.count }, 200, request);
      }

      if (path === '/admin/users' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const users = await db.prepare('SELECT id, email, name, membership, created_at FROM users ORDER BY created_at DESC').all();
        return json({ users: users.results }, 200, request);
      }

      if (path.startsWith('/admin/users/') && method === 'PUT') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const uid = path.split('/')[3];
        const { membership } = await request.json();
        await db.prepare('UPDATE users SET membership = ? WHERE id = ?').bind(membership, uid).run();
        return json({ ok: true }, 200, request);
      }

      // ─── REPORTS ───
      if (path === '/reports' && method === 'POST') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const { song_id } = await request.json();
        const id = generateId();
        await db.prepare('INSERT INTO reports (id, song_id, reported_by, reported_at) VALUES (?, ?, ?, ?)')
          .bind(id, song_id, session.user_id, Date.now()).run();
        return json({ ok: true }, 200, request);
      }

      if (path === '/reports' && method === 'GET') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const reports = await db.prepare('SELECT * FROM reports ORDER BY reported_at DESC').all();
        return json({ reports: reports.results }, 200, request);
      }

      // ─── COUPONS ───
      if (path === '/coupons' && method === 'POST') {
        const session = await getSession(request, db);
        if (!session || session.user_email !== OWNER_EMAIL) return err('Forbidden', 403, request);
        const { code, discount, plan } = await request.json();
        await db.prepare('INSERT INTO coupons (code, discount, plan, created_at, active) VALUES (?, ?, ?, ?, 1)')
          .bind(code.toUpperCase(), discount, plan, Date.now()).run();
        return json({ ok: true }, 201, request);
      }

      if (path === '/coupons/redeem' && method === 'POST') {
        const session = await getSession(request, db);
        if (!session) return err('Unauthorized', 401, request);
        const { code } = await request.json();
        const coupon = await db.prepare('SELECT * FROM coupons WHERE code = ? AND active = 1').bind(code.toUpperCase()).first();
        if (!coupon) return err('Invalid or expired coupon', 404, request);
        await db.prepare('UPDATE users SET membership = ? WHERE id = ?').bind(coupon.plan, session.user_id).run();
        await db.prepare('UPDATE coupons SET active = 0 WHERE code = ?').bind(code.toUpperCase()).run();
        return json({ ok: true, plan: coupon.plan }, 200, request);
      }

      return err('Not found', 404, request);

    } catch (e) {
      console.error(e);
      return err('Internal server error: ' + e.message, 500, request);
    }
  }
};

// ─── Password hashing using Web Crypto ───
async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  const hashArr = new Uint8Array(bits);
  const saltHex = Array.from(salt, b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(hashArr, b => b.toString(16).padStart(2, '0')).join('');
  return saltHex + ':' + hashHex;
}

async function verifyPassword(password, stored) {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
    const hashArr = new Uint8Array(bits);
    const computed = Array.from(hashArr, b => b.toString(16).padStart(2, '0')).join('');
    return computed === hashHex;
  } catch { return false; }
}
