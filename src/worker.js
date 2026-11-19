// Cloudflare Worker: handles every /api/* request (see run_worker_first in wrangler.jsonc).
// Everything else is served from ./public as static assets.
// Bindings needed: SITE (KV namespace), PHOTOS (R2 bucket).
// Secrets needed: ADMIN_PASSWORD, SESSION_SECRET.
// Optional secret: GOOGLE_SERVICE_ACCOUNT (JSON key of a Google service account) to serve client photos from Google Drive folders.

const enc = new TextEncoder();
const TYPES = { 'image/jpeg': 1, 'image/png': 1, 'image/webp': 1, 'image/gif': 1, 'image/avif': 1 };
const MAX = 25 * 1024 * 1024;
const J = (o, s = 200, h = {}) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...h } });
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const rid = () => hex(crypto.getRandomValues(new Uint8Array(16)));
const ID = /^[a-f0-9]{32}$/;

async function hmac(secret, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
async function pbk(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
function same(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const cookie = (req, n) => {
  const m = (req.headers.get('Cookie') || '').split(/;\s*/).find((x) => x.startsWith(n + '='));
  return m ? m.slice(n.length + 1) : '';
};
const setCookie = (n, v, age) => `${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
async function token(env, kind, sub, ttl) {
  const body = `${kind}|${sub}|${Math.floor(Date.now() / 1000) + ttl}`;
  return btoa(body) + '.' + (await hmac(env.SESSION_SECRET, body));
}
async function check(env, kind, t) {
  if (!t || !t.includes('.')) return null;
  const [b, sig] = t.split('.');
  let body;
  try { body = atob(b); } catch { return null; }
  const [k, sub, exp] = body.split('|');
  if (k !== kind || +exp < Date.now() / 1000) return null;
  return same(sig, await hmac(env.SESSION_SECRET, body)) ? sub : null;
}
const rlKey = (req, sc) => 'rl:' + sc + ':' + (req.headers.get('CF-Connecting-IP') || 'x');
const blocked = async (env, req, sc) => +((await env.SITE.get(rlKey(req, sc))) || 0) >= 8;
const failed = async (env, req, sc) => {
  const k = rlKey(req, sc);
  await env.SITE.put(k, String(+((await env.SITE.get(k)) || 0) + 1), { expirationTtl: 600 });
};
const clients = async (env) => JSON.parse((await env.SITE.get('clients')) || '[]');
const pub = (c) => ({ cid: c.cid, name: c.name, note: c.note || '', photos: c.photos || [] });
const body = async (req) => { try { return await req.json(); } catch { return null; } };

/* ---- Google Drive (client photo folders) ----
   Each client can have a Drive folder. The folder is shared (Viewer) with a Google service account, and this
   Worker reads it with that account's key (secret GOOGLE_SERVICE_ACCOUNT). The folder itself stays private:
   photos are streamed through /api/photo/<fileId> after checking they sit in the signed-in client's folder. */
const G = 'https://www.googleapis.com/drive/v3';
const DRIVE_ID = /^[A-Za-z0-9_-]{10,80}$/;
const DRIVE_IMG = { 'image/jpeg': 1, 'image/png': 1, 'image/webp': 1, 'image/gif': 1 };
const DRIVE_MAX = 500;
let GTOK = { t: '', exp: 0 };
const dcache = new Map(); // short-lived, per-isolate
const dget = (k) => { const e = dcache.get(k); return e && e.exp > Date.now() ? e.v : undefined; };
const dset = (k, v, ms) => { if (dcache.size > 500) dcache.clear(); dcache.set(k, { v, exp: Date.now() + ms }); };
const b64u = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
function saKey(env) {
  let o = null;
  try { o = JSON.parse(env.GOOGLE_SERVICE_ACCOUNT || ''); } catch { /* not JSON */ }
  if (!o || !o.client_email || !o.private_key) return null;
  return { email: String(o.client_email), key: String(o.private_key).replace(/\\n/g, '\n') };
}
function driveFolderId(v) {
  const s = String(v || '').trim();
  if (!s) return '';
  if (DRIVE_ID.test(s)) return s;
  const m = s.match(/\/folders\/([A-Za-z0-9_-]{10,80})/) || s.match(/[?&]id=([A-Za-z0-9_-]{10,80})/);
  return m ? m[1] : null;
}
async function driveToken(env) {
  const sa = saKey(env);
  if (!sa) throw new Error('Google Drive is not connected yet. Add the GOOGLE_SERVICE_ACCOUNT secret (see the README).');
  if (GTOK.t && GTOK.exp > Date.now() + 60000) return GTOK.t;
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(enc.encode(JSON.stringify({ alg: 'RS256', typ: 'JWT' })));
  const claim = b64u(enc.encode(JSON.stringify({ iss: sa.email, scope: 'https://www.googleapis.com/auth/drive.readonly', aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 3600 })));
  let sig;
  try {
    const der = Uint8Array.from(atob(sa.key.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('pkcs8', der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, enc.encode(head + '.' + claim));
  } catch { throw new Error('The key in the GOOGLE_SERVICE_ACCOUNT secret could not be read. Paste the whole JSON file.'); }
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'grant_type=' + encodeURIComponent('urn:ietf:params:oauth:grant-type:jwt-bearer') + '&assertion=' + head + '.' + claim + '.' + b64u(sig),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error('Google sign-in failed (' + (j.error_description || j.error || r.status) + '). Check the GOOGLE_SERVICE_ACCOUNT secret.');
  GTOK = { t: j.access_token, exp: Date.now() + (j.expires_in || 3600) * 1000 };
  return GTOK.t;
}
const gfetch = async (env, url) => fetch(url, { headers: { Authorization: 'Bearer ' + (await driveToken(env)) } });
async function gerr(env, r) {
  const j = await r.json().catch(() => ({})), sa = saKey(env), who = sa ? sa.email : 'the service account';
  if (r.status === 404) return new Error('Folder not found. Check the link, and share the folder with ' + who + ' (Viewer).');
  if (r.status === 401 || r.status === 403) return new Error('Google Drive refused access' + (j.error && j.error.message ? ' (' + j.error.message + ')' : '') + '. Check that the Google Drive API is enabled and the folder is shared with ' + who + '.');
  return new Error('Google Drive error ' + r.status + '.');
}
async function driveList(env, folder) {
  const out = [];
  const q = "'" + folder + "' in parents and trashed = false and (mimeType = 'image/jpeg' or mimeType = 'image/png' or mimeType = 'image/webp' or mimeType = 'image/gif')";
  let page = '';
  for (let i = 0; i < 3; i++) {
    const u = new URLSearchParams({ q, fields: 'nextPageToken,files(id,name)', orderBy: 'name_natural', pageSize: '200', supportsAllDrives: 'true', includeItemsFromAllDrives: 'true' });
    if (page) u.set('pageToken', page);
    const r = await gfetch(env, G + '/files?' + u);
    if (!r.ok) throw await gerr(env, r);
    const j = await r.json();
    for (const f of j.files || []) if (DRIVE_ID.test(f.id)) out.push({ id: f.id, n: String(f.name || '').slice(0, 120) });
    page = j.nextPageToken || '';
    if (!page || out.length >= DRIVE_MAX) break;
  }
  return out.slice(0, DRIVE_MAX);
}
async function drivePhotos(env, c) {
  const k = 'l:' + c.drive, hit = dget(k);
  if (hit) return hit;
  const l = await driveList(env, c.drive);
  dset(k, l, 120000);
  return l;
}
async function driveMeta(env, id) {
  const k = 'm:' + id, hit = dget(k);
  if (hit !== undefined) return hit;
  const r = await gfetch(env, G + '/files/' + id + '?supportsAllDrives=true&fields=' + encodeURIComponent('id,mimeType,parents,thumbnailLink,trashed'));
  if (!r.ok && r.status !== 404 && r.status !== 403) throw await gerr(env, r);
  const v = r.ok ? await r.json() : null;
  dset(k, v, 300000);
  return v;
}
async function drivePhoto(env, id, folders, size) {
  const meta = await driveMeta(env, id);
  if (!meta || meta.trashed || !DRIVE_IMG[meta.mimeType] || !(meta.parents || []).some((f) => folders.includes(f))) return J({ error: 'Not allowed' }, 403);
  let r = null, type = meta.mimeType;
  if (size && meta.thumbnailLink) {
    try { // smaller preview for the gallery grid; only ever send the token to Google's image host
      const t = new URL(meta.thumbnailLink);
      if (t.protocol === 'https:' && /\.googleusercontent\.com$/.test(t.hostname)) {
        const tr = await fetch(meta.thumbnailLink.replace(/=s\d+[^=]*$/, '') + '=s' + Math.max(100, Math.min(1600, size)), { headers: { Authorization: 'Bearer ' + (await driveToken(env)) } });
        if (tr.ok) { r = tr; type = tr.headers.get('Content-Type') || 'image/jpeg'; if (!/^image\//.test(type)) type = 'image/jpeg'; }
      }
    } catch { /* fall back to the original file */ }
  }
  if (!r) {
    r = await gfetch(env, G + '/files/' + id + '?alt=media&supportsAllDrives=true');
    if (!r.ok) return J({ error: 'Could not load this photo.' }, 502);
  }
  return new Response(r.body, { headers: { 'Content-Type': type, 'Cache-Control': 'private, max-age=3600', 'X-Content-Type-Options': 'nosniff' } });
}
// What a signed-in client sees: uploaded photos plus the photos in their Drive folder.
async function cview(env, c) {
  const o = pub(c);
  if (c.drive) {
    try { o.photos = [...o.photos, ...(await drivePhotos(env, c))]; } catch { o.driveError = 'Photos from Google Drive could not be loaded right now. Please try again later.'; }
  }
  return o;
}

/* ---- bookings ----
   One KV key per booking: "bk:" + (9999999999999 - timestamp, 13 digits) + 8 random hex chars.
   The inverted timestamp makes KV's ascending key order newest-first. */
const BK_ID = /^\d{13}[a-f0-9]{8}$/;
const BK_STATUS = { new: 1, confirmed: 1, done: 1, cancelled: 1 };
const BK_LIMIT = 5; // requests per IP per hour
const clip = (v, n) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, n);
function okDate(s) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return false;
  const d = new Date(s + 'T00:00:00Z');
  if (isNaN(d) || d.toISOString().slice(0, 10) !== s) return false;
  const now = Date.now();
  return d.getTime() >= now - 2 * 86400000 && d.getTime() <= now + 3 * 365 * 86400000;
}

async function handle(request, env) {
  try {
    if (!env.SITE || !env.PHOTOS || !env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
      return J({ error: 'Server is not set up yet. Add the SITE and PHOTOS bindings and the ADMIN_PASSWORD and SESSION_SECRET secrets.' }, 500);
    }
    const url = new URL(request.url);
    const p = url.pathname.replace(/^\/api\/?/, '');
    const m = request.method;
    const admin = await check(env, 'admin', cookie(request, 'as'));
    const cid = await check(env, 'client', cookie(request, 'cs'));

    /* ---- public ---- */
    if (p === 'content' && m === 'GET') return J(JSON.parse((await env.SITE.get('content')) || '{}'));
    if (p.startsWith('img/') && m === 'GET') {
      const id = p.slice(4);
      if (!ID.test(id)) return J({ error: 'Not found' }, 404);
      const o = await env.PHOTOS.get('p/' + id);
      if (!o) return J({ error: 'Not found' }, 404);
      return new Response(o.body, { headers: { 'Content-Type': o.httpMetadata?.contentType || 'image/jpeg', 'Cache-Control': 'public, max-age=31536000, immutable', 'X-Content-Type-Options': 'nosniff' } });
    }

    /* ---- public booking request ---- */
    if (p === 'booking' && m === 'POST') {
      const rk = 'rl:bk:' + (request.headers.get('CF-Connecting-IP') || 'x');
      if (+((await env.SITE.get(rk)) || 0) >= BK_LIMIT) {
        return J({ error: 'Too many requests from this connection. Please try again in an hour, or message us directly.' }, 429);
      }
      const raw = await request.text();
      if (raw.length > 20000) return J({ error: 'Request is too large.' }, 413);
      let b;
      try { b = JSON.parse(raw); } catch { b = null; }
      if (!b || typeof b !== 'object') return J({ error: 'Invalid data.' }, 400);
      if (clip(b.website, 200)) return J({ ok: true, ref: 'OK-000000' }); // honeypot: pretend success, store nothing
      const r = {
        name: clip(b.name, 100), email: clip(b.email, 120), phone: clip(b.phone, 30),
        service: clip(b.service, 60), date: clip(b.date, 10), time: clip(b.time, 40),
        location: clip(b.location, 200), photographer: clip(b.photographer, 100), message: clip(b.message, 2000),
      };
      if (r.name.length < 2) return J({ error: 'Please enter your name.' }, 400);
      if (!r.email && !r.phone) return J({ error: 'Please add a WhatsApp number or an email so we can reach you.' }, 400);
      if (r.email && !/^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/.test(r.email)) return J({ error: 'That email address does not look right.' }, 400);
      if (r.phone && !/^[+\d][\d\s().-]{5,}$/.test(r.phone)) return J({ error: 'That phone number does not look right.' }, 400);
      if (r.phone && r.phone.replace(/\D/g, '').length > 16) return J({ error: 'That phone number does not look right.' }, 400);
      if (!r.service) return J({ error: 'Please choose the type of shoot.' }, 400);
      if (!okDate(r.date)) return J({ error: 'Please pick a valid date that is not in the past.' }, 400);
      const id = String(9999999999999 - Date.now()).padStart(13, '0') + rid().slice(0, 8);
      await env.SITE.put('bk:' + id, JSON.stringify({ ...r, status: 'new', note: '', at: new Date().toISOString() }));
      await env.SITE.put(rk, String(+((await env.SITE.get(rk)) || 0) + 1), { expirationTtl: 3600 });
      return J({ ok: true, ref: 'OK-' + id.slice(-6).toUpperCase() });
    }

    /* ---- private client photos (owner client or admin) ---- */
    if (p.startsWith('photo/') && m === 'GET') {
      const id = p.slice(6);
      const drv = !ID.test(id) && DRIVE_ID.test(id);
      if (!ID.test(id) && !drv) return J({ error: 'Not found' }, 404);
      if (drv) { // a file from a client's Google Drive folder
        const all = await clients(env);
        const me = !admin && cid && all.find((x) => x.cid === cid);
        const folders = admin ? all.map((x) => x.drive).filter(Boolean) : me && me.drive ? [me.drive] : [];
        if (!folders.length) return J({ error: 'Not allowed' }, 403);
        try { return await drivePhoto(env, id, folders, parseInt(url.searchParams.get('s'), 10) || 0); } catch { return J({ error: 'Could not load this photo.' }, 502); }
      }
      if (!admin) {
        const c = cid && (await clients(env)).find((x) => x.cid === cid);
        if (!c || !(c.photos || []).some((x) => x.id === id)) return J({ error: 'Not allowed' }, 403);
      }
      const o = await env.PHOTOS.get('c/' + id);
      if (!o) return J({ error: 'Not found' }, 404);
      return new Response(o.body, { headers: { 'Content-Type': o.httpMetadata?.contentType || 'image/jpeg', 'Cache-Control': 'private, max-age=3600', 'X-Content-Type-Options': 'nosniff' } });
    }

    /* ---- admin ---- */
    if (p === 'admin/login' && m === 'POST') {
      if (await blocked(env, request, 'a')) return J({ error: 'Too many attempts. Try again in a few minutes.' }, 429);
      const b = await body(request);
      const ok = b && typeof b.password === 'string' && same(await hmac(env.SESSION_SECRET, b.password), await hmac(env.SESSION_SECRET, env.ADMIN_PASSWORD));
      if (!ok) { await failed(env, request, 'a'); return J({ error: 'Wrong password.' }, 401); }
      return J({ ok: true }, 200, { 'Set-Cookie': setCookie('as', await token(env, 'admin', 'owner', 43200), 43200) });
    }
    if (p === 'admin/logout' && m === 'POST') return J({ ok: true }, 200, { 'Set-Cookie': setCookie('as', '', 0) });
    if (p.startsWith('admin/')) {
      if (!admin) return J({ error: 'Please sign in.' }, 401);
      if (p === 'admin/me') return J({ ok: true });
      if (p === 'admin/content' && m === 'PUT') {
        const t = await request.text();
        if (t.length > 200000) return J({ error: 'Content is too large.' }, 413);
        try { JSON.parse(t); } catch { return J({ error: 'Invalid data.' }, 400); }
        await env.SITE.put('content', t);
        return J({ ok: true });
      }
      if (p === 'admin/clients' && m === 'GET') {
        return J({ list: (await clients(env)).map((c) => ({ ...pub(c), hasPw: !!c.hash, drive: c.drive || '' })), driveEmail: (saKey(env) || {}).email || '' });
      }
      if (p === 'admin/clients' && m === 'PUT') {
        const b = await body(request);
        if (!b || !Array.isArray(b.list) || b.list.length > 200) return J({ error: 'Invalid list.' }, 400);
        const old = await clients(env), seen = new Set(), out = [];
        for (const c of b.list) {
          const id = String(c.cid || '').trim().toLowerCase();
          if (!/^[a-z0-9_-]{2,40}$/.test(id)) return J({ error: 'Client IDs need 2 to 40 letters, numbers, - or _ (no spaces).' }, 400);
          if (seen.has(id)) return J({ error: 'Duplicate client ID: ' + id }, 400);
          seen.add(id);
          const drive = driveFolderId(c.drive);
          if (drive === null) return J({ error: 'Could not find a Google Drive folder ID in "' + String(c.drive).slice(0, 60) + '". Paste the folder link from Drive (Share, then Copy link).' }, 400);
          const o = old.find((x) => x.cid === id) || {};
          let salt = o.salt, hash = o.hash;
          if (c.pw) {
            if (String(c.pw).length < 6) return J({ error: 'Passwords need at least 6 characters.' }, 400);
            salt = rid();
            hash = await pbk(String(c.pw), salt);
          }
          out.push({
            cid: id, name: String(c.name || '').slice(0, 100), note: String(c.note || '').slice(0, 2000),
            photos: (c.photos || []).map((x) => x.id).filter((i) => ID.test(i)).slice(0, 500).map((i) => ({ id: i })),
            drive, salt, hash,
          });
        }
        await env.SITE.put('clients', JSON.stringify(out));
        return J({ ok: true });
      }
      if (p === 'admin/drive' && m === 'GET') {
        const f = driveFolderId(url.searchParams.get('folder'));
        if (!f) return J({ error: f === null ? 'That does not look like a Google Drive folder link.' : 'Paste a Drive folder link first.' }, 400);
        try {
          const l = await driveList(env, f);
          return J({ ok: true, count: l.length, names: l.slice(0, 5).map((x) => x.n) });
        } catch (e) { return J({ error: e.message }, 400); }
      }
      if (p === 'admin/upload' && m === 'POST') {
        const type = (request.headers.get('Content-Type') || '').split(';')[0];
        const len = +(request.headers.get('Content-Length') || 0);
        if (!TYPES[type]) return J({ error: 'Please upload a JPG, PNG, WebP, GIF or AVIF image.' }, 415);
        if (!len || len > MAX) return J({ error: 'Images must be under 25 MB.' }, 413);
        const kind = url.searchParams.get('kind') === 'client' ? 'c/' : 'p/';
        const id = rid();
        await env.PHOTOS.put(kind + id, request.body, { httpMetadata: { contentType: type } });
        return J({ id });
      }
      if (p === 'admin/feedback' && m === 'GET') {
        const out = {};
        const l = await env.SITE.list({ prefix: 'fb:', limit: 200 });
        for (const k of l.keys) out[k.name.slice(3)] = JSON.parse((await env.SITE.get(k.name)) || '{}');
        return J(out);
      }
      if (p === 'admin/bookings' && m === 'GET') {
        // 1 list call + up to 40 reads per page, which stays under the Workers Free subrequest limit.
        const l = await env.SITE.list({ prefix: 'bk:', limit: 40, cursor: url.searchParams.get('cursor') || undefined });
        const vals = await Promise.all(l.keys.map((k) => env.SITE.get(k.name)));
        const list = [];
        vals.forEach((v, i) => {
          if (!v) return;
          try { list.push({ id: l.keys[i].name.slice(3), ...JSON.parse(v) }); } catch { /* skip unreadable record */ }
        });
        return J({ list, cursor: l.list_complete ? null : l.cursor });
      }
      const bm = p.match(/^admin\/bookings\/([^/]+)$/);
      if (bm && BK_ID.test(bm[1])) {
        const key = 'bk:' + bm[1];
        if (m === 'DELETE') { await env.SITE.delete(key); return J({ ok: true }); }
        if (m === 'PUT') {
          const cur = await env.SITE.get(key);
          if (!cur) return J({ error: 'Booking not found.' }, 404);
          const b = await body(request);
          if (!b || typeof b !== 'object') return J({ error: 'Invalid data.' }, 400);
          const rec = JSON.parse(cur);
          if (b.status !== undefined) {
            if (!BK_STATUS[b.status]) return J({ error: 'Invalid status.' }, 400);
            rec.status = b.status;
          }
          if (b.note !== undefined) rec.note = clip(b.note, 2000);
          await env.SITE.put(key, JSON.stringify(rec));
          return J({ ok: true });
        }
      }
      return J({ error: 'Not found' }, 404);
    }

    /* ---- client ---- */
    if (p === 'client/login' && m === 'POST') {
      if (await blocked(env, request, 'c')) return J({ error: 'Too many attempts. Try again in a few minutes.' }, 429);
      const b = await body(request);
      const id = String((b && b.cid) || '').trim().toLowerCase();
      const c = (await clients(env)).find((x) => x.cid === id);
      const salt = (c && c.salt) || 'none';
      const h = await pbk(String((b && b.password) || ''), salt);
      if (!c || !c.hash || !same(h, c.hash)) { await failed(env, request, 'c'); return J({ error: 'ID or password is not correct.' }, 401); }
      return J({ client: await cview(env, c) }, 200, { 'Set-Cookie': setCookie('cs', await token(env, 'client', c.cid, 86400), 86400) });
    }
    if (p === 'client/logout' && m === 'POST') return J({ ok: true }, 200, { 'Set-Cookie': setCookie('cs', '', 0) });
    if (p.startsWith('client/')) {
      const c = cid && (await clients(env)).find((x) => x.cid === cid);
      if (!c) return J({ error: 'Please sign in.' }, 401);
      if (p === 'client/me') return J({ client: await cview(env, c) });
      if (p === 'client/feedback' && m === 'GET') {
        return J(JSON.parse((await env.SITE.get('fb:' + c.cid)) || '{"p":{}}'));
      }
      if (p === 'client/feedback' && m === 'PUT') {
        const b = await body(request);
        if (!b || typeof b.p !== 'object' || b.p === null) return J({ error: 'Invalid data.' }, 400);
        const ok = new Set((c.photos || []).map((x) => x.id)), out = {};
        if (c.drive) { try { (await drivePhotos(env, c)).forEach((x) => ok.add(x.id)); } catch { /* Drive unavailable: only uploaded photos can be rated */ } }
        for (const [k, v] of Object.entries(b.p)) {
          if (!ok.has(k) || !v) continue;
          const r = Math.max(0, Math.min(5, parseInt(v.r, 10) || 0));
          const f = v.f === 'pick' || v.f === 'reject' ? v.f : '';
          const n = String(v.n || '').slice(0, 1000);
          if (r || f || n) out[k] = { r, f, n };
        }
        await env.SITE.put('fb:' + c.cid, JSON.stringify({ p: out, name: c.name, at: new Date().toISOString() }));
        return J({ ok: true });
      }
      return J({ error: 'Not found' }, 404);
    }
    return J({ error: 'Not found' }, 404);
  } catch (e) {
    return J({ error: 'Server error: ' + (e && e.message ? e.message : 'unknown') }, 500);
  }
}

export default {
  fetch(request, env) {
    return handle(request, env);
  },
};
