// Cloudflare Worker: handles every /api/* request (see run_worker_first in wrangler.jsonc).
// Everything else is served from ./public as static assets.
// Bindings needed: SITE (KV namespace), PHOTOS (R2 bucket).
// Secrets needed: ADMIN_PASSWORD, SESSION_SECRET.

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

    /* ---- private client photos (owner client or admin) ---- */
    if (p.startsWith('photo/') && m === 'GET') {
      const id = p.slice(6);
      if (!ID.test(id)) return J({ error: 'Not found' }, 404);
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
        return J({ list: (await clients(env)).map((c) => ({ ...pub(c), hasPw: !!c.hash })) });
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
            salt, hash,
          });
        }
        await env.SITE.put('clients', JSON.stringify(out));
        return J({ ok: true });
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
      return J({ client: pub(c) }, 200, { 'Set-Cookie': setCookie('cs', await token(env, 'client', c.cid, 86400), 86400) });
    }
    if (p === 'client/logout' && m === 'POST') return J({ ok: true }, 200, { 'Set-Cookie': setCookie('cs', '', 0) });
    if (p.startsWith('client/')) {
      const c = cid && (await clients(env)).find((x) => x.cid === cid);
      if (!c) return J({ error: 'Please sign in.' }, 401);
      if (p === 'client/me') return J({ client: pub(c) });
      if (p === 'client/feedback' && m === 'GET') {
        return J(JSON.parse((await env.SITE.get('fb:' + c.cid)) || '{"p":{}}'));
      }
      if (p === 'client/feedback' && m === 'PUT') {
        const b = await body(request);
        if (!b || typeof b.p !== 'object' || b.p === null) return J({ error: 'Invalid data.' }, 400);
        const ok = new Set((c.photos || []).map((x) => x.id)), out = {};
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
