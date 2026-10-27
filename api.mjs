import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

// Set ADMIN_PASSWORD in Netlify (Site configuration > Environment variables) to change it.
const password = () => process.env.ADMIN_PASSWORD || 'chocolate all the time';
const secret = () => 'lf:' + password();
const HOURS8 = 8 * 60 * 60 * 1000;

const hmac = (body) => crypto.createHmac('sha256', secret()).update(body).digest('base64url');
const sign = (payload) => {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return body + '.' + hmac(body);
};
function verify(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const good = Buffer.from(hmac(body)), given = Buffer.from(sig);
  if (good.length !== given.length || !crypto.timingSafeEqual(good, given)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
const digest = (s) => crypto.createHash('sha256').update(String(s)).digest();
const json = (data, status = 200) => Response.json(data, { status });
const isAdmin = (req) => verify((req.headers.get('authorization') || '').replace(/^Bearer /, ''))?.role === 'admin';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export default async (req) => {
  const parts = new URL(req.url).pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  const store = getStore('lost-found');
  const body = req.method === 'POST' ? await req.json().catch(() => ({})) : {};

  // POST /api/login/admin
  if (req.method === 'POST' && parts[0] === 'login' && parts[1] === 'admin') {
    const pw = String(body.password || '');
    if (!pw) return json({ error: 'Enter the admin password.' }, 400);
    if (!crypto.timingSafeEqual(digest(pw), digest(password()))) {
      await sleep(800); // slows down password guessing
      return json({ error: 'Wrong password.' }, 401);
    }
    return json({ ok: true, token: sign({ role: 'admin', exp: Date.now() + HOURS8 }) });
  }

  // POST /api/login/student  { name, photo: "data:image/jpeg;base64,..." }
  if (req.method === 'POST' && parts[0] === 'login' && parts[1] === 'student') {
    const name = String(body.name || '').trim();
    const photo = String(body.photo || '');
    if (name.length < 2 || name.length > 80) return json({ error: 'Enter your full name.' }, 400);
    if (!photo.startsWith('data:image/jpeg;base64,') || photo.length > 600000) {
      return json({ error: 'Upload a clear photo of your school ID.' }, 400);
    }
    const id = crypto.randomUUID();
    await store.set('photo/' + id, photo);
    await store.setJSON('meta/' + id, { id, name, at: new Date().toISOString() });
    return json({ ok: true });
  }

  // Everything below is moderator-only.
  if (parts[0] === 'students') {
    if (!isAdmin(req)) return json({ error: 'Log in as a moderator.' }, 401);
    const id = parts[1];
    if (id && !/^[0-9a-f-]{36}$/.test(id)) return json({ error: 'Not found.' }, 404);

    if (req.method === 'GET' && !id) {
      const { blobs } = await store.list({ prefix: 'meta/' });
      const all = await Promise.all(blobs.map((b) => store.get(b.key, { type: 'json' })));
      return json(all.filter(Boolean).sort((a, b) => b.at.localeCompare(a.at)));
    }
    if (req.method === 'GET' && parts[2] === 'photo') {
      const photo = await store.get('photo/' + id);
      return photo ? json({ photo }) : json({ error: 'Not found.' }, 404);
    }
    if (req.method === 'DELETE' && id) {
      await store.delete('meta/' + id);
      await store.delete('photo/' + id);
      return json({ ok: true });
    }
  }
  return json({ error: 'Not found.' }, 404);
};

export const config = { path: '/api/*' };
