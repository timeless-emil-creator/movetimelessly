import { json, randomHex, hashPassword, createSession } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  try {
    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid request.' }, 400);
    }

    const name = (body.name || '').trim();
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    if (!name) return json({ error: 'Enter your name.' }, 400);
    if (!email) return json({ error: 'Enter your email.' }, 400);
    if (password.length < 8) return json({ error: 'Password must be at least 8 characters.' }, 400);

    if (!env.DB) {
      return json({ error: 'DEBUG: env.DB binding is missing. Check Settings → Bindings.' }, 500);
    }

    const existing = await env.DB
      .prepare('SELECT id FROM users WHERE email = ?')
      .bind(email)
      .first();
    if (existing) {
      return json({ error: 'An account with that email already exists.' }, 400);
    }

    const id = crypto.randomUUID();
    const salt = randomHex(16);
    const passwordHash = await hashPassword(password, salt);
    const createdAt = new Date().toISOString();

    await env.DB
      .prepare(
        'INSERT INTO users (id, name, email, password_hash, password_salt, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      )
      .bind(id, name, email, passwordHash, salt, createdAt)
      .run();

    const token = await createSession(env, id);

    return json({ token, user: { id, name, email } });
  } catch (err) {
    // TEMPORARY: surface the real error message in the app instead of a
    // generic Cloudflare crash page, so we can see exactly what's failing.
    return json({ error: 'DEBUG: ' + (err && err.message ? err.message : String(err)) }, 500);
  }
}
