import { json, verifyPassword, createSession } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid request.' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  if (!email || !password) {
    return json({ error: 'Enter your email and password.' }, 400);
  }

  const user = await env.DB
    .prepare('SELECT id, name, email, password_hash, password_salt FROM users WHERE email = ?')
    .bind(email)
    .first();

  const genericError = "That email and password don't match our records.";
  if (!user) return json({ error: genericError }, 401);

  const ok = await verifyPassword(password, user.password_salt, user.password_hash);
  if (!ok) return json({ error: genericError }, 401);

  const token = await createSession(env, user.id);

  return json({ token, user: { id: user.id, name: user.name, email: user.email } });
}
