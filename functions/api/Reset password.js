import { json, randomHex, hashPassword } from '../_lib/auth.js';

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid request.' }, 400);
  }

  const token = body.token || '';
  const newPassword = body.newPassword || '';
  if (newPassword.length < 8) {
    return json({ error: 'Password must be at least 8 characters.' }, 400);
  }

  const reset = await env.DB
    .prepare('SELECT user_id, expires_at FROM password_resets WHERE token = ?')
    .bind(token)
    .first();

  if (!reset || new Date(reset.expires_at) < new Date()) {
    return json({ error: 'This reset link is invalid or has expired.' }, 400);
  }

  const salt = randomHex(16);
  const passwordHash = await hashPassword(newPassword, salt);

  await env.DB
    .prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?')
    .bind(passwordHash, salt, reset.user_id)
    .run();

  await env.DB.prepare('DELETE FROM password_resets WHERE token = ?').bind(token).run();

  return json({ ok: true });
}
