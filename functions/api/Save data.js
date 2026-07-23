import { json, requireUser } from '../_lib/auth.js';

// Note: the frontend sends the raw state object as the request body
// (not wrapped in { data: ... }) — see saveState() in index.html.
export async function onRequestPost({ request, env }) {
  const userId = await requireUser(request, env);
  if (!userId) return json({ error: 'Not authenticated.' }, 401);

  const raw = await request.text();
  try {
    JSON.parse(raw); // validate before storing
  } catch {
    return json({ error: 'Invalid data.' }, 400);
  }

  const existing = await env.DB
    .prepare('SELECT user_id FROM user_data WHERE user_id = ?')
    .bind(userId)
    .first();

  const now = new Date().toISOString();
  if (existing) {
    await env.DB
      .prepare('UPDATE user_data SET data = ?, updated_at = ? WHERE user_id = ?')
      .bind(raw, now, userId)
      .run();
  } else {
    await env.DB
      .prepare('INSERT INTO user_data (user_id, data, updated_at) VALUES (?, ?, ?)')
      .bind(userId, raw, now)
      .run();
  }

  return json({ ok: true });
}
