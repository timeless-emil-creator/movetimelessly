import { json, requireUser } from '../_lib/auth.js';

export async function onRequestGet({ request, env }) {
  const userId = await requireUser(request, env);
  if (!userId) return json({ error: 'Not authenticated.' }, 401);

  const row = await env.DB
    .prepare('SELECT data FROM user_data WHERE user_id = ?')
    .bind(userId)
    .first();

  if (!row) return json({ data: null });

  return json({ data: JSON.parse(row.data) });
}
