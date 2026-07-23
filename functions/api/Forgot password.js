import { json, randomHex } from '../_lib/auth.js';

// Issues a reset token and, if RESEND_API_KEY is configured, emails a real
// reset link. Without that env var set, it falls back to logging the link
// so you can still test the flow manually. See README for setup.
export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid request.' }, 400);
  }

  const email = (body.email || '').trim().toLowerCase();
  const generic = { message: "If that email has an account, we've sent a reset link. Check your inbox." };
  if (!email) return json(generic);

  const user = await env.DB.prepare('SELECT id, name FROM users WHERE email = ?').bind(email).first();
  if (user) {
    const token = randomHex(20);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour
    await env.DB
      .prepare('INSERT INTO password_resets (token, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(token, user.id, expiresAt)
      .run();

    const origin = new URL(request.url).origin;
    const resetLink = `${origin}/?reset_token=${token}`;

    if (env.RESEND_API_KEY) {
      try {
        const res = await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.RESEND_API_KEY}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            from: env.FROM_EMAIL || 'Timeless Movements <onboarding@resend.dev>',
            to: email,
            subject: 'Reset your password',
            html: `<p>Hi ${user.name || 'there'},</p>
                   <p>Click the link below to reset your Timeless Movements password. This link expires in 1 hour.</p>
                   <p><a href="${resetLink}">${resetLink}</a></p>
                   <p>If you didn't request this, you can safely ignore this email.</p>`,
          }),
        });
        if (!res.ok) console.log('Resend API error:', res.status, await res.text());
      } catch (e) {
        console.log('Email send failed:', e.message);
      }
    } else {
      console.log('RESEND_API_KEY not set — reset link (not emailed):', resetLink);
    }
  }

  return json(generic);
}
