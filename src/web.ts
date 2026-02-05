/**
 * Web UI routes for human administration
 */

import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { Env, Client, Agent, Secret, AuditEntry } from './types';
import * as db from './db';
import { encrypt, hashPassword, verifyPassword } from './crypto';
import { html } from 'hono/html';

export const webRoutes = new Hono<{ Bindings: Env }>();

// ─── Helpers ───────────────────────────────────────────────────────────────────

async function getSessionClient(c: any): Promise<string | null> {
  const sessionId = getCookie(c, 'session');
  if (!sessionId) return null;
  
  const session = await db.getSession(c.env.DB, sessionId);
  return session?.client_id ?? null;
}

function getMasterKey(env: Env): string {
  return env.MASTER_KEY || 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
}

function redirect(path: string) {
  return new Response(null, {
    status: 302,
    headers: { Location: path },
  });
}

// ─── Templates ─────────────────────────────────────────────────────────────────

const baseStyles = `
  :root {
    --bg: #0a0a0a; --bg-secondary: #141414; --bg-tertiary: #1f1f1f;
    --text: #e5e5e5; --text-muted: #737373;
    --accent: #22c55e; --accent-hover: #16a34a;
    --danger: #ef4444; --border: #262626;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; min-height: 100vh; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
  nav { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1rem; }
  nav .container { display: flex; justify-content: space-between; align-items: center; }
  nav .logo { font-weight: bold; font-size: 1.25rem; color: var(--text); }
  nav .logo span { color: var(--accent); }
  nav ul { display: flex; list-style: none; gap: 1.5rem; }
  nav a { color: var(--text-muted); }
  nav a:hover, nav a.active { color: var(--text); text-decoration: none; }
  main { padding: 2rem 0; }
  h1, h2, h3 { margin-bottom: 1rem; }
  .card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.5rem; text-align: center; }
  .stat-value { font-size: 2.5rem; font-weight: bold; color: var(--accent); }
  .stat-label { color: var(--text-muted); font-size: 0.875rem; text-transform: uppercase; }
  .form-group { margin-bottom: 1rem; }
  label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
  input, select { width: 100%; padding: 0.75rem; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 0.375rem; color: var(--text); font-size: 1rem; }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.75rem 1.5rem; border: none; border-radius: 0.375rem; font-size: 1rem; font-weight: 500; cursor: pointer; }
  .btn-primary { background: var(--accent); color: #000; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
  .btn-sm { padding: 0.5rem 1rem; font-size: 0.875rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--text-muted); font-weight: 500; font-size: 0.875rem; text-transform: uppercase; }
  .alert { padding: 1rem; border-radius: 0.375rem; margin-bottom: 1rem; }
  .alert-error { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); color: var(--danger); }
  .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; }
  .badge-success { background: rgba(34, 197, 94, 0.2); color: var(--accent); }
  .badge-muted { background: var(--bg-tertiary); color: var(--text-muted); }
  .token { font-family: monospace; font-size: 0.875rem; background: var(--bg-tertiary); padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
  .empty { text-align: center; padding: 3rem; color: var(--text-muted); }
  .auth-container { max-width: 400px; margin: 4rem auto; padding: 0 1rem; }
  .auth-card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 2rem; }
  .text-muted { color: var(--text-muted); }
  .text-center { text-align: center; }
  .mt-2 { margin-top: 1rem; }
  .mb-2 { margin-bottom: 1rem; }
  .flex { display: flex; }
  .justify-between { justify-content: space-between; }
  .items-center { align-items: center; }
  .gap-2 { gap: 0.5rem; }
`;

function layout(title: string, content: string, nav?: string) {
  return html`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - SEKS Broker</title>
  <style>${baseStyles}</style>
</head>
<body>
  ${nav ? html`<nav><div class="container">${nav}</div></nav>` : ''}
  ${content}
</body>
</html>`;
}

function navBar(active: string) {
  return html`
    <div class="logo"><span>SEKS</span> Broker</div>
    <ul>
      <li><a href="/dashboard" class="${active === 'dashboard' ? 'active' : ''}">Dashboard</a></li>
      <li><a href="/secrets" class="${active === 'secrets' ? 'active' : ''}">Secrets</a></li>
      <li><a href="/agents" class="${active === 'agents' ? 'active' : ''}">Agents</a></li>
      <li><a href="/activity" class="${active === 'activity' ? 'active' : ''}">Activity</a></li>
    </ul>
    <form method="POST" action="/logout" style="margin: 0;">
      <button type="submit" class="btn btn-ghost btn-sm">Logout</button>
    </form>
  `;
}

// ─── Routes ────────────────────────────────────────────────────────────────────

// Landing page
webRoutes.get('/', (c) => {
  const content = html`
    <div class="auth-container" style="max-width: 600px; margin-top: 6rem;">
      <div class="text-center mb-2">
        <h1 style="font-size: 3rem; margin-bottom: 0.5rem;">
          <span style="color: var(--accent);">SEKS</span> Broker
        </h1>
        <p class="text-muted" style="font-size: 1.25rem;">
          Cloud-native secret management for AI agents
        </p>
      </div>
      <div class="card" style="margin-top: 3rem;">
        <h2 class="text-center">Bring Your Own Keys</h2>
        <p class="text-muted text-center" style="margin-bottom: 1.5rem;">
          Everything just works. Your agents, your keys, zero setup friction.
        </p>
        <div class="text-center">
          <a href="/login" class="btn btn-primary" style="font-size: 1.125rem; padding: 1rem 2rem;">
            Get Started →
          </a>
        </div>
      </div>
    </div>
  `;
  return c.html(layout('Welcome', content));
});

// Login page
webRoutes.get('/login', (c) => {
  const content = html`
    <div class="auth-container">
      <div class="auth-card">
        <h1 class="text-center"><span style="color: var(--accent);">SEKS</span> Broker</h1>
        <form method="POST" action="/login">
          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required placeholder="you@example.com">
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required placeholder="••••••••">
          </div>
          <button type="submit" class="btn btn-primary" style="width: 100%;">Sign In</button>
        </form>
        <p class="text-muted text-center mt-2" style="font-size: 0.875rem;">
          New here? Just enter your email and password to create an account.
        </p>
      </div>
    </div>
  `;
  return c.html(layout('Login', content));
});

// Login submit
webRoutes.post('/login', async (c) => {
  const body = await c.req.parseBody();
  const email = body.email as string;
  const password = body.password as string;
  
  let client = await db.getClientByEmail(c.env.DB, email);
  
  if (!client) {
    // Auto-register
    const hash = await hashPassword(password);
    client = await db.createClient(c.env.DB, email, hash);
  } else {
    // Verify password
    const valid = await verifyPassword(password, client.password_hash);
    if (!valid) {
      const content = html`
        <div class="auth-container">
          <div class="auth-card">
            <h1 class="text-center"><span style="color: var(--accent);">SEKS</span> Broker</h1>
            <div class="alert alert-error">Invalid email or password</div>
            <form method="POST" action="/login">
              <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required value="${email}">
              </div>
              <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
              </div>
              <button type="submit" class="btn btn-primary" style="width: 100%;">Sign In</button>
            </form>
          </div>
        </div>
      `;
      return c.html(layout('Login', content));
    }
  }
  
  const session = await db.createSession(c.env.DB, client.id);
  setCookie(c, 'session', session.id, { path: '/', httpOnly: true, sameSite: 'Lax' });
  return redirect('/dashboard');
});

// Logout
webRoutes.post('/logout', async (c) => {
  const sessionId = getCookie(c, 'session');
  if (sessionId) {
    await db.deleteSession(c.env.DB, sessionId);
  }
  deleteCookie(c, 'session');
  return redirect('/login');
});

// Dashboard
webRoutes.get('/dashboard', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const client = await db.getClientById(c.env.DB, clientId);
  const secrets = await db.listSecrets(c.env.DB, clientId);
  const agents = await db.listAgents(c.env.DB, clientId);
  const activity = await db.listAudit(c.env.DB, clientId, 5);
  
  const content = html`
    <main>
      <div class="container">
        <h1>Welcome${client?.name ? `, ${client.name}` : ''}</h1>
        <div class="stats">
          <div class="stat">
            <div class="stat-value">${secrets.length}</div>
            <div class="stat-label">Secrets</div>
          </div>
          <div class="stat">
            <div class="stat-value">${agents.length}</div>
            <div class="stat-label">Agents</div>
          </div>
        </div>
        <div class="card">
          <h2>Quick Start</h2>
          <ol style="padding-left: 1.5rem; color: var(--text-muted);">
            <li style="margin-bottom: 0.5rem;"><strong style="color: var(--text);">Add your API keys</strong> — Go to <a href="/secrets">Secrets</a></li>
            <li style="margin-bottom: 0.5rem;"><strong style="color: var(--text);">Create an agent</strong> — Go to <a href="/agents">Agents</a></li>
            <li><strong style="color: var(--text);">Use the API</strong> — Your agent can now access secrets</li>
          </ol>
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Dashboard', content, navBar('dashboard')));
});

// Secrets list
webRoutes.get('/secrets', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const secrets = await db.listSecrets(c.env.DB, clientId);
  
  const rows = secrets.map(s => html`
    <tr>
      <td><code class="token">${s.name}</code></td>
      <td>${s.provider}</td>
      <td class="text-muted">${s.created_at.split('T')[0]}</td>
      <td>
        <form method="POST" action="/secrets/${s.id}/delete" onsubmit="return confirm('Delete this secret?');" style="margin: 0;">
          <button type="submit" class="btn btn-danger btn-sm">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');
  
  const content = html`
    <main>
      <div class="container">
        <div class="flex justify-between items-center mb-2">
          <h1>Secrets</h1>
          <a href="/secrets/add" class="btn btn-primary">+ Add Secret</a>
        </div>
        <div class="card">
          ${secrets.length === 0 ? html`
            <div class="empty">
              <p>No secrets configured yet</p>
              <a href="/secrets/add" class="btn btn-primary mt-2">+ Add Secret</a>
            </div>
          ` : html`
            <table>
              <thead><tr><th>Name</th><th>Provider</th><th>Created</th><th></th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          `}
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Secrets', content, navBar('secrets')));
});

// Add secret page
webRoutes.get('/secrets/add', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const content = html`
    <main>
      <div class="container" style="max-width: 600px;">
        <h1>Add Secret</h1>
        <div class="card">
          <form method="POST" action="/secrets/add">
            <div class="form-group">
              <label for="name">Secret Name</label>
              <input type="text" id="name" name="name" required placeholder="OPENAI_API_KEY" pattern="[A-Z0-9_]+">
              <small class="text-muted">Use uppercase with underscores</small>
            </div>
            <div class="form-group">
              <label for="provider">Provider</label>
              <select id="provider" name="provider" required>
                <option value="anthropic">Anthropic (Claude)</option>
                <option value="openai">OpenAI</option>
                <option value="google">Google AI</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div class="form-group">
              <label for="value">Secret Value</label>
              <input type="password" id="value" name="value" required placeholder="sk-...">
              <small class="text-muted">Will be encrypted before storage</small>
            </div>
            <div class="flex gap-2">
              <button type="submit" class="btn btn-primary">Save Secret</button>
              <a href="/secrets" class="btn btn-ghost">Cancel</a>
            </div>
          </form>
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Add Secret', content, navBar('secrets')));
});

// Add secret submit
webRoutes.post('/secrets/add', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const body = await c.req.parseBody();
  const name = body.name as string;
  const provider = body.provider as string;
  const value = body.value as string;
  
  const encrypted = await encrypt(value, getMasterKey(c.env));
  await db.createSecret(c.env.DB, clientId, name, provider, encrypted);
  
  return redirect('/secrets');
});

// Delete secret
webRoutes.post('/secrets/:id/delete', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const id = c.req.param('id');
  await db.deleteSecret(c.env.DB, id, clientId);
  return redirect('/secrets');
});

// Agents list
webRoutes.get('/agents', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const agents = await db.listAgents(c.env.DB, clientId);
  
  const rows = agents.map(a => html`
    <tr>
      <td><strong>${a.name}</strong></td>
      <td><code class="token">${a.token.slice(0, 16)}...${a.token.slice(-4)}</code></td>
      <td class="text-muted">${a.created_at.split('T')[0]}</td>
      <td class="text-muted">${a.last_seen_at?.split('T')[0] || 'Never'}</td>
      <td>
        <form method="POST" action="/agents/${a.id}/delete" onsubmit="return confirm('Delete this agent?');" style="margin: 0;">
          <button type="submit" class="btn btn-danger btn-sm">Delete</button>
        </form>
      </td>
    </tr>
  `).join('');
  
  const content = html`
    <main>
      <div class="container">
        <h1>Agents</h1>
        <div class="card">
          <h3>Create Agent</h3>
          <form method="POST" action="/agents/add" class="flex gap-2">
            <input type="text" name="name" placeholder="Agent name" required style="flex: 1;">
            <button type="submit" class="btn btn-primary">Create</button>
          </form>
        </div>
        <div class="card">
          <h3>Your Agents</h3>
          ${agents.length === 0 ? html`
            <div class="empty"><p>No agents created yet</p></div>
          ` : html`
            <table>
              <thead><tr><th>Name</th><th>Token</th><th>Created</th><th>Last Seen</th><th></th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          `}
        </div>
        <div class="card">
          <h3>API Usage</h3>
          <pre style="background: var(--bg-tertiary); padding: 1rem; border-radius: 0.375rem; overflow-x: auto;"><code>curl -X POST https://your-broker.workers.dev/v1/secrets/list \\
  -H "Authorization: Bearer seks_agent_..." \\
  -H "Content-Type: application/json"</code></pre>
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Agents', content, navBar('agents')));
});

// Add agent
webRoutes.post('/agents/add', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const body = await c.req.parseBody();
  const name = body.name as string;
  
  await db.createAgent(c.env.DB, clientId, name);
  return redirect('/agents');
});

// Delete agent
webRoutes.post('/agents/:id/delete', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const id = c.req.param('id');
  await db.deleteAgent(c.env.DB, id, clientId);
  return redirect('/agents');
});

// Activity log
webRoutes.get('/activity', async (c) => {
  const clientId = await getSessionClient(c);
  if (!clientId) return redirect('/login');
  
  const entries = await db.listAudit(c.env.DB, clientId, 100);
  
  const rows = entries.map(e => html`
    <tr>
      <td class="text-muted">${e.created_at.replace('T', ' ').split('.')[0]}</td>
      <td>${e.agent_id || '-'}</td>
      <td>${e.action}</td>
      <td>${e.resource ? html`<code class="token">${e.resource}</code>` : '-'}</td>
      <td><span class="badge ${e.status === 'success' ? 'badge-success' : 'badge-muted'}">${e.status}</span></td>
    </tr>
  `).join('');
  
  const content = html`
    <main>
      <div class="container">
        <h1>Activity Log</h1>
        <div class="card">
          ${entries.length === 0 ? html`
            <div class="empty"><p>No activity recorded yet</p></div>
          ` : html`
            <table>
              <thead><tr><th>Time</th><th>Agent</th><th>Action</th><th>Resource</th><th>Status</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          `}
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Activity', content, navBar('activity')));
});
