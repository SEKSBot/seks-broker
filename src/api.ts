/**
 * REST API routes for agents
 */

import { Hono } from 'hono';
import type { Env, SecretGetRequest, ProxyRequest } from './types';
import * as db from './db';
import { decrypt } from './crypto';

export const apiRoutes = new Hono<{ Bindings: Env }>();

// ─── Auth Helper ───────────────────────────────────────────────────────────────

async function authenticateAgent(c: any) {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  
  const token = authHeader.slice(7);
  const agent = await db.getAgentByToken(c.env.DB, token);
  
  if (agent) {
    // Update last seen (fire and forget)
    c.executionCtx.waitUntil(db.updateAgentLastSeen(c.env.DB, agent.id));
  }
  
  return agent;
}

function getMasterKey(env: Env): string {
  // In production, this should be set via wrangler secret
  // For dev, generate an ephemeral one (data won't persist across restarts)
  return env.MASTER_KEY || 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
}

// ─── Health Check ──────────────────────────────────────────────────────────────

apiRoutes.get('/health', (c) => {
  return c.json({ status: 'ok', version: '0.1.0' });
});

// ─── Get Secret ────────────────────────────────────────────────────────────────

apiRoutes.post('/secrets/get', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, error: 'Unauthorized' }, 401);
  }
  
  const body = await c.req.json<SecretGetRequest>();
  if (!body.name) {
    return c.json({ ok: false, error: 'Missing "name" field' }, 400);
  }
  
  const secret = await db.getSecret(c.env.DB, agent.client_id, body.name);
  if (!secret) {
    await db.logAudit(c.env.DB, agent.client_id, agent.id, 'secret.get', body.name, 'not_found');
    return c.json({ ok: false, error: `Secret '${body.name}' not found` }, 404);
  }
  
  try {
    const value = await decrypt(secret.encrypted_value, getMasterKey(c.env));
    await db.logAudit(c.env.DB, agent.client_id, agent.id, 'secret.get', body.name, 'success');
    return c.json({ ok: true, value });
  } catch (e) {
    return c.json({ ok: false, error: 'Failed to decrypt secret' }, 500);
  }
});

// ─── List Secrets ──────────────────────────────────────────────────────────────

apiRoutes.post('/secrets/list', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, secrets: [] }, 401);
  }
  
  const secrets = await db.listSecrets(c.env.DB, agent.client_id);
  const secretInfos = secrets.map(s => ({ name: s.name, provider: s.provider }));
  
  await db.logAudit(c.env.DB, agent.client_id, agent.id, 'secret.list', null, 'success');
  return c.json({ ok: true, secrets: secretInfos });
});

// ─── Proxy Request ─────────────────────────────────────────────────────────────

const SERVICE_CONFIG: Record<string, { baseUrl: string; secretName: string; authHeader: string }> = {
  openai: {
    baseUrl: 'https://api.openai.com',
    secretName: 'OPENAI_API_KEY',
    authHeader: 'Authorization',
  },
  anthropic: {
    baseUrl: 'https://api.anthropic.com',
    secretName: 'ANTHROPIC_API_KEY',
    authHeader: 'x-api-key',
  },
  claude: {
    baseUrl: 'https://api.anthropic.com',
    secretName: 'ANTHROPIC_API_KEY',
    authHeader: 'x-api-key',
  },
};

apiRoutes.post('/proxy/request', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, error: 'Unauthorized' }, 401);
  }
  
  const body = await c.req.json<ProxyRequest>();
  
  const config = SERVICE_CONFIG[body.service];
  if (!config) {
    return c.json({ ok: false, error: `Unknown service: ${body.service}` }, 400);
  }
  
  // Get the API key
  const secret = await db.getSecret(c.env.DB, agent.client_id, config.secretName);
  if (!secret) {
    return c.json({ ok: false, error: `No ${config.secretName} configured` }, 404);
  }
  
  let apiKey: string;
  try {
    apiKey = await decrypt(secret.encrypted_value, getMasterKey(c.env));
  } catch (e) {
    return c.json({ ok: false, error: 'Failed to decrypt secret' }, 500);
  }
  
  // Build upstream request
  const url = `${config.baseUrl}${body.path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...body.headers,
  };
  
  // Add auth header
  if (config.authHeader === 'Authorization') {
    headers['Authorization'] = `Bearer ${apiKey}`;
  } else {
    headers[config.authHeader] = apiKey;
  }
  
  // Add Anthropic-specific headers
  if (body.service === 'anthropic' || body.service === 'claude') {
    headers['anthropic-version'] = '2023-06-01';
  }
  
  // Remove any auth headers from user-provided headers
  delete headers['authorization'];
  delete headers['x-api-key'];
  
  try {
    const response = await fetch(url, {
      method: body.method.toUpperCase(),
      headers,
      body: body.body ? JSON.stringify(body.body) : undefined,
    });
    
    const status = response.status;
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      responseBody = await response.text();
    }
    
    await db.logAudit(
      c.env.DB, agent.client_id, agent.id, 'proxy.request',
      body.service, 'success', null, `status=${status}`
    );
    
    return c.json({
      ok: status >= 200 && status < 300,
      status,
      body: responseBody,
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    await db.logAudit(
      c.env.DB, agent.client_id, agent.id, 'proxy.request',
      body.service, 'error', null, error
    );
    return c.json({ ok: false, error: `Request failed: ${error}` }, 502);
  }
});
