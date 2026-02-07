/**
 * Database operations for SEKS Broker
 */

import { generateId, generateToken } from './crypto';
import type { Client, Agent, Secret, AuditEntry, Session, Env } from './types';

// ─── Clients ───────────────────────────────────────────────────────────────────

export async function createClient(
  db: D1Database,
  email: string,
  passwordHash: string,
  name?: string
): Promise<Client> {
  const id = generateId();
  const now = new Date().toISOString();
  
  await db.prepare(
    'INSERT INTO clients (id, email, password_hash, name, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, email, passwordHash, name ?? null, now).run();
  
  return { id, email, password_hash: passwordHash, name: name ?? null, created_at: now };
}

export async function getClientByEmail(db: D1Database, email: string): Promise<Client | null> {
  const result = await db.prepare('SELECT * FROM clients WHERE email = ?').bind(email).first<Client>();
  return result ?? null;
}

export async function getClientById(db: D1Database, id: string): Promise<Client | null> {
  const result = await db.prepare('SELECT * FROM clients WHERE id = ?').bind(id).first<Client>();
  return result ?? null;
}

// ─── Agents ────────────────────────────────────────────────────────────────────

export async function createAgent(
  db: D1Database,
  clientId: string,
  name: string
): Promise<Agent> {
  const id = `agent_${generateId().split('-')[0]}`;
  const token = generateToken('seks_agent');
  const now = new Date().toISOString();
  
  await db.prepare(
    'INSERT INTO agents (id, client_id, name, token, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, clientId, name, token, '[]', now).run();
  
  return { id, client_id: clientId, name, token, scopes: '[]', created_at: now, last_seen_at: null };
}

export async function getAgentByToken(db: D1Database, token: string): Promise<Agent | null> {
  const result = await db.prepare('SELECT * FROM agents WHERE token = ?').bind(token).first<Agent>();
  return result ?? null;
}

export async function getAgentById(db: D1Database, id: string): Promise<Agent | null> {
  const result = await db.prepare('SELECT * FROM agents WHERE id = ?').bind(id).first<Agent>();
  return result ?? null;
}

export async function listAgents(db: D1Database, clientId: string): Promise<Agent[]> {
  const result = await db.prepare(
    'SELECT * FROM agents WHERE client_id = ? ORDER BY created_at DESC'
  ).bind(clientId).all<Agent>();
  return result.results ?? [];
}

export async function deleteAgent(db: D1Database, id: string, clientId: string): Promise<void> {
  await db.prepare('DELETE FROM agents WHERE id = ? AND client_id = ?').bind(id, clientId).run();
}

export async function updateAgentLastSeen(db: D1Database, id: string): Promise<void> {
  const now = new Date().toISOString();
  await db.prepare('UPDATE agents SET last_seen_at = ? WHERE id = ?').bind(now, id).run();
}

// ─── Secrets ───────────────────────────────────────────────────────────────────

export async function createSecret(
  db: D1Database,
  clientId: string,
  name: string,
  provider: string,
  encryptedValue: string
): Promise<Secret> {
  const id = generateId();
  const now = new Date().toISOString();
  
  await db.prepare(
    'INSERT INTO secrets (id, client_id, name, provider, encrypted_value, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, clientId, name, provider, encryptedValue, now, now).run();
  
  return {
    id, client_id: clientId, name, provider, encrypted_value: encryptedValue,
    metadata: null, created_at: now, updated_at: now
  };
}

export async function getSecret(db: D1Database, clientId: string, name: string): Promise<Secret | null> {
  const result = await db.prepare(
    'SELECT * FROM secrets WHERE client_id = ? AND name = ?'
  ).bind(clientId, name).first<Secret>();
  return result ?? null;
}

export async function listSecrets(db: D1Database, clientId: string): Promise<Secret[]> {
  const result = await db.prepare(
    'SELECT * FROM secrets WHERE client_id = ? ORDER BY name'
  ).bind(clientId).all<Secret>();
  return result.results ?? [];
}

export async function deleteSecret(db: D1Database, id: string, clientId: string): Promise<void> {
  await db.prepare('DELETE FROM secrets WHERE id = ? AND client_id = ?').bind(id, clientId).run();
}

export async function getSecretById(db: D1Database, id: string, clientId: string): Promise<Secret | null> {
  const result = await db.prepare(
    'SELECT * FROM secrets WHERE id = ? AND client_id = ?'
  ).bind(id, clientId).first<Secret>();
  return result ?? null;
}

export async function updateSecret(
  db: D1Database,
  id: string,
  clientId: string,
  name: string,
  provider: string,
  encryptedValue?: string
): Promise<void> {
  const now = new Date().toISOString();
  if (encryptedValue) {
    await db.prepare(
      'UPDATE secrets SET name = ?, provider = ?, encrypted_value = ?, updated_at = ? WHERE id = ? AND client_id = ?'
    ).bind(name, provider, encryptedValue, now, id, clientId).run();
  } else {
    await db.prepare(
      'UPDATE secrets SET name = ?, provider = ?, updated_at = ? WHERE id = ? AND client_id = ?'
    ).bind(name, provider, now, id, clientId).run();
  }
}

// ─── Audit Log ─────────────────────────────────────────────────────────────────

export async function logAudit(
  db: D1Database,
  clientId: string,
  agentId: string | null,
  action: string,
  resource: string | null,
  status: string,
  ipAddress?: string | null,
  details?: string | null
): Promise<void> {
  const id = generateId();
  const now = new Date().toISOString();
  
  await db.prepare(
    'INSERT INTO audit_log (id, client_id, agent_id, action, resource, status, ip_address, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, clientId, agentId, action, resource, status, ipAddress ?? null, details ?? null, now).run();
}

export async function listAudit(db: D1Database, clientId: string, limit: number = 100): Promise<AuditEntry[]> {
  const result = await db.prepare(
    'SELECT * FROM audit_log WHERE client_id = ? ORDER BY created_at DESC LIMIT ?'
  ).bind(clientId, limit).all<AuditEntry>();
  return result.results ?? [];
}

// ─── Sessions ──────────────────────────────────────────────────────────────────

export async function createSession(db: D1Database, clientId: string): Promise<Session> {
  const id = generateId();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000); // 24 hours
  
  await db.prepare(
    'INSERT INTO sessions (id, client_id, expires_at, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, clientId, expiresAt.toISOString(), now.toISOString()).run();
  
  return { id, client_id: clientId, expires_at: expiresAt.toISOString(), created_at: now.toISOString() };
}

export async function getSession(db: D1Database, id: string): Promise<Session | null> {
  const result = await db.prepare('SELECT * FROM sessions WHERE id = ?').bind(id).first<Session>();
  if (!result) return null;
  
  // Check expiration
  if (new Date(result.expires_at) < new Date()) {
    await deleteSession(db, id);
    return null;
  }
  
  return result;
}

export async function deleteSession(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
}

// ─── Fake Tokens ───────────────────────────────────────────────────────────────

export interface FakeToken {
  id: string;
  agent_id: string;
  provider: string;
  token: string;
  created_at: string;
  last_used_at: string | null;
}

export async function createFakeToken(
  db: D1Database,
  agentId: string,
  provider: string
): Promise<FakeToken> {
  const id = generateId();
  const token = `seks_${provider}_${generateToken('').slice(0, 24)}`; // e.g., seks_openai_abc123...
  const now = new Date().toISOString();
  
  // Delete existing token for this agent+provider (upsert behavior)
  await db.prepare('DELETE FROM fake_tokens WHERE agent_id = ? AND provider = ?')
    .bind(agentId, provider).run();
  
  await db.prepare(
    'INSERT INTO fake_tokens (id, agent_id, provider, token, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, agentId, provider, token, now).run();
  
  return { id, agent_id: agentId, provider, token, created_at: now, last_used_at: null };
}

export async function getFakeTokenByToken(db: D1Database, token: string): Promise<FakeToken | null> {
  const result = await db.prepare('SELECT * FROM fake_tokens WHERE token = ?')
    .bind(token).first<FakeToken>();
  return result ?? null;
}

export async function listFakeTokens(db: D1Database, agentId: string): Promise<FakeToken[]> {
  const result = await db.prepare('SELECT * FROM fake_tokens WHERE agent_id = ? ORDER BY provider')
    .bind(agentId).all<FakeToken>();
  return result.results ?? [];
}

export async function deleteFakeToken(db: D1Database, id: string, agentId: string): Promise<void> {
  await db.prepare('DELETE FROM fake_tokens WHERE id = ? AND agent_id = ?')
    .bind(id, agentId).run();
}

export async function updateFakeTokenLastUsed(db: D1Database, id: string): Promise<void> {
  const now = new Date().toISOString();
  await db.prepare('UPDATE fake_tokens SET last_used_at = ? WHERE id = ?')
    .bind(now, id).run();
}
