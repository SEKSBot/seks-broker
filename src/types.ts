/**
 * Type definitions for SEKS Broker
 */

export interface Env {
  DB: D1Database;
  MASTER_KEY?: string;
}

// Database models

export interface Client {
  id: string;
  email: string;
  password_hash: string;
  name: string | null;
  created_at: string;
}

export interface Agent {
  id: string;
  client_id: string;
  name: string;
  token: string;
  scopes: string;
  created_at: string;
  last_seen_at: string | null;
}

export interface Secret {
  id: string;
  client_id: string;
  name: string;
  provider: string;
  encrypted_value: string;
  metadata: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuditEntry {
  id: string;
  client_id: string;
  agent_id: string | null;
  action: string;
  resource: string | null;
  status: string;
  ip_address: string | null;
  details: string | null;
  created_at: string;
}

export interface Session {
  id: string;
  client_id: string;
  expires_at: string;
  created_at: string;
}

// API types

export interface SecretGetRequest {
  name: string;
}

export interface SecretGetResponse {
  ok: boolean;
  value?: string;
  error?: string;
}

export interface SecretListResponse {
  ok: boolean;
  secrets: Array<{ name: string; provider: string }>;
}

export interface ProxyRequest {
  service: string;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ProxyResponse {
  ok: boolean;
  status?: number;
  body?: unknown;
  error?: string;
}
