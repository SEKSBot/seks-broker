/**
 * Tests for database operations
 * Uses a mock D1 database for unit testing
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock D1Database interface for testing
interface MockStatement {
  bind: (...args: any[]) => MockStatement;
  first: <T>() => Promise<T | null>;
  all: <T>() => Promise<{ results: T[] }>;
  run: () => Promise<{ success: boolean }>;
}

interface MockD1Database {
  prepare: (query: string) => MockStatement;
  _queries: Array<{ query: string; params: any[] }>;
  _mockData: {
    secrets: Map<string, any>;
    secretAccess: Map<string, string[]>; // secret_id -> agent_ids
    agents: Map<string, any>;
    clients: Map<string, any>;
  };
}

function createMockDb(): MockD1Database {
  const mockData = {
    secrets: new Map<string, any>(),
    secretAccess: new Map<string, string[]>(),
    agents: new Map<string, any>(),
    clients: new Map<string, any>(),
  };

  const queries: Array<{ query: string; params: any[] }> = [];

  function createStatement(query: string): MockStatement {
    let boundParams: any[] = [];

    const statement: MockStatement = {
      bind(...args: any[]) {
        boundParams = args;
        queries.push({ query, params: args });
        return statement;
      },

      async first<T>(): Promise<T | null> {
        // Handle secret queries with access control
        if (query.includes('SELECT s.* FROM secrets s') && query.includes('secret_access')) {
          const [clientId, name, agentId] = boundParams;
          for (const [id, secret] of mockData.secrets) {
            if (secret.client_id === clientId && secret.name === name) {
              const access = mockData.secretAccess.get(id) || [];
              // Global (no access entries) or agent has access
              if (access.length === 0 || access.includes(agentId)) {
                return secret as T;
              }
            }
          }
          return null;
        }

        // Simple secret query (admin)
        if (query.includes('SELECT * FROM secrets WHERE client_id = ? AND name = ?')) {
          const [clientId, name] = boundParams;
          for (const secret of mockData.secrets.values()) {
            if (secret.client_id === clientId && secret.name === name) {
              return secret as T;
            }
          }
          return null;
        }

        // Count secret access
        if (query.includes('SELECT COUNT(*) as count FROM secret_access')) {
          const [secretId] = boundParams;
          const access = mockData.secretAccess.get(secretId) || [];
          return { count: access.length } as T;
        }

        return null;
      },

      async all<T>(): Promise<{ results: T[] }> {
        // List secrets with access control
        if (query.includes('SELECT s.* FROM secrets s') && query.includes('secret_access')) {
          const [clientId, agentId] = boundParams;
          const results: any[] = [];
          for (const [id, secret] of mockData.secrets) {
            if (secret.client_id === clientId) {
              const access = mockData.secretAccess.get(id) || [];
              if (access.length === 0 || access.includes(agentId)) {
                results.push(secret);
              }
            }
          }
          return { results: results as T[] };
        }

        // List secrets (admin)
        if (query.includes('SELECT * FROM secrets WHERE client_id = ?')) {
          const [clientId] = boundParams;
          const results = Array.from(mockData.secrets.values())
            .filter(s => s.client_id === clientId);
          return { results: results as T[] };
        }

        // Get secret access
        if (query.includes('SELECT * FROM secret_access WHERE secret_id = ?')) {
          const [secretId] = boundParams;
          const agentIds = mockData.secretAccess.get(secretId) || [];
          const results = agentIds.map(agentId => ({
            secret_id: secretId,
            agent_id: agentId,
            created_at: new Date().toISOString(),
          }));
          return { results: results as T[] };
        }

        return { results: [] };
      },

      async run() {
        // Insert secret
        if (query.includes('INSERT INTO secrets')) {
          const [id, clientId, name, provider, encryptedValue, createdAt, updatedAt] = boundParams;
          mockData.secrets.set(id, {
            id,
            client_id: clientId,
            name,
            provider,
            encrypted_value: encryptedValue,
            metadata: null,
            created_at: createdAt,
            updated_at: updatedAt,
          });
        }

        // Delete secret access
        if (query.includes('DELETE FROM secret_access WHERE secret_id = ?')) {
          const [secretId] = boundParams;
          mockData.secretAccess.delete(secretId);
        }

        // Insert secret access
        if (query.includes('INSERT INTO secret_access')) {
          const [secretId, agentId] = boundParams;
          const existing = mockData.secretAccess.get(secretId) || [];
          existing.push(agentId);
          mockData.secretAccess.set(secretId, existing);
        }

        return { success: true };
      },
    };

    return statement;
  }

  return {
    prepare: createStatement,
    _queries: queries,
    _mockData: mockData,
  };
}

// Import the actual functions after setting up mocks
import * as db from './db';

describe('Secret Access Control', () => {
  let mockDb: MockD1Database;

  beforeEach(() => {
    mockDb = createMockDb();
  });

  describe('listSecrets with agent filtering', () => {
    beforeEach(() => {
      // Set up test data
      mockDb._mockData.secrets.set('secret1', {
        id: 'secret1',
        client_id: 'client1',
        name: 'GLOBAL_KEY',
        provider: 'other',
        encrypted_value: 'encrypted1',
        created_at: '2024-01-01',
        updated_at: '2024-01-01',
      });

      mockDb._mockData.secrets.set('secret2', {
        id: 'secret2',
        client_id: 'client1',
        name: 'AGENT_A_KEY',
        provider: 'other',
        encrypted_value: 'encrypted2',
        created_at: '2024-01-01',
        updated_at: '2024-01-01',
      });

      mockDb._mockData.secrets.set('secret3', {
        id: 'secret3',
        client_id: 'client1',
        name: 'AGENT_B_KEY',
        provider: 'other',
        encrypted_value: 'encrypted3',
        created_at: '2024-01-01',
        updated_at: '2024-01-01',
      });

      // secret1 is global (no access entries)
      // secret2 is for agent_a only
      mockDb._mockData.secretAccess.set('secret2', ['agent_a']);
      // secret3 is for agent_b only
      mockDb._mockData.secretAccess.set('secret3', ['agent_b']);
    });

    it('agent sees global secrets', async () => {
      const secrets = await db.listSecrets(mockDb as any, 'client1', 'agent_a');
      const names = secrets.map(s => s.name);
      expect(names).toContain('GLOBAL_KEY');
    });

    it('agent sees own secrets', async () => {
      const secrets = await db.listSecrets(mockDb as any, 'client1', 'agent_a');
      const names = secrets.map(s => s.name);
      expect(names).toContain('AGENT_A_KEY');
    });

    it('agent does not see other agent secrets', async () => {
      const secrets = await db.listSecrets(mockDb as any, 'client1', 'agent_a');
      const names = secrets.map(s => s.name);
      expect(names).not.toContain('AGENT_B_KEY');
    });

    it('admin sees all secrets', async () => {
      // Without agentId, should return all
      const secrets = await db.listSecrets(mockDb as any, 'client1');
      expect(secrets.length).toBe(3);
    });
  });

  describe('getSecret with agent filtering', () => {
    beforeEach(() => {
      mockDb._mockData.secrets.set('secret1', {
        id: 'secret1',
        client_id: 'client1',
        name: 'SHARED_KEY',
        provider: 'other',
        encrypted_value: 'encrypted',
        created_at: '2024-01-01',
        updated_at: '2024-01-01',
      });

      // Shared between agent_a and agent_b
      mockDb._mockData.secretAccess.set('secret1', ['agent_a', 'agent_b']);
    });

    it('authorized agent can get secret', async () => {
      const secret = await db.getSecret(mockDb as any, 'client1', 'SHARED_KEY', 'agent_a');
      expect(secret).toBeTruthy();
      expect(secret?.name).toBe('SHARED_KEY');
    });

    it('authorized agent can get secret (second agent)', async () => {
      const secret = await db.getSecret(mockDb as any, 'client1', 'SHARED_KEY', 'agent_b');
      expect(secret).toBeTruthy();
    });

    it('unauthorized agent cannot get secret', async () => {
      const secret = await db.getSecret(mockDb as any, 'client1', 'SHARED_KEY', 'agent_c');
      expect(secret).toBeNull();
    });
  });

  describe('setSecretAccess', () => {
    it('sets access for multiple agents', async () => {
      await db.setSecretAccess(mockDb as any, 'secret1', ['agent_a', 'agent_b']);
      const access = mockDb._mockData.secretAccess.get('secret1');
      expect(access).toContain('agent_a');
      expect(access).toContain('agent_b');
    });

    it('empty array makes secret global', async () => {
      mockDb._mockData.secretAccess.set('secret1', ['agent_a']);
      await db.setSecretAccess(mockDb as any, 'secret1', []);
      const access = mockDb._mockData.secretAccess.get('secret1');
      expect(access).toBeUndefined();
    });

    it('replaces existing access', async () => {
      mockDb._mockData.secretAccess.set('secret1', ['agent_a', 'agent_b']);
      await db.setSecretAccess(mockDb as any, 'secret1', ['agent_c']);
      const access = mockDb._mockData.secretAccess.get('secret1');
      expect(access).toEqual(['agent_c']);
    });
  });

  describe('isSecretGlobal', () => {
    it('returns true for secret with no access entries', async () => {
      const isGlobal = await db.isSecretGlobal(mockDb as any, 'secret1');
      expect(isGlobal).toBe(true);
    });

    it('returns false for secret with access entries', async () => {
      mockDb._mockData.secretAccess.set('secret1', ['agent_a']);
      const isGlobal = await db.isSecretGlobal(mockDb as any, 'secret1');
      expect(isGlobal).toBe(false);
    });
  });
});

describe('Secret CRUD', () => {
  let mockDb: MockD1Database;

  beforeEach(() => {
    mockDb = createMockDb();
  });

  it('createSecret returns secret with id', async () => {
    const secret = await db.createSecret(
      mockDb as any,
      'client1',
      'TEST_KEY',
      'other',
      'encrypted_value'
    );

    expect(secret.id).toBeTruthy();
    expect(secret.name).toBe('TEST_KEY');
    expect(secret.provider).toBe('other');
    expect(secret.client_id).toBe('client1');
  });
});
