/**
 * SEKS Broker - Cloud-native secret management for AI agents
 * 
 * Cloudflare Workers + D1 + Hono
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';

import { apiRoutes } from './api';
import { webRoutes } from './web';
import { Env } from './types';

const app = new Hono<{ Bindings: Env }>();

// Middleware
app.use('*', logger());
app.use('/v1/*', cors());
app.use('/api/*', cors());

// API routes (for agents) - /v1/secrets/*, /v1/proxy/*, etc.
app.route('/v1', apiRoutes);

// Passthrough proxy also available at /api/* (cleaner URLs)
// These routes are defined in apiRoutes as /api/openai/*, etc.
// Mounting apiRoutes at '' makes them available at /api/*
app.route('', apiRoutes);

// Web UI routes (for humans)
app.route('/', webRoutes);

export default app;
