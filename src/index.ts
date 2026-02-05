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

// API routes (for agents)
app.route('/v1', apiRoutes);

// Web UI routes (for humans)
app.route('/', webRoutes);

export default app;
