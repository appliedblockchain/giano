import type { FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';
import type { SessionContext, SessionService } from '../services/sessions.js';

declare module 'fastify' {
  interface FastifyRequest {
    session: SessionContext | null;
  }
  interface FastifyInstance {
    requireSession: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireAdmin: (request: FastifyRequest, reply: FastifyReply) => Promise<void>;
    isAdminRequest: (request: FastifyRequest) => boolean;
  }
}

function bearerToken(request: FastifyRequest): string | null {
  const header = request.headers.authorization;
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice('Bearer '.length).trim() || null;
}

function timingSafeIncludes(keys: string[], candidate: string): boolean {
  // constant-time-ish comparison across the configured key set
  let matched = false;
  for (const key of keys) {
    if (key.length === candidate.length) {
      let diff = 0;
      for (let i = 0; i < key.length; i++) diff |= key.charCodeAt(i) ^ candidate.charCodeAt(i);
      if (diff === 0) matched = true;
    }
  }
  return matched;
}

export default fp(
  async (app, opts: { sessions: SessionService; adminApiKeys: string[] }) => {
    app.decorateRequest('session', null);

    app.decorate('isAdminRequest', (request: FastifyRequest) => {
      const token = bearerToken(request);
      return token !== null && opts.adminApiKeys.length > 0 && timingSafeIncludes(opts.adminApiKeys, token);
    });

    app.decorate('requireAdmin', async (request: FastifyRequest, reply: FastifyReply) => {
      if (!app.isAdminRequest(request)) {
        return reply.code(401).send({ error: 'unauthorized', message: 'admin API key required' });
      }
    });

    app.decorate('requireSession', async (request: FastifyRequest, reply: FastifyReply) => {
      const token = bearerToken(request);
      if (!token) {
        return reply.code(401).send({ error: 'unauthorized', message: 'bearer session token required' });
      }
      const session = await opts.sessions.resolve(token);
      if (!session) {
        return reply.code(401).send({ error: 'unauthorized', message: 'invalid or expired session' });
      }
      request.session = session;
    });
  },
  { name: 'auth' },
);
