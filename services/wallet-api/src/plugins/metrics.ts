import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';
import { sha256hex } from '../services/tenants.js';

declare module 'fastify' {
  interface FastifyInstance {
    metrics: {
      useropRelayed: Counter<'status' | 'tenant' | 'chain'>;
      policyRejections: Counter<'rule' | 'tenant' | 'chain'>;
      ceremonyFailures: Counter<'kind' | 'tenant'>;
      useropLatency: Histogram<'tenant' | 'chain'>;
      /** ALERTABLE: if this ever fires, RP resolution is broken or someone is probing. */
      crossTenantRejections: Counter<'kind' | 'tenant'>;
      /**
       * Wallet-management lifecycle events (WM-50…WM-52). ALERTABLE on
       * action="pending-declined": a fingerprint the user refused to confirm is either a
       * bug or an attempted key substitution — exactly what D8 exists to prevent.
       */
      walletManagement: Counter<'action' | 'outcome' | 'tenant'>;

      // ── Gas sponsorship ──────────────────────────────────────────────────────
      /** ALERTABLE: a refusal-rate spike for one tenant usually means a rule change went wrong. */
      sponsorshipDecisions: Counter<'tenant' | 'method' | 'outcome' | 'reason' | 'chain'>;
      /** ALERTABLE: any signature from an unexpected key_id, and signing stopping entirely. */
      sponsorshipSignatures: Counter<'tenant' | 'key_id' | 'chain'>;
      /** ALERTABLE: an outage, as distinct from a rule refusal — the two need different responses. */
      sponsorshipUnavailable: Counter<'cause'>;
      tenantBalanceWei: Gauge<'tenant' | 'chain'>;
      tenantReservedWei: Gauge<'tenant' | 'chain'>;
      tenantAvailableWei: Gauge<'tenant' | 'chain'>;
      /** ALERTABLE on non-zero: money the pooled deposit absorbed on one tenant's behalf. */
      tenantDeficitWei: Gauge<'tenant' | 'chain'>;
      /** PAGES on 1: claims exceed the deposit, which is an insolvency. Per chain — each chain has its own deposit. */
      paymasterInvariantBreach: Gauge<'chain'>;
      /** Expected positive; unexpectedly fast growth means tenants are being overcharged. */
      paymasterInvariantSlackWei: Gauge<'chain'>;
      paymasterDepositWei: Gauge<'chain'>;
      paymasterTreasuryWei: Gauge<'chain'>;
      paymasterStakeWei: Gauge<'chain'>;
      paymasterWatcherLagBlocks: Gauge<'chain'>;
      paymasterWatcherLagSeconds: Gauge<'chain'>;
      /** ALERTABLE: a drawdown the events do not explain is the signature of a leaked signing key. */
      paymasterReconciliationDivergenceWei: Gauge<'chain'>;
      /** 0/1 per served chain — drives the chain-unavailable alert (MC-54, MC-103). */
      chainAvailable: Gauge<'chain'>;
    };
  }
}

/**
 * Prometheus metrics for the userop relay and ceremonies, exposed at GET /metrics.
 * Every metric carries a `tenant` label (the slug — human-readable, bounded
 * cardinality) so per-tenant billing/alerting/capacity dashboards are possible.
 * When `bearerToken` is set the endpoint requires it (D3.6 — per-tenant volumes are
 * not public data); unset keeps it open for dev/compose stacks.
 */
export default fp(
  async (app: FastifyInstance, opts: { bearerToken?: string }) => {
    const registry = new Registry();
    collectDefaultMetrics({ register: registry });

    const metrics = {
      useropRelayed: new Counter({
        name: 'giano_userop_relayed_total',
        help: 'User operations processed by the relay, by outcome, tenant and chain',
        labelNames: ['status', 'tenant', 'chain'] as const,
        registers: [registry],
      }),
      policyRejections: new Counter({
        name: 'giano_userop_policy_rejections_total',
        help: 'Policy rule rejections, by rule, tenant and chain — a rejection means different things on different chains',
        labelNames: ['rule', 'tenant', 'chain'] as const,
        registers: [registry],
      }),
      ceremonyFailures: new Counter({
        name: 'giano_ceremony_failures_total',
        help: 'WebAuthn ceremony verification failures, by kind and tenant',
        labelNames: ['kind', 'tenant'] as const,
        registers: [registry],
      }),
      useropLatency: new Histogram({
        name: 'giano_userop_relay_seconds',
        help: 'Latency of the userop relay endpoint',
        labelNames: ['tenant', 'chain'] as const,
        buckets: [0.05, 0.1, 0.25, 0.5, 1, 2, 5],
        registers: [registry],
      }),
      crossTenantRejections: new Counter({
        name: 'giano_cross_tenant_rejections_total',
        help: "Requests rejected for crossing a tenant boundary (kind: credential|challenge|session) — alert on any increase",
        labelNames: ['kind', 'tenant'] as const,
        registers: [registry],
      }),
      walletManagement: new Counter({
        name: 'giano_wallet_management_events_total',
        help: 'Wallet-management lifecycle events by action, outcome and tenant — alert on action="pending-declined" (a refused fingerprint is a bug or an attempted key substitution)',
        labelNames: ['action', 'outcome', 'tenant'] as const,
        registers: [registry],
      }),

      sponsorshipDecisions: new Counter({
        name: 'giano_sponsorship_decisions_total',
        help: 'Sponsorship decisions by tenant, method (stub|data), outcome, refusal reason and chain',
        labelNames: ['tenant', 'method', 'outcome', 'reason', 'chain'] as const,
        registers: [registry],
      }),
      sponsorshipSignatures: new Counter({
        name: 'giano_sponsorship_signatures_total',
        help: 'Sponsorship authorisations signed, by tenant, signing key id and chain — alert on an unexpected key_id',
        labelNames: ['tenant', 'key_id', 'chain'] as const,
        registers: [registry],
      }),
      sponsorshipUnavailable: new Counter({
        name: 'giano_sponsorship_unavailable_total',
        help: 'Sponsorship failures that are outages rather than refusals (cause: signer|hsm|database|chain)',
        labelNames: ['cause'] as const,
        registers: [registry],
      }),
      tenantBalanceWei: new Gauge({
        name: 'giano_tenant_balance_wei',
        help: "A tenant's on-chain gas balance, per chain",
        labelNames: ['tenant', 'chain'] as const,
        registers: [registry],
      }),
      tenantReservedWei: new Gauge({
        name: 'giano_tenant_reserved_wei',
        help: "A tenant's outstanding sponsorship reservations, per chain",
        labelNames: ['tenant', 'chain'] as const,
        registers: [registry],
      }),
      tenantAvailableWei: new Gauge({
        name: 'giano_tenant_available_wei',
        help: 'balance − reserved: what a new operation may actually draw on — alert below the tenant threshold',
        labelNames: ['tenant', 'chain'] as const,
        registers: [registry],
      }),
      tenantDeficitWei: new Gauge({
        name: 'giano_tenant_deficit_wei',
        help: "Money the pooled deposit absorbed on a tenant's behalf — alert on any non-zero value",
        labelNames: ['tenant', 'chain'] as const,
        registers: [registry],
      }),
      paymasterInvariantBreach: new Gauge({
        name: 'giano_paymaster_invariant_breach',
        help: '1 when Σ tenant balances + treasury exceeds the deposit. This is an insolvency — page immediately',
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      paymasterInvariantSlackWei: new Gauge({
        name: 'giano_paymaster_invariant_slack_wei',
        help: 'deposit − (Σ balances + treasury). Expected positive; growth faster than the overhead model predicts means tenants are overcharged',
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      paymasterDepositWei: new Gauge({
        name: 'giano_paymaster_deposit_wei',
        help: "The paymaster's EntryPoint deposit",
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      paymasterTreasuryWei: new Gauge({
        name: 'giano_paymaster_treasury_wei',
        help: 'Accrued platform fees not yet withdrawn',
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      paymasterStakeWei: new Gauge({
        name: 'giano_paymaster_stake_wei',
        help: "The paymaster's EntryPoint stake — bundlers reject an unstaked validating paymaster",
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      paymasterWatcherLagBlocks: new Gauge({
        name: 'giano_paymaster_watcher_lag_blocks',
        help: 'Blocks between the chain head and the watcher cursor',
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      paymasterWatcherLagSeconds: new Gauge({
        name: 'giano_paymaster_watcher_lag_seconds',
        help: 'Seconds since the watcher last completed a pass',
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      paymasterReconciliationDivergenceWei: new Gauge({
        name: 'giano_paymaster_reconciliation_divergence_wei',
        help: 'Deposit drawdown the observed events do not account for — the signature of a leaked signing key',
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
      chainAvailable: new Gauge({
        name: 'giano_chain_available',
        help: '1 while a served chain is reachable, 0 while it is not — one series per chain (MC-103)',
        labelNames: ['chain'] as const,
        registers: [registry],
      }),
    };
    app.decorate('metrics', metrics);

    app.get('/metrics', { schema: { hide: true } }, async (request, reply) => {
      if (opts.bearerToken) {
        const header = request.headers.authorization;
        const presented = header?.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : '';
        // compare sha256 digests so lengths always match for timingSafeEqual
        const ok = presented && timingSafeEqual(Buffer.from(sha256hex(presented)), Buffer.from(sha256hex(opts.bearerToken)));
        if (!ok) {
          return reply.code(401).send({ error: 'unauthorized', message: 'metrics bearer token required' });
        }
      }
      reply.header('content-type', registry.contentType);
      return registry.metrics();
    });
  },
  { name: 'metrics' },
);
