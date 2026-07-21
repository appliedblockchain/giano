# Giano — Execution Plan: From Monorepo Source to Distributable Wallet Component

## Context

The investigation in `GAP-ANALYSIS.md` (repo root) established that Giano — an ERC-4337 passkey smart wallet — currently exists only as pnpm monorepo source: its npm packages are unpublishable (`workspace:` deps, gitignored generated artifacts, root-only build tooling), its only "backend" is demo-grade Next.js API routes with in-memory storage and no auth, there is zero Docker/CI infrastructure, and — most critically — the integration model makes each client application the wallet (the dApp's origin is the WebAuthn RP and the dApp must implement the security-critical `GianoProviderInjection` interface).

**Target state (per the updated report):** Giano ships as versioned artifacts — npm packages on **GitHub Packages** (`@appliedblockchain` scope) plus Docker images on **GHCR** — that every client project deploys *itself* as services in its own stack (Giano is never centrally hosted). Wallet trust lives entirely in Giano-shipped code: a dedicated wallet origin (`wallet.clientapp.com`) served by a Giano container runs all passkey ceremonies and consent UI; the dApp installs only a thin SDK.

**Locked decisions (user-confirmed):**
- Plan scope: full 4-phase roadmap — Phases 1–2 in executable detail, Phases 3–4 directional but concrete.
- npm registry: GitHub Packages (private, `@appliedblockchain`).
- `giano-wallet-api`: new Fastify + TypeScript service, PostgreSQL, `@simplewebauthn/server`.
- `giano-wallet-web`: new minimal greenfield app (the demo `services/custom-example` remains a demo/test harness).

## Upfront architecture decisions

- **D1 — wallet-web = Vite React SPA served by nginx** (not Next.js): all server logic lives in `giano-wallet-api`; a static SPA gives a minimal-attack-surface container with runtime config injected at start (`/config.json` via envsubst), so one published image serves every client deployment. nginx proxies `/api/*` and `/.well-known/webauthn` to the wallet-api (same-origin ⇒ no CORS/third-party-cookie issues).
- **D2 — transport = custom JSON-RPC-over-postMessage popup protocol** modeled on Coinbase wallet-sdk v4 (keys.coinbase.com pattern), implemented fresh in a shared package (`@appliedblockchain/giano-wallet-transport`) — not WalletConnect (needs a relay server), not `@coinbase/wallet-sdk` (hardcodes their origins; its ECDH layer is unnecessary when both origins belong to one project and postMessage origin checks authenticate the channel). **Popup-first; iframe mode deferred** (cross-origin WebAuthn-in-iframe + third-party-cookie problems).
- **D3 — package layout**: extract `packages/wallet-core` (provider, account/signing, injection) out of the connector; add `packages/wallet-transport`; slim `packages/connector` to the thin SDK (major bump → 1.0.0) with the old injection API kept as a deprecated `/embedded` subpath export.
- **D4 — canonical deploy toolchain = Hardhat Ignition** (existing CREATE2 salt + committed journals for chains 8453/84532/381185; sdr-testnet needs a Hardhat-only plugin). Canonical build: solc 0.8.28 / runs 200 / viaIR; align or delete the divergent `foundry.toml` `[profile.deploy]`; Foundry stays test-only. Enforced by a CI determinism job.

---

## Phase 1 — Packaging & publishing (npm on GitHub Packages)

Verified facts the plan relies on: the connector imports only `gianoSmartWalletAbi`/`gianoSmartWalletFactoryAbi` from contracts (`toGianoSmartAccount.ts:1`); nothing outside contracts consumes `typechain-types`; the ignition `deployed_addresses.json` files **are** git-tracked (force-added), so a registry generator works from a clean checkout; EntryPoint v0.7 (`0x0000000071727De2…`) is not in ignition output and must come from a constant + per-chain override.

### M1.1 Shared build scaffolding
- New root `tsconfig.base.json` (strict, ES2022, `moduleResolution: bundler`); slim root `tsconfig.json`, **delete dead path aliases** (`webapp`/`api`/`bcm`).
- Delete `services/web-outdated/` (R15).
- Per-package configs: `packages/connector/{tsconfig.json,tsup.config.ts}` (3 entries: `index`, `index-web`, `index-node`; ESM+CJS; dts; peers external), `packages/contracts/tsup.config.ts`; then delete root `tsup.config.ts`.

### M1.2 Contracts package publishable (before connector)
- **C1 Commit `generated.ts`**: run `hh:compile && hh:wagmi`, un-gitignore, commit; CI drift check (`regenerate && git diff --exit-code`). This kills the "build contracts before connector type-checks" ordering (R10).
- **C2 Address registry (R8)**: new `packages/contracts/scripts/generate-addresses.ts` reads `ignition/deployments/chain-*/deployed_addresses.json` (mapping `GianoAccountFactory#GianoSmartWalletFactory→factory`, `#GianoSmartWallet→implementation`, `Testing#PermissivePaymaster→paymaster?`, `Testing#PrivateERC20→testErc20?`), merges committed `address-overrides.json` (per-chain `entryPoint`, default `ENTRYPOINT_V07_ADDRESS`), emits **committed** `addresses.ts` exporting `gianoAddresses: Record<number, GianoDeployment>` + `getGianoDeployment(chainId)`. Committed + CI drift check (not pack-time-only — dev-time resolution matters).
- **C3 `index.ts` + package.json**: `export * from './generated'; export * from './addresses';` — drop `typechain-types` from the published surface. Fix `files` (`["dist", "src/**/*.sol", "addresses.ts", "generated.ts", …]`), add `exports` map with `types` conditions, `main/module/types` with extensions, `publishConfig: {registry: npm.pkg.github.com, access: restricted}`, `prepublishOnly: "pnpm build:ts"` (tsup-only — publish must not need solc), repository/author/LICENSE.
- **C4 Canonical toolchain note (R9 subset)**: document Hardhat Ignition (solc 0.8.28/runs 200/viaIR) as canonical in a new `packages/contracts/README.md`; neutralize the divergent `foundry.toml` `[profile.deploy]`. Full CI determinism gate is Phase 4.
- *Accept:* fresh clone, **no submodules, no solc**: `pnpm i && contracts build:ts && connector build` green; `npm pack` tarball contains dist + `.sol` sources.

### M1.3 Connector package publishable
- **N1 package.json overhaul (R7)**: `viem ^2.31.0` / `wagmi ^2.15.0` / `@rainbow-me/rainbowkit ^2.2.0` become `peerDependencies` (wagmi/rainbowkit optional via `peerDependenciesMeta` — the `/node` entry needs neither), kept in devDeps for local builds. Keep `"@appliedblockchain/giano-contracts": "workspace:^"` (pnpm rewrites to real semver on publish — verify in `pnpm pack` tarball). Fix `main` extension, add `module`, `sideEffects: false`, `exports` with `types` per subpath (`.`, `./web`, `./node`), `files`, `publishConfig`, `prepublishOnly`, license → MIT.
- **N2 Logger hygiene**: replace `console.*` in `provider.ts` with an injectable `GianoLogger` (default no-op except error).
- **N3 README fixes (R14)**: remove the nonexistent `GianoNodeConnector`, document real exports + GH Packages install (`.npmrc` guidance incl. the @appliedblockchain scope caveat below).
- *Accept:* `npm pack` → install tarball in a scratch external Vite app with peer deps; `tsc --noEmit` resolves all three entry points.

### M1.4 Changesets + GitHub Actions
- `@changesets/cli`, `.changeset/config.json` (restricted; **independent versioning now**, moving to fixed/lockstep mode in Phase 4 per P4.5; ignore the demo app).
- `.github/workflows/ci.yml`: `packages` job (install → build → typecheck → drift checks for `generated.ts`/`addresses.ts`) + `forge` job (submodules recursive, foundry-toolchain, `forge test`).
- `.github/workflows/release.yml`: changesets action → version PR → publish to GitHub Packages with `GITHUB_TOKEN` (`packages: write`).
- Root doc/script cleanup (R14): fix README §67/§57, `.env-base-mainnet` `CONFIG_KEY` bug, point demo `config.ts` fallbacks at `gianoAddresses` (kills the drifted `0x5A1dd8C5…` values), **flag committed Coinbase CDP bundler keys for rotation** (ops task).
- *Accept:* first versions on GitHub Packages (`giano-contracts@2.2.0`, `giano-connector@0.2.0`) via the Changesets flow; CI green.

**Phase 1 key risk — GH Packages scope collision:** consumers who set `@appliedblockchain:registry=npm.pkg.github.com` can't fetch public `@appliedblockchain/silentdatarollup-*` from npmjs in the same project (those are devDeps of contracts only, not shipped). Do **not** add a repo-level scope `.npmrc`; route via per-package `publishConfig` and document the caveat in the install guide.

## Phase 2 — `giano-wallet-api` backend service (Fastify + Postgres)

New `services/wallet-api/` (private; distributed only as `ghcr.io/appliedblockchain/giano-wallet-api`). Stack: Fastify 5, `@simplewebauthn/server` ^13 (**ESM-only → service is `"type": "module"`**), zod + fastify-type-provider-zod (pin a compatible pair), drizzle-orm + plain-SQL migrations bundled in the image, `pg`, viem + `@appliedblockchain/giano-contracts` (ABIs + registry), pino, vitest + testcontainers.

**Key insight preserved:** the existing `GianoProviderInjection` seam already passes full `PublicKeyCredential` objects (attestation/assertion), which is sufficient for complete server-side @simplewebauthn verification **without changing the interface** — the reference injection is a pure implementation of the existing seam.

### M2.1 Skeleton + DB
- Layout: `src/{index,migrate,app,config}.ts`, `db/`, `plugins/{db,auth,error-handler}.ts`, `routes/{health,webauthn,credentials,userops,well-known,admin}.ts`, `services/{challenges,sessions,userop-policy,bundler}.ts`, `migrations/0001_init.sql`, `openapi/generate.ts`.
- Schema: `users` (with `external_id` — the client project's user id, the R6a binding point), `credentials` (COSE key + P-256 x/y hex + counter + `wallet_address`), `challenges` (**one-time use enforced by `UPDATE … WHERE consumed_at IS NULL AND expires_at > now() RETURNING *`**), `sessions` (sha256 token hash, expiry, revocation), `userop_log` (unique `userop_hash` → idempotency + audit), `ror_origins`.
- Env matrix (zod-validated): `DATABASE_URL`, `RUN_MIGRATIONS`, `RP_ID`/`RP_NAME`, `EXPECTED_ORIGINS`, `CHAIN_ID`/`RPC_URL`/`BUNDLER_URL`, `ENTRYPOINT_ADDRESS`/`FACTORY_ADDRESS` (defaulting from `gianoAddresses[CHAIN_ID]`), TTLs, userop policy caps (`USEROP_MAX_CALL_GAS`, fee caps, `USEROP_ALLOWED_TARGETS`, `USEROP_ALLOWED_PAYMASTERS`), `OPEN_REGISTRATION` (default false) + `ADMIN_API_KEYS`, `CORS_ORIGINS`.
- Routes: `/healthz`, `/readyz`, `GET /.well-known/webauthn` (DB-backed), admin ROR CRUD (bearer via `ADMIN_API_KEYS`).

### M2.2 WebAuthn ceremonies + sessions
- `POST /v1/webauthn/options` (`{externalUserId}` → challenge + known credential IDs; guarded by admin key server-to-server **or** `OPEN_REGISTRATION=true` for demos — production must bind registration to the client's own auth).
- `POST /v1/webauthn/registration/verify`: consume challenge → `verifyRegistrationResponse` (expectedOrigin/RPID from env) → derive P-256 x/y (reuse the `@peculiar/asn1-ecc` approach) → store credential → compute counterfactual wallet address (must mirror `toGianoSmartAccount`'s derivation — share a helper via the connector `/node` entry + cross-check test) → issue session (opaque 32-byte bearer, hash stored).
- `POST /v1/webauthn/authentication/verify` (counter regression rejected only when counter > 0 — passkeys often report 0), `GET /v1/me{,/credentials,/credentials/:id/public-key}`, `POST /v1/sessions/logout`. **Identity always from the session — never a userId in the URL** (fixes the demo's unauthenticated model). Rate-limit ceremony endpoints.
- *Accept:* testcontainers integration tests — challenge replay/expiry → 400, wrong origin/rpid → 400, session gates `/v1/me`.

### M2.3 UserOp relay with policy
- `POST /v1/userops` (session-authed). **EntryPoint never taken from the request body** (the demo trusted `signedUserOp.account.entryPoint.address` — a hole). Policy pipeline with per-rule audit rows: sender must match the session credential's wallet (or counterfactual); gas/fee caps; optional target allowlist (decode `callData` via `gianoSmartWalletAbi` `execute`/`executeBatch`); paymaster allowlist; server-side `getUserOperationHash` + duplicate rejection (idempotent). Forward to `BUNDLER_URL`, return `{userOperationHash}` (frontend keeps waiting for receipts — existing pattern).
- `GET /v1/userops/:hash` (log/status) **and `GET /v1/userops/:hash/receipt` (public read-only receipt lookup — required by Phase 3's thin SDK so dApps never need a bundler URL).**

### M2.4 Reference injection in the connector
- New `packages/connector/src/provider-injection/wallet-api/create-wallet-api-injection.ts`: `createWalletApiInjection({ apiUrl, externalUserId, getRegistrationGrant?, fetch? })` mapping the existing seam onto the API (`getCredentialInfo`→options, `onCredentialCreated`→registration/verify (returns `null` — no server-side wallet deployment in Phase 2), `onCredentialSignedIn`→authentication/verify, `getPublicKeyByCredentialId`→me/credentials, `onCredentialKey`→no-op, `submitUserOperation`→`/v1/userops`).
- Demo migration: replace `demo-server-injection.ts`/`ServerStorage` with the reference injection; **delete** the demo's `api/storage/**`, `api/submit-userop.ts`, `api/well-known/webauthn.ts`; keep `LocalStorage` injection as the no-backend variant. Update `README-GIANO-INJECTION.md` to present the reference injection as the default.

### M2.5 Docker, compose, OpenAPI, CI
- Multi-stage `Dockerfile` (node:22-alpine, `pnpm --filter … deploy --prod` — repo-root build context bundles the workspace dep, no registry auth needed at image build), non-root, HEALTHCHECK, migrations bundled + `node dist/migrate.js` one-shot.
- `deploy/docker-compose.reference.yml` (postgres + wallet-api, full commented env matrix — what client projects copy) and `deploy/docker-compose.dev.yml` (+ anvil + alto with env-substituted executor key).
- Committed, drift-checked `openapi/openapi.json` (R6a contract); Swagger UI in non-prod.
- CI: wallet-api job (vitest + Postgres service container + OpenAPI drift); `docker.yml` publishing to GHCR on tag.

**Phase 2 exit criteria:** clean machine `docker compose up` → healthy `/readyz`, migrations applied; demo runs register → sign-in → send-userop against wallet-api with data surviving restart; all four demo API routes deleted; no endpoint accepts unauthenticated userId; audit rows for every policy rejection; connector minor released with `createWalletApiInjection`; GHCR image published.

**Phase 2 decision notes:** dApp origin remains the RP until Phase 3 (env values change, API doesn't); opaque bearer sessions now, cookie support added with the wallet origin in Phase 3; no server-side wallet deployment (first-userop `factory/factoryData` deployment stays).

---

## Phase 3 — Dedicated wallet origin + thin SDK (removes wallet trust from client apps)

Ordered work items (P3.1 and P3.2 can start immediately, parallel to Phase 2):

- **P3.1 Extract `packages/wallet-core`** from the connector, no behavior change: move `src/provider.ts`, `src/account/**` (incl. `toGianoSmartAccount.ts`), `src/provider-injection/**`, `giano-entry-point.ts`, `giano-error.ts`. Connector temporarily re-exports everything so `services/custom-example` keeps working. While moving: replace `console.*` with a pluggable leveled logger, fix the inverted gas defaults (`provider.ts:172-173`: priority 400 gwei > max 200 gwei) by making fee estimation injectable, add vitest units for `wrapSignature`, `toReplaySafeTypedData`, userop prep. *Accept:* demo unchanged; wallet-core builds standalone; tests green.
- **P3.2 `packages/wallet-transport`**: versioned message envelope (`{giano: 1, id: ULID, type, payload}`) with `handshake`/`handshake:ack` (capability + version negotiation), `rpc`/`rpc:response` (EIP-1193 error codes, e.g. 4001 reject), `event`, `ready`, `close`. Zod validation both directions; strict `targetOrigin` + `event.origin`/`event.source` checks on both ends; wallet pins first validated dApp origin per popup. Popup opened synchronously in the user gesture as `about:blank` then navigated (Safari), ~420×640; SDK persists `{sessionId, accounts, chainId}` in `localStorage` so `eth_accounts` answers without a popup; `POPUP_BLOCKED` typed error + documented COOP caveat (dApp must not send `COOP: same-origin`). Deliverables: `TransportClient`, `TransportHost`, `PopupManager`, happy-dom two-window unit tests.
- **P3.3 `services/wallet-web`** (Vite SPA): routes `Connect`, `CreateWallet`, `SignIn`, `ReviewTransaction` (decoded calls via wallet-core `decodeCalls`, dApp-origin banner), `SignMessage` (EIP-712 tree view), `Settings` (passkeys, add owner, session revoke). `wallet/api-injection.ts` implements `GianoProviderInjection` against wallet-api — integrators never see the interface again. Runtime config from `/config.json`: `chainId`, `rpcUrl`, `factoryAddress` (defaulting from the contracts address registry), `walletApiUrl`, `allowedDappOrigins[]`, `rpId`, branding. **What moves out of the dApp:** all `navigator.credentials.*` calls, all signing paths, userop prep/submission (via wallet-api relay), consent UI. *Accept:* two-origin local flow — demo dApp connects, creates passkey wallet in popup, sends tx through consent to devnet.
- **P3.4 Slim the connector SDK** (parallel with P3.3): new `createGianoWalletProvider({walletUrl, chain, transport})`; `connector.ts` (wagmi) and `gianoWallet.ts` (RainbowKit) survive nearly unchanged atop it; read-path RPC (`eth_call`, `eth_chainId`, …) answered dApp-side without popup; `waitForUserOperationReceipt` via new public wallet-api endpoint `GET /v1/userops/:hash/receipt` (**flag to Phase 2**). Old API re-exported at `@appliedblockchain/giano-connector/embedded` with deprecation warning; publish 1.0.0 + migration guide. *Accept:* demo page using only the thin SDK; no `navigator.credentials` reachable from the default entrypoint.
- **P3.5 Security hardening**: RP ID default = wallet host, opt-in registrable domain (startup validation in wallet-api); nginx CSP `frame-ancestors 'none'` + `X-Frame-Options: DENY` (popup-only v1); zod-validate every inbound message; consent screens always show pinned dApp origin; rate limiting + challenge single-use integration test.
- **P3.6 ROR enhancement**: `/.well-known/webauthn` served on the wallet origin (proxy → wallet-api, DB-backed); docs recipe from the existing `related-origin-requests.tsx` demo; Chromium-only Playwright check.
- **P3.7 `giano-wallet-web` image** (GHCR, multi-arch) added to the reference compose stack (distinct origins, e.g. `app.localtest.me` / `wallet.localtest.me`).
- **P3.8 E2E suite** (Playwright + CDP virtual authenticator on the popup page): create-wallet/connect; session-resume without ceremony; send-tx consent approve → receipt; reject → 4001; personal_sign + typed data; hostile-origin message injection ignored; popup-blocked path; ROR well-known. Safari/Firefox: transport-only smoke behind a `GIANO_E2E_FAKE_WEBAUTHN` flag + manual checklist.

**Phase 3 exit criteria:** a dApp integrating only `@appliedblockchain/giano-connector@1.x` + a wallet URL can create a wallet, connect, sign, and send a sponsored transaction with zero WebAuthn/credential/bundler code in its bundle; E2E green in CI; security checklist audited.

## Phase 4 — Distribution ops

- **P4.1 `giano-bundler` image**: pinned `@pimlico/alto`, env-driven flags (`ALTO_RPC_URL`, `ALTO_ENTRYPOINTS` default EntryPoint v0.7, `ALTO_EXECUTOR_PRIVATE_KEYS` from secrets, `ALTO_SAFE_MODE=true` default); entrypoint refuses to start with missing keys or the well-known Anvil key unless `GIANO_DEV_MODE=true`; delete `alto-local.json`; document managed-bundler alternative. *(Pull forward into Phase 3 window — E2E stack needs it.)*
- **P4.2 `giano-contracts-deployer` one-shot job image** (`packages/contracts/Dockerfile.deployer`): Ignition deploy `--strategy create2` from env (`RPC_URL`, `CHAIN_ID`, `DEPLOYER_PRIVATE_KEY`, `DEPLOY_TESTING`, `VERIFY`), emits `/out/giano-addresses.<chainId>.json` in the registry schema, idempotent via Ignition journal; ships as Helm pre-install hook + compose `profiles: [deploy]`.
- **P4.3 `giano-devnet` image**: anvil with baked `--dump-state` (EntryPoint v0.7 from `@account-abstraction/contracts` artifacts — removing the `vendor/account-abstraction` submodule + yarn@1 flow — plus factory + testing contracts); instant-boot deterministic local chain replacing `hh:node`/`hh:initlocal`/`aa:deploy:local`. *(Pull forward too.)*
- **P4.4 Helm chart + rendered k8s reference** under `deploy/` (wallet-api + migrations job, wallet-web, optional bundler, deployer hook Job, ingress routing `/.well-known/webauthn` + `/api` → wallet-api; external Postgres by default; `existingSecret` references).
- **P4.5 Version alignment**: Changesets *fixed* mode across all packages; images + Helm `appVersion` tagged with the same semver; handshake carries `sdkVersion`, wallet-api exposes `GET /v1/version`; `COMPATIBILITY.md` with upgrade order (api → web → SDK; migrations backward-compatible one minor).
- **P4.6 CI/CD** (`.github/workflows/`): `ci.yml` (build/typecheck/vitest/forge/lint), `e2e.yml` (compose stack + Playwright), `release.yml` (tag → npm publish to GitHub Packages + buildx multi-arch GHCR push + chart/registry artifacts on the GitHub Release), `determinism.yml` (recompile with canonical settings, recompute CREATE2 addresses with salt `0xAB…AB`, fail on divergence from committed `deployed_addresses.json`).
- **P4.7 Secrets & monitoring docs**: `docs/SECRETS.md` (executor/deployer keys, DSN, rotation; "no key ever reaches wallet-web or the dApp"); pino structured logs + Prometheus metrics on wallet-api (userop relay counts/latency/policy rejections, ceremony failures); alto metrics; Helm ServiceMonitor toggle.
- **P4.8 `docs/INTEGRATION.md`**: DNS/TLS for the wallet subdomain, proxy rules + COOP caveat, env matrix per container, DB expectations, health checks, deployer run, SDK snippet, upgrade runbook.
- **P4.9 Remaining hardening**: real `ChainType`/chainId encoding in `encodeUserId`, remove dead `hh:test`, drop `services/web-outdated`.

**Phase 4 exit criteria:** clean machine runs the full stack from published GHCR images via `docker compose up` and passes E2E; `helm install giano` smoke-tests on kind; one tag push produces packages + images + chart at one version; determinism job green.

---

## Key risks

| Risk | Mitigation |
|---|---|
| Safari popup/user-activation chain | open `about:blank` synchronously in gesture, navigate after; ceremonies triggered by in-popup buttons |
| dApp COOP header severs `window.opener` | detect missing `ready` → typed error + docs (`COOP: same-origin-allow-popups` guidance) |
| RP ID choice irreversible per deployment | default = wallet host; startup validation; documented registrable-domain opt-in; decide default before GA |
| CREATE2 determinism breaks on compiler drift | D4 canonicalization + `determinism.yml` CI gate; bytecode change = major release with new registry section |
| Embedded-mode consumers broken by connector 1.0.0 | `/embedded` compat subpath + migration guide + ≥2-minor deprecation window |
| Per-client upgrade drift (no central rollout) | handshake version check + `COMPATIBILITY.md` + backward-compatible API/migration policy |

## Sequencing

```
Phase 1 (packaging) ────────────► P3.4 thin SDK
Phase 2 (wallet-api) ───────────► P3.3 / P3.5 / P3.6
P3.1 wallet-core   ─┐ (start now, parallel to Phase 2)
P3.2 transport     ─┼► P3.3 wallet-web ► P3.5 ► P3.7 ► P3.8 E2E
P3.4 thin SDK      ─┘
P4.1 bundler img / P4.3 devnet img — pull forward (E2E stack dependency)
P4.2 deployer ── after D4 ratified · P4.4 Helm ── after images exist · P4.5/P4.6 last
```

## Verification

- Per-milestone acceptance criteria above; overall: the Phase 3 exit test (thin-SDK dApp performs create/connect/sign/send with no wallet code) and the Phase 4 clean-machine compose test are the two end-to-end gates.
- CI gates: vitest units (transport protocol fuzzing, wallet-core signing), testcontainers integration (challenge single-use, session auth, relay policy), Playwright E2E with virtual authenticator across two real origins, CREATE2 determinism job.
