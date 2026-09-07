---
'@appliedblockchain/giano-wallet-kit': minor
---

New package: the wallet SDK ("the kit") — the framework-agnostic orchestration a Giano wallet
origin is built from (WALLET-SDK-REQUIREMENTS.md). One package now holds what wallet-web and the
BYO reference each re-implemented by hand: config validation, the per-chain runtimes (fee-before-
paymaster, sponsorship pre-flight, one shared wallet-api injection), the transport host with its
single-slot consent gate, and the headless wallet-management controller (chain-before-registry,
per-chain index re-reads, fingerprint recompute, the last-owner guard). A React adapter ships
behind `@appliedblockchain/giano-wallet-kit/react`; the core is framework-free. Both Giano wallet
UIs now build on it (WK-30, WK-31).
