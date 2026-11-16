---
"@appliedblockchain/giano-contracts": minor
---

The bundler chain section accepts `stateOverride` (default `true`) (Silent Data, H6).

Set it to `false` for an RPC that refuses `eth_call` state overrides. The bundler then returns fixed gas limits instead of simulating. It keeps the call gas the caller sends, and a higher verification gas the caller sends.
