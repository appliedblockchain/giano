---
'@appliedblockchain/giano-wallet-transport': minor
---

New popup transport package: versioned `{giano, id, type, payload}` envelope
(handshake/ack with version+capability negotiation, rpc/rpc:response with EIP-1193 error
codes, event, ready, close), zod validation in both directions, strict
targetOrigin/event.origin/event.source discipline with first-validated-origin pinning on
the wallet side, and a Safari-safe PopupManager (synchronous about:blank open, then
navigate) with a typed POPUP_BLOCKED error and documented COOP caveat.
