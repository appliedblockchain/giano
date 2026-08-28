// The canonical contract addresses — explicitly frozen constants, NOT "whatever some
// reference chain happens to have" (specs/MULTICHAIN_SPECS.md §4.2, S13; MC-19).
//
// One passkey resolves to one smart-account address on every served chain only when the
// factory and the implementation sit at these exact addresses there. A chain whose factory
// is anywhere else — or whose factory sits here but was built from different sources — must
// not be admitted to a deployment's served list. Deployments verify this at configuration
// load (fatal), and repeatably via `giano-doctor chain`.
//
// Frozen from the v1.1.0 contracts build (solc 0.8.28, optimizer runs 200, viaIR, evm
// "paris", CREATE2 salt 0xAB…AB against the Arachnid deterministic-deployment proxy, and
// EntryPoint v0.7 at its canonical address — the implementation hardcodes it, so a chain
// carrying a different EntryPoint produces different bytecode and different addresses for
// everything downstream, MC-141). Any change to the compiler identity or to the contract
// sources is an address-breaking change to the whole deployment (MC-26): it must produce a
// NEW canonical freeze, never a silent re-baseline.

/** GianoSmartWalletFactory at its canonical CREATE2 address. */
export const CANONICAL_FACTORY = '0x26dCd29390eba3B22BcCbd2143989E5994Ac7050' as const;

/** GianoSmartWallet implementation the canonical factory clones. */
export const CANONICAL_IMPLEMENTATION = '0x15cC758f7D3188c2361f6141CEaa9Ab2792bea56' as const;

/**
 * The account nonce Giano derives every user's address with. Part of the CREATE2 salt, so
 * it must be identical on every chain (MC-21) — it is simply always zero.
 */
export const CANONICAL_ACCOUNT_NONCE = 0n;
