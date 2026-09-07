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
// "paris", CREATE2 salt 0xAB…AB through CreateX at 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed
// — the factory Hardhat Ignition's `create2` strategy uses; NOT the Arachnid
// deterministic-deployment proxy, which this repo uses only for the P-256 verifier
// (scripts/p256_deploy.ts) — and EntryPoint v0.7 at its canonical address: the wallet
// implementation hardcodes it, so a chain carrying a different EntryPoint produces different
// bytecode and different addresses for everything downstream, MC-141). Any change to the
// compiler identity or to the contract sources is an address-breaking change to the whole
// deployment (MC-26): it must produce a NEW canonical freeze, never a silent re-baseline.
//
// CreateX derives its salt as keccak256(abi.encode(salt)) for a salt whose leading 20 bytes are
// neither the sender nor the zero address, which is the shape of 0xAB…AB — no chain id and no
// deployer EOA enter the address. That is what makes these constants chain- and
// operator-independent rather than merely "the same so far".

/** GianoSmartWalletFactory at its canonical CREATE2 address. */
export const CANONICAL_FACTORY = '0x26dCd29390eba3B22BcCbd2143989E5994Ac7050' as const;

/** GianoSmartWallet implementation the canonical factory clones. */
export const CANONICAL_IMPLEMENTATION = '0x15cC758f7D3188c2361f6141CEaa9Ab2792bea56' as const;

/**
 * The account nonce Giano derives every user's address with. Part of the CREATE2 salt, so
 * it must be identical on every chain (MC-21) — it is simply always zero.
 */
export const CANONICAL_ACCOUNT_NONCE = 0n;

/**
 * The production sponsorship paymaster proxy — the address tenants send funding to and the one
 * a dApp names in `paymasterAndData`.
 *
 * Frozen for the same reason as the factory, but the mechanism is different and worth stating.
 * The proxy is a stock `ERC1967Proxy` deployed by {@link CANONICAL_PAYMASTER_DEPLOYER} with an
 * *empty* initialisation payload, so nothing operator-specific — role admin, fees, gas allowance
 * — reaches its init code; `GianoPaymasterDeployer.deploy` initialises it in the same
 * transaction instead. Two operators deploying this build therefore land on this same address.
 *
 * The implementation *is* in the proxy's init code, so this address moves with any change to
 * {@link CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION}'s bytecode. Upgrading a live proxy
 * through UUPS keeps the address; re-deploying a modified build from genesis does not, and is a
 * new canonical freeze.
 */
export const CANONICAL_SPONSORSHIP_PAYMASTER = '0xf98b56de62ce88cEb70A9155582248cDBf2D0718' as const;

/**
 * The `GianoPaymaster` implementation {@link CANONICAL_SPONSORSHIP_PAYMASTER} delegates to at
 * the freeze. Unlike the proxy, this is expected to change on every upgrade — it is frozen so
 * that a *fresh* deployment can be checked against the build this freeze came from.
 */
export const CANONICAL_SPONSORSHIP_PAYMASTER_IMPLEMENTATION = '0xFc6e7a0b9b5E9E27C8E2caf8961A13FD16ebd818' as const;

/**
 * `GianoPaymasterDeployer`, the CREATE2 deployer the paymaster proxy hangs off. Recorded because
 * the proxy address is a pure function of (this deployer, salt 0xAB…AB, proxy init code): anyone
 * can recompute {@link CANONICAL_SPONSORSHIP_PAYMASTER} from these three without trusting a
 * deployment journal.
 */
export const CANONICAL_PAYMASTER_DEPLOYER = '0xD90a7Ec5724DA9f30D3224Eb68d39B2790b36b09' as const;
