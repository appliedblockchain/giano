/**
 * Values that off-chain code shares with `GianoPaymaster`. A forge test
 * (`test/GianoPaymaster/Validation.t.sol`) reads this file and fails if a value here differs from the
 * contract's.
 */

/**
 * The smallest `paymasterPostOpGasLimit` that `GianoPaymaster` validation accepts, from the release
 * that added `MIN_POST_OP_GAS_LIMIT`. The tenant is charged only in `postOp`, so a smaller limit lets
 * the operation run while the shared deposit pays and the tenant pays nothing. A sponsorship service
 * must not sign a smaller limit: the authorisation covers it, so that check also protects
 * paymasters deployed before the contract enforced the floor.
 */
export const PAYMASTER_MIN_POST_OP_GAS_LIMIT = 100_000n;
