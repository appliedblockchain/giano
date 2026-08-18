// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import '@openzeppelin/contracts/token/ERC20/ERC20.sol';
import '@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol';

/**
 * @title TestERC20
 * @notice A deliberately trivial ERC-20 for the demo and e2e stacks. It has no access control and
 *         no initial supply: anyone may `mint` tokens to any address, and anyone may `burn` (or
 *         `burnFrom`, via allowance) tokens they hold. It is a faucet token for exercising the
 *         wallet's contract-call path — not a model of a real token.
 * @dev Testing-only. `scripts/generate-addresses.ts` refuses to record it on a production chain.
 */
contract TestERC20 is ERC20, ERC20Burnable {
    constructor() ERC20('Giano Test Token', 'GTT') {}

    /// @notice Mint `amount` base units to `to`. Unrestricted by design — this is a faucet.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
