// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {UCEFOwned} from "../../vendor/ucef/UCEFOwned.sol";

/// @title GianoTestPrivateErc20
/// @notice Test fixture for chains whose RPC enforces private reads (Silent Data). Only the holder
///         can read its balance; any other caller reverts with `UCEFUnauthorizedBalanceAccess`.
///         Transfer and approval events are `PrivateEvent` logs that only the parties can see.
/// @dev Anyone can mint to themselves. Deployed by `deploy:cli testing` under
///      `giano.test.private-erc20`, never on a production chain (R-29). On a public chain the
///      privacy is not enforced: anyone can read storage and calldata.
contract GianoTestPrivateErc20 is UCEFOwned {
    constructor() UCEFOwned("Giano Test Private Token", "GTPT") {}

    /// @notice Mints `amount` to the caller.
    function mint(uint256 amount) external {
        _mint(msg.sender, amount);
    }

    /// @dev Minting is open: the token is a test fixture with no value.
    function _authorizeMint(address, uint256) internal pure override {}
}
