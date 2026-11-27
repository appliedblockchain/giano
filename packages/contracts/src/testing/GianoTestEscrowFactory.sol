// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

/// @title GianoTestEscrowFactory
/// @notice Test fixture for apps that deploy a contract at run time for every payment: an escrow,
///         deployed as an EIP-1167 minimal proxy (a clone) of one implementation. The e2e suite uses it
///         to test sponsorship rules for contracts that did not exist when the tenant configured
///         sponsorship.
/// @dev Anyone can create an escrow, and the factory keeps no record of what it deployed: it only emits
///      `EscrowCloneCreated`. An escrow's address is predictable (`predictEscrowAddress`), so a tenant
///      can allow it before it exists. The salt is bound to the caller, so nobody else can deploy at an
///      address predicted for a caller. Deployed by the e2e suite itself, never on a production chain.
contract GianoTestEscrowFactory {
    /// @notice The escrow every clone delegates to. Storage, not immutable: a fixture artifact has none.
    address public implementation;

    event EscrowCloneCreated(address indexed escrow, address indexed payer, bytes32 salt);

    constructor() {
        implementation = address(new GianoTestEscrow());
    }

    /// @notice Deploys an escrow with the caller as its payer, at `predictEscrowAddress(msg.sender, salt)`.
    function createEscrow(bytes32 salt) external returns (address escrow) {
        escrow = Clones.cloneDeterministic(implementation, _saltFor(msg.sender, salt));
        GianoTestEscrow(escrow).initialize(msg.sender);
        emit EscrowCloneCreated(escrow, msg.sender, salt);
    }

    /// @notice The address `createEscrow(salt)` deploys to when `payer` calls it.
    function predictEscrowAddress(address payer, bytes32 salt) external view returns (address) {
        return Clones.predictDeterministicAddress(implementation, _saltFor(payer, salt));
    }

    function _saltFor(address payer, bytes32 salt) private pure returns (bytes32) {
        return keccak256(abi.encode(payer, salt));
    }
}

/// @title GianoTestEscrow
/// @notice An escrow between a payer and the parties that confirm it. It holds no funds: the fixture
///         tests which calls are sponsored, not payments.
contract GianoTestEscrow {
    address public payer;
    bool public released;
    mapping(address => bool) public confirmed;

    event Confirmed(address indexed party);
    event Released();

    error AlreadyInitialized();
    error NotThePayer(address account);

    /// @notice Sets the payer, once. The factory calls it in the same transaction that deploys the clone.
    function initialize(address payer_) external {
        if (payer != address(0)) revert AlreadyInitialized();
        payer = payer_;
    }

    /// @notice Records that the caller confirms the escrow. Open to anyone.
    function confirm() external {
        confirmed[msg.sender] = true;
        emit Confirmed(msg.sender);
    }

    /// @notice Releases the escrow. Only the payer can.
    function release() external {
        if (msg.sender != payer) revert NotThePayer(msg.sender);
        released = true;
        emit Released();
    }
}
