// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Create2} from '@openzeppelin/contracts/utils/Create2.sol';
import {ERC1967Proxy} from '@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol';

/// @title Giano paymaster deployer
///
/// @notice Deploys the paymaster proxy and initialises it in **one transaction**.
///
/// @dev    Address stability (D10) requires the proxy's constructor arguments to carry no
///         operator-specific data, which means an *empty* initialisation payload — the usual
///         OpenZeppelin pattern of passing initialiser calldata to the proxy constructor would
///         bake the operator's own role-admin address into the init code and change the address.
///         An empty payload leaves a window between deploy and `initialize` in which anyone
///         watching the mempool could take the roles.
///
///         This contract closes that window without a custom proxy: the proxy stays a stock
///         `ERC1967Proxy`, and both steps happen in the same transaction. The proxy address
///         therefore remains a pure function of (this deployer, salt, init code), which is what
///         keeps the determinism check in CI meaningful.
contract GianoPaymasterDeployer {
    /// @notice Emitted for every proxy this deployer creates.
    event PaymasterDeployed(address indexed proxy, address indexed implementation, bytes32 salt);

    error InitialisationFailed(bytes reason);

    /// @notice CREATE2-deploys a stock `ERC1967Proxy` over `implementation` with an empty payload,
    ///         then initialises it in the same transaction.
    /// @param salt           CREATE2 salt. The repo's fixed deployment salt.
    /// @param implementation The `GianoPaymaster` implementation.
    /// @param initCalldata   ABI-encoded call to `initialize(...)`.
    /// @return proxy         The deployed proxy.
    function deploy(bytes32 salt, address implementation, bytes calldata initCalldata) external returns (address proxy) {
        proxy = Create2.deploy(0, salt, _proxyInitCode(implementation));

        (bool ok, bytes memory reason) = proxy.call(initCalldata);
        if (!ok) revert InitialisationFailed(reason);

        emit PaymasterDeployed(proxy, implementation, salt);
    }

    /// @notice The address `deploy` would produce, so deployment tooling and the determinism check
    ///         can assert it without sending a transaction.
    function predict(bytes32 salt, address implementation) external view returns (address) {
        return Create2.computeAddress(salt, keccak256(_proxyInitCode(implementation)));
    }

    function _proxyInitCode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(type(ERC1967Proxy).creationCode, abi.encode(implementation, ''));
    }
}
