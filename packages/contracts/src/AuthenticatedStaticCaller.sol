// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {ERC1271} from './ERC1271.sol';

struct StaticCall {
    address target;
    bytes data;
    uint256 signedAt;
    bytes signature;
}

abstract contract AuthenticatedStaticCaller is ERC1271 {
    // The names are specific to this check. `signedStaticCall` returns a target's revert data
    // unchanged, so a client can only tell these errors from a target's by their selectors.
    error StaticCallSignatureExpired(uint256 expiredAt, uint256 currentTimestamp);
    error StaticCallSignatureNotYetValid(uint256 signedAt, uint256 currentTimestamp);
    error StaticCallInvalidSignature();

    //TODO: Make this configurable?
    uint256 constant signatureLifetime = 30 minutes;

    function getSignatureLifetime() external pure returns (uint256) {
        return signatureLifetime;
    }

    /// @notice The hash an owner signs to authorise one `signedStaticCall`.
    /// @dev The hash covers the target and the calldata, so a signature authorises exactly one read.
    ///      `replaySafeHash` then binds it to this wallet and this chain.
    function staticCallHash(address target, bytes calldata data, uint256 signedAt) public pure returns (bytes32) {
        return keccak256(
            abi.encode(AuthenticatedStaticCaller.signedStaticCall.selector, signedAt, target, keccak256(data))
        );
    }

    function signedStaticCall(StaticCall calldata call) external view returns (bytes memory) {
        // A future `signedAt` would let a signature outlive `signatureLifetime`.
        if (call.signedAt > block.timestamp) {
            revert StaticCallSignatureNotYetValid(call.signedAt, block.timestamp);
        }
        if (call.signedAt + signatureLifetime < block.timestamp) {
            revert StaticCallSignatureExpired(call.signedAt + signatureLifetime, block.timestamp);
        }
        bytes32 hash = staticCallHash(call.target, call.data, call.signedAt);
        if (!_isValidSignature(replaySafeHash(hash), call.signature)) {
            revert StaticCallInvalidSignature();
        }
        (bool success, bytes memory result) = call.target.staticcall(call.data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        return result;
    }
}
