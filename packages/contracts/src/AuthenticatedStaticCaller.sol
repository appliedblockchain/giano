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
    error SignatureExpired(uint256 expiredAt, uint256 currentTimestamp);
    error SignatureNotYetValid(uint256 signedAt, uint256 currentTimestamp);
    error InvalidSignature();

    //TODO: Make this configurable?
    uint256 constant signatureLifetime = 30 minutes;

    function getSignatureLifetime() external view returns (uint256) {
        return signatureLifetime;
    }

    /// @notice The hash an owner signs to authorise one `signedStaticCall`.
    /// @dev The hash covers the target and the calldata, so a signature authorises exactly one read.
    ///      `replaySafeHash` then binds it to this wallet and this chain.
    function staticCallHash(address target, bytes calldata data, uint256 signedAt) public view returns (bytes32) {
        return keccak256(abi.encode(this.signedStaticCall.selector, signedAt, target, keccak256(data)));
    }

    function signedStaticCall(StaticCall calldata call) external view returns (bytes memory) {
        // A future `signedAt` would let a signature outlive `signatureLifetime`.
        if (call.signedAt > block.timestamp) {
            revert SignatureNotYetValid(call.signedAt, block.timestamp);
        }
        if (call.signedAt + signatureLifetime < block.timestamp) {
            revert SignatureExpired(call.signedAt + signatureLifetime, block.timestamp);
        }
        bytes32 hash = staticCallHash(call.target, call.data, call.signedAt);
        if (!_isValidSignature(replaySafeHash(hash), call.signature)) {
            revert InvalidSignature();
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
