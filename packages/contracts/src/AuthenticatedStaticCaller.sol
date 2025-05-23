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
    error InvalidSignature();

    //TODO: Make this configurable?
    uint256 constant signatureLifetime = 30 minutes;

    function signedStaticCall(StaticCall calldata call) external view returns (bytes memory) {
        if (call.signedAt + signatureLifetime < block.timestamp) {
            revert SignatureExpired(call.signedAt + signatureLifetime, block.timestamp);
        }
        bytes32 hash = keccak256(bytes.concat(this.signedStaticCall.selector, bytes32(call.signedAt)));
        if (!_isValidSignature(hash, call.signature)) {
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
