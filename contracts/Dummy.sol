// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import './PassKey.sol';
import './AccessControl.sol';

contract Dummy is PassKey, AccessControl {
    bytes32 public constant ANY_ROLE = keccak256('ANY_ROLE');

    address public owner;

    constructor(string memory accessControlAdminPublicKey) {
        owner = msg.sender;
        _grantRole(DEFAULT_ADMIN_ROLE, accessControlAdminPublicKey, '');
    }

    function anyFunction(PassKeyParams memory passKeyParams) public validSignature(passKeyParams) onlyRole(ANY_ROLE, passKeyParams.publicKey) returns (bool) {
        return true;
    }
}
