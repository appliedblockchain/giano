// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import './Secp256r1.sol';

contract PassKey {
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, 'Only the owner can access this function.');
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function verifyPassKeySignature(uint256 pubKeyX, uint256 pubKeyY, uint256 sigx, uint256 sigy, uint256 sigHash) public view returns (bool) {
        return Secp256r1.Verify(pubKeyX, pubKeyY, sigx, sigy, sigHash);
    }
}
