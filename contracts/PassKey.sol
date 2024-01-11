// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import './Secp256r1.sol';
import './parsers/PassKeyParser.sol';

contract PassKey {
    error InvalidSignature(string publicKey, string signature);

    address public owner;
    mapping(bytes32 => mapping(bytes32 => bool)) private usedSignatures;

    event SignatureVerified(bytes32 publicKeyHash, bytes32 signatureHash, bool isValid);

    modifier onlyOwner() {
        require(msg.sender == owner, 'Only the owner can access this function.');
        _;
    }
    modifier signatureNotUsed(string memory publicKey, string memory signature) {
        if (usedSignatures[_hashString(publicKey)][_hashString(signature)]) {
            revert InvalidSignature(publicKey, signature);
        }
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function _hashString(string memory str) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(str));
    }

    function verifyPassKeySignature(uint256 pubKeyX, uint256 pubKeyY, uint256 sigx, uint256 sigy, uint256 sigHash) public view returns (bool) {
        return Secp256r1.Verify(pubKeyX, pubKeyY, sigx, sigy, sigHash);
    }

    function parseAndVerifyPassKeySignature(
        string memory publicKey,
        string memory signature,
        string memory authenticatorData,
        string memory clientDataJSON
    ) public signatureNotUsed(publicKey, signature) {
        (uint256 pubKeyX, uint256 pubKeyY) = PassKeyParser.getPublicKeyXY(publicKey);
        (uint256 sigR, uint256 sigS) = PassKeyParser.getSignatureRS(signature);
        uint256 dataHash = PassKeyParser.getDataHash(authenticatorData, clientDataJSON);

        bool isValid = Secp256r1.Verify(pubKeyX, pubKeyY, sigR, sigS, dataHash);

        bytes32 publicKeyHash = _hashString(publicKey);
        bytes32 signatureHash = _hashString(signature);

        if (isValid) {
            usedSignatures[publicKeyHash][signatureHash] = true;
        }

        emit SignatureVerified(publicKeyHash, signatureHash, isValid);
    }
}
