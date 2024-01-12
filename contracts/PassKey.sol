// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import './Secp256r1.sol';
import './parsers/PassKeyParser.sol';

struct PassKeyParams {
    string publicKey;
    string signature;
    string authenticatorData;
    string clientDataJSON;
}

contract PassKey {
    error InvalidSignature(string publicKey, string signature);

    mapping(bytes32 => mapping(bytes32 => bool)) private usedSignatures;

    event SignatureVerified(bytes32 publicKeyHash, bytes32 signatureHash, bool isValid);

    modifier signatureNotUsed(string memory publicKey, string memory signature) {
        if (usedSignatures[keccak256(abi.encodePacked(publicKey))][keccak256(abi.encodePacked(signature))]) {
            revert InvalidSignature(publicKey, signature);
        }
        _;
    }

    modifier validSignature(PassKeyParams memory passkeyParams) {
        parseAndVerifyPassKeySignature(passkeyParams);
        _;
    }

    function verifyPassKeySignature(uint256 pubKeyX, uint256 pubKeyY, uint256 sigx, uint256 sigy, uint256 sigHash) public view returns (bool) {
        return Secp256r1.Verify(pubKeyX, pubKeyY, sigx, sigy, sigHash);
    }

    function parseAndVerifyPassKeySignature(PassKeyParams memory passkeyParams) public signatureNotUsed(passkeyParams.publicKey, passkeyParams.signature) {
        (uint256 pubKeyX, uint256 pubKeyY) = PassKeyParser.getPublicKeyXY(passkeyParams.publicKey);
        (uint256 sigR, uint256 sigS) = PassKeyParser.getSignatureRS(passkeyParams.signature);
        uint256 dataHash = PassKeyParser.getDataHash(passkeyParams.authenticatorData, passkeyParams.clientDataJSON);

        bool isValid = Secp256r1.Verify(pubKeyX, pubKeyY, sigR, sigS, dataHash);

        bytes32 publicKeyHash = keccak256(abi.encodePacked(passkeyParams.publicKey));
        bytes32 signatureHash = keccak256(abi.encodePacked(passkeyParams.signature));

        if (isValid) {
            usedSignatures[publicKeyHash][signatureHash] = true;
        }

        emit SignatureVerified(publicKeyHash, signatureHash, isValid);
    }
}
