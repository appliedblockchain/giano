// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import '../Base64.sol';

library Asn1Parser {
    error InvalidFormat();

    function _validateFieldLength(bytes memory field) private pure {
        uint8 numberOfMetadataBytes = 2; // sequence1 Tag and Length
        // field[0] is the Tag
        // field[1] is the Length
        if (field.length < numberOfMetadataBytes || field.length != uint8(field[1]) + numberOfMetadataBytes) {
            revert InvalidFormat();
        }
    }

    function _DERInteger(bytes memory integer, uint256 expectedLength) private pure returns (bytes memory) {
        if (integer.length == expectedLength) {
            return integer;
        }

        bytes memory newInteger = new bytes(expectedLength);

        if (integer.length < expectedLength) {
            uint256 numberOfMissingBytes = expectedLength - integer.length;
            for (uint8 i = 0; i < numberOfMissingBytes; i++) {
                newInteger[i] = 0x00;
            }
            for (uint8 i = 0; i < integer.length; i++) {
                newInteger[i + numberOfMissingBytes] = integer[i];
            }
            return newInteger;
        }

        uint256 numberOfExtraBytes = integer.length - expectedLength;
        for (uint8 i = 0; i < expectedLength; i++) {
            newInteger[i] = integer[i + numberOfExtraBytes];
        }

        return newInteger;
    }

    function parsePublicKey(string memory publicKey) internal pure returns (bytes memory, bytes memory, bytes memory) {
        bytes memory publicKeyBytes = Base64.decode(publicKey);
        _validateFieldLength(publicKeyBytes);
        // sequence1 Tag
        uint8 count = 0;
        count++;
        // sequence1 Length
        count++;
        // sequence2 Tag
        count++;
        // sequence2 Length
        count++;
        // objectIdentifier1 Tag
        count++;
        // objectIdentifier1 Length
        uint8 objectIdentifier1Len = uint8(publicKeyBytes[count]);
        count++;
        bytes memory objectIdentifier1 = new bytes(objectIdentifier1Len);
        for (uint8 i = 0; i < objectIdentifier1Len; i++) {
            objectIdentifier1[i] = publicKeyBytes[count];
            count++;
        }
        // objectIdentifier2 Tag
        count++;
        // objectIdentifier2 Length
        uint8 objectIdentifier2Len = uint8(publicKeyBytes[count]);
        count++;
        bytes memory objectIdentifier2 = new bytes(objectIdentifier2Len);
        for (uint8 i = 0; i < objectIdentifier2Len; i++) {
            objectIdentifier2[i] = publicKeyBytes[count];
            count++;
        }
        // bitString Tag
        count++;
        // bitString Length
        uint8 bitStringLen = uint8(publicKeyBytes[count]);
        count++;
        // number of padding bits (0)
        count++;
        // bitString length also includes the number of padding bits
        uint8 publicKeyLen = bitStringLen - 1;
        bytes memory parsedPublicKeyBytes = new bytes(publicKeyLen);
        for (uint8 i = 0; i < publicKeyLen; i++) {
            parsedPublicKeyBytes[i] = publicKeyBytes[count];
            count++;
        }

        return (objectIdentifier1, objectIdentifier2, parsedPublicKeyBytes);
    }

    function parseSignature(string memory signature) internal pure returns (bytes memory, bytes memory) {
        bytes memory signatureBytes = Base64.decode(signature);
        _validateFieldLength(signatureBytes);
        // sequence1 Tag
        uint8 count = 0;
        count++;
        // sequence1 Length
        count++;
        // integer1 Tag
        count++;
        // integer1 Length
        uint8 integer1Len = uint8(signatureBytes[count]);
        count++;

        bytes memory integer1 = new bytes(integer1Len);
        for (uint8 i = 0; i < integer1Len; i++) {
            integer1[i] = signatureBytes[count];
            count++;
        }
        // integer2 Tag
        count++;
        // integer2 Length
        uint8 integer2Len = uint8(signatureBytes[count]);
        count++;

        bytes memory integer2 = new bytes(integer2Len);
        for (uint8 i = 0; i < integer2Len; i++) {
            integer2[i] = signatureBytes[count];
            count++;
        }

        integer1 = _DERInteger(integer1, 32);
        integer2 = _DERInteger(integer2, 32);

        return (integer1, integer2);
    }
}
