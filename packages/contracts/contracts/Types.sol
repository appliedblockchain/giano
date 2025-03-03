// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

library Types {
    struct Signature {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 challengeLocation;
        uint256 responseTypeLocation;
        uint256 r;
        uint256 s;
        PublicKey publicKey;
    }
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }
    struct SignedCall {
        Call call;
        bytes signature;
    }
    struct PublicKey {
        bytes32 x;
        bytes32 y;
    }

}
