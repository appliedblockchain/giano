// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;
import {console} from "hardhat/console.sol";
/**
 * Helper library for external contracts to verify P256 signatures.
 **/
library P256 {
    // official address of the precompile contract
    address constant VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    function verifySignatureAllowMalleability(
        bytes32 message_hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        console.log("VSAM start");
        bytes memory args = abi.encode(message_hash, r, s, x, y);
        console.log("VSAM encoded args");
        (bool success, bytes memory ret) = VERIFIER.staticcall(args);
        console.log("VSAM call result");
        assert(success); //never reverts, always returns 0 or 1
        console.log("asserted");
        bool isValid = abi.decode(ret, (uint256)) == 1;
        console.log("isValid");
        console.log(isValid);
        return isValid;
    }

    /// P256 curve order n/2 for malleability check
    uint256 constant P256_N_DIV_2 =
    57896044605178124381348723474703786764998477612067880171211129530534256022184;

    function verifySignature(
        bytes32 message_hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        // check for signature malleability
        if (s > P256_N_DIV_2) {
            return false;
        }

        return verifySignatureAllowMalleability(message_hash, r, s, x, y);
    }
}
