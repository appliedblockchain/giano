// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title P256
 * @author Giano Team
 * @notice Helper library for verifying P256 (secp256r1) signatures in Solidity
 * @dev Uses the EIP-7212 precompile for efficient signature verification
 */
library P256 {
    // Official address of the P256 verification precompile (EIP-7212)
    address constant VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;

    /**
     * @notice Verifies a P256 signature without checking for signature malleability
     * @dev Uses the EIP-7212 precompile to perform signature verification
     * @param message_hash The hash of the message that was signed
     * @param r The r component of the signature
     * @param s The s component of the signature 
     * @param x The x coordinate of the public key
     * @param y The y coordinate of the public key
     * @return True if the signature is valid
     */
    function verifySignatureAllowMalleability(
        bytes32 message_hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool) {
        bytes memory args = abi.encode(message_hash, r, s, x, y);
        (bool success, bytes memory ret) = VERIFIER.staticcall(args);
        assert(success); // never reverts, always returns 0 or 1

        return abi.decode(ret, (uint256)) == 1;
    }

    /// P256 curve order n/2 for malleability check
    uint256 constant P256_N_DIV_2 =
    57896044605178124381348723474703786764998477612067880171211129530534256022184;

    /**
     * @notice Verifies a P256 signature with malleability check
     * @dev Checks that s <= n/2 (where n is the curve order) before verifying the signature
     * @param message_hash The hash of the message that was signed
     * @param r The r component of the signature
     * @param s The s component of the signature
     * @param x The x coordinate of the public key
     * @param y The y coordinate of the public key
     * @return True if the signature is valid and has low s value
     */
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
