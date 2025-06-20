// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {CredentialKeyMapper} from "../src/CredentialKeyMapper.sol";

contract CredentialKeyMapperTest is Test {
    CredentialKeyMapper credentialMapper;
    
    // Test constants
    bytes32 constant TEST_ID_HASH = keccak256("test-credential-id");
    bytes32 constant TEST_ID_HASH_2 = keccak256("test-credential-id-2");
    bytes32 constant TEST_X = bytes32(uint256(1));
    bytes32 constant TEST_Y = bytes32(uint256(2));
    bytes32 constant TEST_X_2 = bytes32(uint256(3));
    bytes32 constant TEST_Y_2 = bytes32(uint256(4));

    function setUp() public {
        credentialMapper = new CredentialKeyMapper();
    }

    function test_setCredentialKey_success() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: TEST_X,
            y: TEST_Y
        });

        credentialMapper.setCredentialKey(TEST_ID_HASH, key);

        CredentialKeyMapper.PublicKey memory retrievedKey = credentialMapper.getCredentialKey(TEST_ID_HASH);
        assertEq(retrievedKey.x, TEST_X);
        assertEq(retrievedKey.y, TEST_Y);
    }

    function test_setCredentialKey_revertsOnDuplicateId() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: TEST_X,
            y: TEST_Y
        });

        // Set the credential key first time
        credentialMapper.setCredentialKey(TEST_ID_HASH, key);

        // Try to set again - should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                CredentialKeyMapper.CredentialIdAlreadySet.selector,
                TEST_ID_HASH
            )
        );
        credentialMapper.setCredentialKey(TEST_ID_HASH, key);
    }

    function test_setCredentialKey_revertsOnEmptyCredentialId() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: TEST_X,
            y: TEST_Y
        });

        // Should revert when trying to set a credential with empty (zero) ID
        vm.expectRevert(CredentialKeyMapper.EmptyCredentialId.selector);
        credentialMapper.setCredentialKey(bytes32(0), key);
    }

    function test_setCredentialKey_revertsOnInvalidKeyX() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: bytes32(0), // Invalid X coordinate
            y: TEST_Y
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                CredentialKeyMapper.InvalidKey.selector,
                bytes32(0),
                TEST_Y
            )
        );
        credentialMapper.setCredentialKey(TEST_ID_HASH, key);
    }

    function test_setCredentialKey_revertsOnInvalidKeyY() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: TEST_X,
            y: bytes32(0) // Invalid Y coordinate
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                CredentialKeyMapper.InvalidKey.selector,
                TEST_X,
                bytes32(0)
            )
        );
        credentialMapper.setCredentialKey(TEST_ID_HASH, key);
    }

    function test_setCredentialKey_revertsOnBothInvalidCoordinates() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: bytes32(0),
            y: bytes32(0)
        });

        vm.expectRevert(
            abi.encodeWithSelector(
                CredentialKeyMapper.InvalidKey.selector,
                bytes32(0),
                bytes32(0)
            )
        );
        credentialMapper.setCredentialKey(TEST_ID_HASH, key);
    }

    function test_getCredentialKey_returnsZeroForNonExistentKey() public {
        CredentialKeyMapper.PublicKey memory retrievedKey = credentialMapper.getCredentialKey(TEST_ID_HASH);
        assertEq(retrievedKey.x, bytes32(0));
        assertEq(retrievedKey.y, bytes32(0));
    }

    function test_getCredentialKey_returnsCorrectKey() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: TEST_X,
            y: TEST_Y
        });

        credentialMapper.setCredentialKey(TEST_ID_HASH, key);

        CredentialKeyMapper.PublicKey memory retrievedKey = credentialMapper.getCredentialKey(TEST_ID_HASH);
        assertEq(retrievedKey.x, TEST_X);
        assertEq(retrievedKey.y, TEST_Y);
    }

    function test_multipleCredentials() public {
        CredentialKeyMapper.PublicKey memory key1 = CredentialKeyMapper.PublicKey({
            x: TEST_X,
            y: TEST_Y
        });
        
        CredentialKeyMapper.PublicKey memory key2 = CredentialKeyMapper.PublicKey({
            x: TEST_X_2,
            y: TEST_Y_2
        });

        // Set multiple credentials
        credentialMapper.setCredentialKey(TEST_ID_HASH, key1);
        credentialMapper.setCredentialKey(TEST_ID_HASH_2, key2);

        // Verify both are stored correctly
        CredentialKeyMapper.PublicKey memory retrievedKey1 = credentialMapper.getCredentialKey(TEST_ID_HASH);
        CredentialKeyMapper.PublicKey memory retrievedKey2 = credentialMapper.getCredentialKey(TEST_ID_HASH_2);
        
        assertEq(retrievedKey1.x, TEST_X);
        assertEq(retrievedKey1.y, TEST_Y);
        assertEq(retrievedKey2.x, TEST_X_2);
        assertEq(retrievedKey2.y, TEST_Y_2);
    }

    // Note: removeCredentialKey tests require valid WebAuthn signatures
    // which are complex to generate in tests. The following test shows
    // the expected behavior but uses mock data that will fail signature validation.
    function test_removeCredentialKey_revertsOnInvalidSignature() public {
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: TEST_X,
            y: TEST_Y
        });

        // Set the credential key first
        credentialMapper.setCredentialKey(TEST_ID_HASH, key);

        // Try to remove with invalid signature - this will revert due to signature validation
        bytes memory invalidSignature = abi.encode(
            abi.encode(bytes("invalid"), bytes("signature"), bytes("data"))
        );

        // This will fail during WebAuthn.verify call
        vm.expectRevert();
        credentialMapper.removeCredentialKey(TEST_ID_HASH, invalidSignature);
    }

    function test_removeCredentialKey_revertsOnNonExistentKey() public {
        bytes memory signature = abi.encode(
            abi.encode(bytes("mock"), bytes("signature"), bytes("data"))
        );

        // This will fail because the key doesn't exist (x and y are both 0)
        vm.expectRevert();
        credentialMapper.removeCredentialKey(TEST_ID_HASH, signature);
    }

    function test_edgeCaseMaxValues() public {
        bytes32 maxValue = bytes32(type(uint256).max);
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: maxValue,
            y: maxValue
        });

        credentialMapper.setCredentialKey(TEST_ID_HASH, key);

        CredentialKeyMapper.PublicKey memory retrievedKey = credentialMapper.getCredentialKey(TEST_ID_HASH);
        assertEq(retrievedKey.x, maxValue);
        assertEq(retrievedKey.y, maxValue);
    }

    function test_edgeCaseMinValidValues() public {
        bytes32 minValue = bytes32(uint256(1));
        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: minValue,
            y: minValue
        });

        credentialMapper.setCredentialKey(TEST_ID_HASH, key);

        CredentialKeyMapper.PublicKey memory retrievedKey = credentialMapper.getCredentialKey(TEST_ID_HASH);
        assertEq(retrievedKey.x, minValue);
        assertEq(retrievedKey.y, minValue);
    }

    function test_fuzzSetAndGetCredentialKey(bytes32 idHash, bytes32 x, bytes32 y) public {
        // Skip invalid inputs
        vm.assume(idHash != bytes32(0));
        vm.assume(x != bytes32(0));
        vm.assume(y != bytes32(0));

        CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
            x: x,
            y: y
        });

        credentialMapper.setCredentialKey(idHash, key);

        CredentialKeyMapper.PublicKey memory retrievedKey = credentialMapper.getCredentialKey(idHash);
        assertEq(retrievedKey.x, x);
        assertEq(retrievedKey.y, y);
    }

    function test_fuzzRevertOnInvalidInputs(bytes32 idHash, bytes32 x, bytes32 y) public {
        // Test cases where at least one input is invalid
        bool invalidId = idHash == bytes32(0);
        bool invalidX = x == bytes32(0);
        bool invalidY = y == bytes32(0);
        
        // If any are invalid, the call should revert
        if (invalidId || invalidX || invalidY) {
            CredentialKeyMapper.PublicKey memory key = CredentialKeyMapper.PublicKey({
                x: x,
                y: y
            });

            vm.expectRevert();
            credentialMapper.setCredentialKey(idHash, key);
        }
    }
} 