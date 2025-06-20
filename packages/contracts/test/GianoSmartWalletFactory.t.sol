// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";
import {GianoSmartWallet, MultiOwnable} from "../src/GianoSmartWallet.sol";
import {GianoSmartWalletFactory} from "../src/GianoSmartWalletFactory.sol";

contract GianoSmartWalletFactoryEnrichedTest is Test {
    GianoSmartWalletFactory factory;
    GianoSmartWallet implementation;
    bytes[] owners;
    bytes[] publicKeyOwners;

    // Test addresses
    address constant ADDR_1 = address(0x1);
    address constant ADDR_2 = address(0x2);
    address constant ADDR_3 = address(0x3);

    function setUp() public {
        implementation = new GianoSmartWallet();
        factory = new GianoSmartWalletFactory(address(implementation));
        
        // Setup address owners
        owners.push(abi.encode(ADDR_1));
        owners.push(abi.encode(ADDR_2));
        
        // Setup public key owners (64 bytes each)
        publicKeyOwners.push(abi.encode(
            bytes32(uint256(1)), // x coordinate
            bytes32(uint256(2))  // y coordinate
        ));
        publicKeyOwners.push(abi.encode(
            bytes32(uint256(3)), // x coordinate
            bytes32(uint256(4))  // y coordinate
        ));
    }

    function test_constructor_setsImplementation() public {
        address testImplementation = address(0x123);
        GianoSmartWalletFactory testFactory = new GianoSmartWalletFactory(testImplementation);
        assertEq(testFactory.implementation(), testImplementation);
    }

    function test_constructor_withZeroImplementation() public {
        // Should be able to create factory with zero implementation
        GianoSmartWalletFactory testFactory = new GianoSmartWalletFactory(address(0));
        assertEq(testFactory.implementation(), address(0));
    }

    function test_createAccount_setsOwnersCorrectly() public {
        address expectedAddress = factory.getAddress(owners, 0);
        vm.expectCall(expectedAddress, abi.encodeCall(GianoSmartWallet.initialize, (owners)));
        
        GianoSmartWallet account = factory.createAccount{value: 1e18}(owners, 0);
        
        assertTrue(account.isOwnerAddress(ADDR_1));
        assertTrue(account.isOwnerAddress(ADDR_2));
        assertEq(address(account).balance, 1e18);
    }

    function test_createAccount_withPublicKeyOwners() public {
        GianoSmartWallet account = factory.createAccount(publicKeyOwners, 0);
        
        assertTrue(account.isOwnerPublicKey(bytes32(uint256(1)), bytes32(uint256(2))));
        assertTrue(account.isOwnerPublicKey(bytes32(uint256(3)), bytes32(uint256(4))));
    }

    function test_createAccount_withMixedOwners() public {
        bytes[] memory mixedOwners = new bytes[](3);
        mixedOwners[0] = abi.encode(ADDR_1); // Address owner
        mixedOwners[1] = abi.encode(
            bytes32(uint256(1)), // Public key owner
            bytes32(uint256(2))
        );
        mixedOwners[2] = abi.encode(ADDR_2); // Another address owner

        GianoSmartWallet account = factory.createAccount(mixedOwners, 0);
        
        assertTrue(account.isOwnerAddress(ADDR_1));
        assertTrue(account.isOwnerAddress(ADDR_2));
        assertTrue(account.isOwnerPublicKey(bytes32(uint256(1)), bytes32(uint256(2))));
    }

    function test_createAccount_revertsIfNoOwners() public {
        bytes[] memory emptyOwners = new bytes[](0);
        
        vm.expectRevert(GianoSmartWalletFactory.OwnerRequired.selector);
        factory.createAccount(emptyOwners, 0);
    }

    function test_createAccount_revertsIfLength32ButLargerThanAddress() public {
        bytes[] memory badOwners = new bytes[](1);
        badOwners[0] = abi.encode(uint256(type(uint160).max) + 1);
        
        vm.expectRevert(
            abi.encodeWithSelector(MultiOwnable.InvalidEthereumAddressOwner.selector, badOwners[0])
        );
        factory.createAccount(badOwners, 0);
    }

    function test_createAccount_revertsIfInvalidLength() public {
        bytes[] memory badOwners = new bytes[](1);
        // Create manually invalid length bytes (not 32 or 64 bytes)
        badOwners[0] = hex"1234"; // 2 bytes - invalid length
        
        vm.expectRevert(
            abi.encodeWithSelector(MultiOwnable.InvalidOwnerBytesLength.selector, badOwners[0])
        );
        factory.createAccount(badOwners, 0);
    }

    function test_createAccount_deploysToPredeterminedAddress() public {
        address predictedAddress = factory.getAddress(owners, 0);
        GianoSmartWallet account = factory.createAccount(owners, 0);
        
        assertEq(address(account), predictedAddress);
    }

    function test_createAccount_returnsExistingAccountIfAlreadyDeployed() public {
        GianoSmartWallet firstAccount = factory.createAccount(owners, 0);
        
        // Second call should return same account and not call initialize again
        vm.expectCall(address(firstAccount), abi.encodeCall(GianoSmartWallet.initialize, (owners)), 0);
        GianoSmartWallet secondAccount = factory.createAccount(owners, 0);
        
        assertEq(address(firstAccount), address(secondAccount));
    }

    function test_createAccount_withDifferentNonces() public {
        GianoSmartWallet account1 = factory.createAccount(owners, 0);
        GianoSmartWallet account2 = factory.createAccount(owners, 1);
        GianoSmartWallet account3 = factory.createAccount(owners, 2);
        
        // All should be different addresses
        assertTrue(address(account1) != address(account2));
        assertTrue(address(account1) != address(account3));
        assertTrue(address(account2) != address(account3));
        
        // But all should have the same owners
        assertTrue(account1.isOwnerAddress(ADDR_1));
        assertTrue(account2.isOwnerAddress(ADDR_1));
        assertTrue(account3.isOwnerAddress(ADDR_1));
    }

    function test_createAccount_passesValueCorrectly() public {
        uint256 value = 5 ether;
        vm.deal(address(this), value);
        
        GianoSmartWallet account = factory.createAccount{value: value}(owners, 0);
        
        assertEq(address(account).balance, value);
    }

    function test_getAddress_returnsConsistentAddress() public {
        address predicted1 = factory.getAddress(owners, 0);
        address predicted2 = factory.getAddress(owners, 0);
        
        assertEq(predicted1, predicted2);
    }

    function test_getAddress_differentForDifferentOwners() public {
        bytes[] memory differentOwners = new bytes[](1);
        differentOwners[0] = abi.encode(ADDR_3);
        
        address addr1 = factory.getAddress(owners, 0);
        address addr2 = factory.getAddress(differentOwners, 0);
        
        assertTrue(addr1 != addr2);
    }

    function test_getAddress_differentForDifferentNonces() public {
        address addr1 = factory.getAddress(owners, 0);
        address addr2 = factory.getAddress(owners, 1);
        
        assertTrue(addr1 != addr2);
    }

    function test_implementation_returnsCorrectAddress() public {
        assertEq(factory.implementation(), address(implementation));
    }

    function test_initCodeHash_returnsCorrectHash() public {
        bytes32 expectedHash = LibClone.initCodeHashERC1967(address(implementation));
        bytes32 actualHash = factory.initCodeHash();
        
        assertEq(actualHash, expectedHash);
    }

    function test_initCodeHash_consistentAcrossCalls() public {
        bytes32 hash1 = factory.initCodeHash();
        bytes32 hash2 = factory.initCodeHash();
        
        assertEq(hash1, hash2);
    }

    function test_getSalt_internal() public {
        // Test the internal salt calculation by comparing getAddress results
        address addr1 = factory.getAddress(owners, 0);
        
        // Change owners order and check salt changes
        bytes[] memory reorderedOwners = new bytes[](2);
        reorderedOwners[0] = owners[1];
        reorderedOwners[1] = owners[0];
        
        address addr2 = factory.getAddress(reorderedOwners, 0);
        
        assertTrue(addr1 != addr2); // Different salt should produce different address
    }

    function test_createAccount_withSingleOwner() public {
        bytes[] memory singleOwner = new bytes[](1);
        singleOwner[0] = abi.encode(ADDR_1);
        
        GianoSmartWallet account = factory.createAccount(singleOwner, 0);
        
        assertTrue(account.isOwnerAddress(ADDR_1));
        assertEq(account.ownerCount(), 1);
    }

    function test_createAccount_withMaxUint256Nonce() public {
        GianoSmartWallet account = factory.createAccount(owners, type(uint256).max);
        
        assertTrue(account.isOwnerAddress(ADDR_1));
        assertTrue(account.isOwnerAddress(ADDR_2));
    }

    function test_createAccount_multipleWithSameParameters() public {
        // First deployment
        GianoSmartWallet account1 = factory.createAccount(owners, 0);
        
        // Second deployment with same parameters should return same account
        GianoSmartWallet account2 = factory.createAccount(owners, 0);
        
        assertEq(address(account1), address(account2));
    }

    function test_fuzz_createAccount(bytes[] memory fuzzOwners, uint256 nonce) public {
        // Filter invalid inputs
        vm.assume(fuzzOwners.length > 0);
        vm.assume(fuzzOwners.length <= 5); // Reasonable limit for fuzzing
        
        bool allValid = true;
        // Check for duplicates and valid format
        for (uint256 i = 0; i < fuzzOwners.length; i++) {
            if (fuzzOwners[i].length != 32 && fuzzOwners[i].length != 64) {
                allValid = false;
                break;
            }
            if (fuzzOwners[i].length == 32) {
                uint256 val = uint256(bytes32(fuzzOwners[i]));
                if (val > type(uint160).max) {
                    allValid = false;
                    break;
                }
            }
            // Check for duplicates (which would cause AlreadyOwner error)
            for (uint256 j = i + 1; j < fuzzOwners.length; j++) {
                if (keccak256(fuzzOwners[i]) == keccak256(fuzzOwners[j])) {
                    allValid = false;
                    break;
                }
            }
            if (!allValid) break;
        }
        
        vm.assume(allValid);
        
        // Should not revert with valid inputs
        address predicted = factory.getAddress(fuzzOwners, nonce);
        GianoSmartWallet account = factory.createAccount(fuzzOwners, nonce);
        
        assertEq(address(account), predicted);
    }

    function test_fuzz_getAddress(bytes[] memory fuzzOwners, uint256 nonce) public {
        // Filter invalid inputs
        vm.assume(fuzzOwners.length > 0);
        vm.assume(fuzzOwners.length <= 10);
        
        // Should never revert
        address addr = factory.getAddress(fuzzOwners, nonce);
        assertTrue(addr != address(0)); // Should never return zero address
    }

    function test_gas_createAccount() public {
        uint256 gasBefore = gasleft();
        factory.createAccount(owners, 0);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should use reasonable amount of gas (adjust threshold as needed)
        assertTrue(gasUsed < 500000); // 500k gas limit
    }

    function test_gas_getAddress() public {
        uint256 gasBefore = gasleft();
        factory.getAddress(owners, 0);
        uint256 gasUsed = gasBefore - gasleft();
        
        // Should be very cheap operation (adjusted for actual gas usage)
        assertTrue(gasUsed < 30000); // 30k gas limit
    }
} 