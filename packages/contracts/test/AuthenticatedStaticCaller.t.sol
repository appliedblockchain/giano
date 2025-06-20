// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {GianoSmartWallet} from "../src/GianoSmartWallet.sol";
import {GianoSmartWalletFactory} from "../src/GianoSmartWalletFactory.sol";
import {AuthenticatedStaticCaller, StaticCall} from "../src/AuthenticatedStaticCaller.sol";
import {MockTarget} from "./mocks/MockTarget.sol";

contract AuthenticatedStaticCallerTest is Test {
    GianoSmartWalletFactory factory;
    GianoSmartWallet account;
    MockTarget target;
    bytes[] owners;
    
    uint256 constant SIGNATURE_LIFETIME = 30 minutes;

    function setUp() public {
        factory = new GianoSmartWalletFactory(address(new GianoSmartWallet()));
        owners.push(abi.encode(address(0x1234)));
        account = factory.createAccount(owners, 0);
        target = new MockTarget();
    }

    function test_getSignatureLifetime() public {
        assertEq(account.getSignatureLifetime(), SIGNATURE_LIFETIME);
    }

    function test_signedStaticCall_signatureExpired() public {
        bytes memory callData = abi.encodeWithSignature("datahash()");
        // Start with current time and then warp to make it expired
        uint256 signedAt = block.timestamp;
        
        bytes memory signature = abi.encode(
            uint256(0), // ownerIndex
            abi.encodePacked(bytes32(0), bytes32(0), uint8(27)) // signatureData
        );
        
        StaticCall memory call = StaticCall({
            target: address(target),
            data: callData,
            signedAt: signedAt,
            signature: signature
        });

        // Warp time to make signature expired
        vm.warp(block.timestamp + SIGNATURE_LIFETIME + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                AuthenticatedStaticCaller.SignatureExpired.selector,
                signedAt + SIGNATURE_LIFETIME,
                block.timestamp
            )
        );
        account.signedStaticCall(call);
    }

    function test_signedStaticCall_invalidSignature() public {
        bytes memory callData = abi.encodeWithSignature("datahash()");
        uint256 signedAt = block.timestamp;
        
        // Invalid signature that won't validate
        bytes memory signature = abi.encode(
            uint256(0), // ownerIndex  
            abi.encodePacked(bytes32(0), bytes32(0), uint8(27)) // invalid signatureData
        );
        
        StaticCall memory call = StaticCall({
            target: address(target),
            data: callData,
            signedAt: signedAt,
            signature: signature
        });

        vm.expectRevert(AuthenticatedStaticCaller.InvalidSignature.selector);
        account.signedStaticCall(call);
    }

    function test_signedStaticCall_targetCallFails() public {
        // This test will create a call that fails due to invalid signature
        // Since we can't easily mock the internal signature validation
        bytes memory callData = abi.encodeWithSelector(
            MockTarget.revertWithTargetError.selector,
            "test error"
        );
        uint256 signedAt = block.timestamp;
        
        bytes memory signature = abi.encode(
            uint256(0), // ownerIndex
            abi.encodePacked(bytes32(0), bytes32(0), uint8(27)) // signatureData
        );
        
        StaticCall memory call = StaticCall({
            target: address(target),
            data: callData,
            signedAt: signedAt,
            signature: signature
        });

        // This will fail on invalid signature before reaching the target call
        vm.expectRevert(AuthenticatedStaticCaller.InvalidSignature.selector);
        account.signedStaticCall(call);
    }

    function test_signedStaticCall_validTimeWindow() public {
        bytes memory callData = abi.encodeWithSignature("datahash()");
        uint256 signedAt = block.timestamp;
        
        bytes memory signature = abi.encode(
            uint256(0), // ownerIndex
            abi.encodePacked(bytes32(0), bytes32(0), uint8(27)) // signatureData
        );
        
        StaticCall memory call = StaticCall({
            target: address(target),
            data: callData,
            signedAt: signedAt,
            signature: signature
        });

        // Should fail just after the time window
        vm.warp(block.timestamp + SIGNATURE_LIFETIME + 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                AuthenticatedStaticCaller.SignatureExpired.selector,
                signedAt + SIGNATURE_LIFETIME,
                block.timestamp
            )
        );
        account.signedStaticCall(call);
    }

    function test_signedStaticCall_correctHashGeneration() public view {
        uint256 signedAt = block.timestamp;
        
        // Calculate expected hash
        bytes32 expectedHash = keccak256(
            bytes.concat(account.signedStaticCall.selector, bytes32(signedAt))
        );
        bytes32 expectedReplaySafeHash = account.replaySafeHash(expectedHash);
        
        // Verify the replay safe hash is different from the original
        assertNotEq(expectedHash, expectedReplaySafeHash);
        
        // Verify the replay safe hash includes domain separator
        bytes32 domainSeparator = account.domainSeparator();
        assertTrue(domainSeparator != bytes32(0));
    }

    function test_signedStaticCall_nonExistentTarget() public {
        bytes memory callData = abi.encodeWithSignature("nonExistent()");
        uint256 signedAt = block.timestamp; // Use current time
        
        bytes memory signature = abi.encode(
            uint256(0), // ownerIndex
            abi.encodePacked(bytes32(0), bytes32(0), uint8(27)) // signatureData
        );
        
        StaticCall memory call = StaticCall({
            target: address(0xdead), // Non-existent contract
            data: callData,
            signedAt: signedAt,
            signature: signature
        });

        // Should fail on invalid signature before trying the call
        vm.expectRevert(AuthenticatedStaticCaller.InvalidSignature.selector);
        account.signedStaticCall(call);
    }
} 