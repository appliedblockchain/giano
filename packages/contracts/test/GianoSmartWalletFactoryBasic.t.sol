// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {LibClone} from "solady/utils/LibClone.sol";

import {GianoSmartWallet, MultiOwnable} from "../src/GianoSmartWallet.sol";
import {GianoSmartWalletFactory} from "../src/GianoSmartWalletFactory.sol";

contract GianoSmartWalletFactoryBasicTest is Test {
    GianoSmartWalletFactory factory;
    GianoSmartWallet account;
    bytes[] owners;

    function setUp() public {
        account = new GianoSmartWallet();
        factory = new GianoSmartWalletFactory(address(account));
        owners.push(abi.encode(address(1)));
        owners.push(abi.encode(address(2)));
    }

    function test_constructor_setsImplementation(address implementation) public {
        factory = new GianoSmartWalletFactory(implementation);
        assertEq(factory.implementation(), implementation);
    }

    function test_createAccountSetsOwnersCorrectly() public {
        address expectedAddress = factory.getAddress(owners, 0);
        vm.expectCall(expectedAddress, abi.encodeCall(GianoSmartWallet.initialize, (owners)));
        GianoSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        assert(a.isOwnerAddress(address(1)));
        assert(a.isOwnerAddress(address(2)));
    }

    function test_revertsIfNoOwners() public {
        owners.pop();
        owners.pop();
        vm.expectRevert(GianoSmartWalletFactory.OwnerRequired.selector);
        factory.createAccount{value: 1e18}(owners, 0);
    }

    function test_exitIfAccountIsAlreadyInitialized() public {
        GianoSmartWallet a = factory.createAccount(owners, 0);
        vm.expectCall(address(a), abi.encodeCall(GianoSmartWallet.initialize, (owners)), 0);
        GianoSmartWallet a2 = factory.createAccount(owners, 0);
        assertEq(address(a), address(a2));
    }

    function test_RevertsIfLength32ButLargerThanAddress() public {
        bytes memory badOwner = abi.encode(uint256(type(uint160).max) + 1);
        owners.push(badOwner);
        vm.expectRevert(abi.encodeWithSelector(MultiOwnable.InvalidEthereumAddressOwner.selector, badOwner));
        factory.createAccount{value: 1e18}(owners, 0);
    }

    function test_createAccountDeploysToPredeterminedAddress() public {
        address p = factory.getAddress(owners, 0);
        GianoSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(address(a), p);
    }

    function test_CreateAccount_ReturnsPredeterminedAddress_WhenAccountAlreadyExists() public {
        address p = factory.getAddress(owners, 0);
        GianoSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        GianoSmartWallet b = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(address(a), p);
        assertEq(address(a), address(b));
    }

    function testDeployDeterministicPassValues() public {
        vm.deal(address(this), 1e18);
        GianoSmartWallet a = factory.createAccount{value: 1e18}(owners, 0);
        assertEq(address(a).balance, 1e18);
    }

    function test_implementation_returnsExpectedAddress() public {
        assertEq(factory.implementation(), address(account));
    }

    function test_initCodeHash() public {
        bytes32 execptedHash = LibClone.initCodeHashERC1967(address(account));
        bytes32 factoryHash = factory.initCodeHash();
        assertEq(factoryHash, execptedHash);
    }
}
