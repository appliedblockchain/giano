// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import {GianoSmartWallet} from "../src/GianoSmartWallet.sol";
import {GianoSmartWalletFactory} from "../src/GianoSmartWalletFactory.sol";
import {ERC1271InputGenerator} from "../src/utils/ERC1271InputGenerator.sol";

contract GianoSmartWallet1271InputGeneratorTest is Test {
    GianoSmartWalletFactory factory;
    GianoSmartWallet implementation;
    GianoSmartWallet deployedAccount;
    bytes[] owners;

    function setUp() public {
        implementation = new GianoSmartWallet();
        factory = new GianoSmartWalletFactory(address(implementation));
    }

    function testGetReplaySafeHashForDeployedAccount() public {
        owners.push(abi.encode(address(1)));
        deployedAccount = GianoSmartWallet(payable(factory.createAccount(owners, 0)));

        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        bytes32 replaySafeHash = deployedAccount.replaySafeHash(hash);
        ERC1271InputGenerator generator = new ERC1271InputGenerator(deployedAccount, hash, address(0), "");
        assertEq(bytes32(address(generator).code), replaySafeHash);
    }

    function testGetReplaySafeHashForUndeployedAccount() public {
        owners.push(abi.encode(address(1)));
        GianoSmartWallet undeployedAccount = GianoSmartWallet(payable(factory.getAddress(owners, 0)));
        bytes32 hash = 0x15fa6f8c855db1dccbb8a42eef3a7b83f11d29758e84aed37312527165d5eec5;
        ERC1271InputGenerator generator = new ERC1271InputGenerator(
            undeployedAccount,
            hash,
            address(factory),
            abi.encodeWithSignature("createAccount(bytes[],uint256)", owners, 0)
        );

        // This is now deployed.
        bytes32 replaySafeHash = undeployedAccount.replaySafeHash(hash);

        assertEq(bytes32(address(generator).code), replaySafeHash);
    }
}
