// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {GianoSmartWallet} from "../../src/GianoSmartWallet.sol";
import {GianoSmartWalletFactory} from "../../src/GianoSmartWalletFactory.sol";

import "./SmartWalletTestBase.sol";

contract TestImplementation is SmartWalletTestBase {
    address implementation = address(new GianoSmartWallet());

    function setUp() public override {
        super.setUp();
        GianoSmartWalletFactory factory = new GianoSmartWalletFactory(implementation);
        account = factory.createAccount(owners, 1);
    }

    function testImplementation() public {
        address addr = account.implementation();
        assertEq(addr, implementation);
    }
}
