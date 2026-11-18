// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";

import {GianoTestPrivateErc20} from "../../src/testing/GianoTestPrivateErc20.sol";
import {UCEF} from "../../lib/ucef-contracts/packages/ucef/contracts/UCEF.sol";
import {PrivateEventEmitter} from "../../lib/ucef-contracts/packages/ucef/contracts/utils/PrivateEventEmitter.sol";

contract GianoTestPrivateErc20Test is Test {
    GianoTestPrivateErc20 token;
    address holder = makeAddr("holder");
    address outsider = makeAddr("outsider");

    function setUp() public {
        token = new GianoTestPrivateErc20();
    }

    function test_holderReadsItsBalance() public {
        vm.prank(holder);
        token.mint(1000);
        vm.prank(holder);
        assertEq(token.balanceOf(holder), 1000);
    }

    function test_anotherCallerCannotReadTheBalance() public {
        vm.prank(holder);
        token.mint(1000);
        vm.expectRevert(abi.encodeWithSelector(UCEF.UCEFUnauthorizedBalanceAccess.selector, outsider, holder));
        vm.prank(outsider);
        token.balanceOf(holder);
    }

    function test_anotherCallerCannotReadAnEmptyBalance() public {
        // The revert does not depend on the balance, so it does not reveal whether one exists.
        vm.expectRevert(abi.encodeWithSelector(UCEF.UCEFUnauthorizedBalanceAccess.selector, outsider, holder));
        vm.prank(outsider);
        token.balanceOf(holder);
    }

    function test_mintIncreasesTheHoldersBalance(uint128 first, uint128 second) public {
        vm.startPrank(holder);
        token.mint(first);
        token.mint(second);
        assertEq(token.balanceOf(holder), uint256(first) + second);
        vm.stopPrank();
        assertEq(token.totalSupply(), uint256(first) + second);
    }

    function test_mintCreditsOnlyTheCaller() public {
        vm.prank(holder);
        token.mint(1000);
        vm.prank(outsider);
        assertEq(token.balanceOf(outsider), 0);
    }

    function test_transferIsAPrivateEventForTheParties() public {
        vm.prank(holder);
        token.mint(1000);

        address[] memory viewers = new address[](2);
        viewers[0] = holder;
        viewers[1] = outsider;
        vm.expectEmit(true, true, true, true, address(token));
        emit PrivateEventEmitter.PrivateEvent(viewers, token.EVENT_TYPE_TRANSFER(), abi.encode(holder, outsider, 400));
        vm.prank(holder);
        token.transfer(outsider, 400);

        vm.prank(holder);
        assertEq(token.balanceOf(holder), 600);
        vm.prank(outsider);
        assertEq(token.balanceOf(outsider), 400);
    }

    function test_allowanceIsVisibleOnlyToTheOwnerAndTheSpender() public {
        vm.prank(holder);
        token.approve(outsider, 50);
        vm.prank(holder);
        assertEq(token.allowance(holder, outsider), 50);
        vm.prank(outsider);
        assertEq(token.allowance(holder, outsider), 50);

        address third = makeAddr("third");
        vm.expectRevert(abi.encodeWithSelector(UCEF.UCEFUnauthorizedBalanceAccess.selector, third, holder));
        vm.prank(third);
        token.allowance(holder, outsider);
    }
}
