// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccessControl} from '@openzeppelin/contracts/access/IAccessControl.sol';
import {TimelockController} from '@openzeppelin/contracts/governance/TimelockController.sol';
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';
import {GianoTimelock} from '../../src/paymaster/GianoTimelock.sol';

/// @dev Stands in for a Safe: a contract account that relays whatever its owner tells it to. The
///      timelock must work with a proposer that is not an EOA (G9 R3).
contract SafeLike {
    address internal immutable owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function exec(address target, bytes calldata data) external returns (bytes memory) {
        require(msg.sender == owner, 'not owner');
        (bool ok, bytes memory result) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        return result;
    }
}

/// @notice G9: the paymaster's timelocked operations, each with its own delay.
contract TimelockTest is PaymasterTestBase {
    uint256 internal constant MIN_DELAY = 1 hours;
    uint256 internal constant UPGRADE_DELAY = 7 days;
    uint256 internal constant ROLE_DELAY = 7 days;
    uint256 internal constant WITHDRAW_ADDRESS_DELAY = 3 days;
    uint256 internal constant DEFAULT_FEE_DELAY = 2 days;
    uint256 internal constant TENANT_FEE_DELAY = 1 days;

    GianoTimelock internal timelock;
    SafeLike internal safe;
    address internal safeOwner = makeAddr('safeOwner');

    function setUp() public override {
        super.setUp();
        safe = new SafeLike(safeOwner);

        address pm = address(paymaster);
        GianoTimelock.FunctionDelay[] memory delays = new GianoTimelock.FunctionDelay[](7);
        delays[0] = GianoTimelock.FunctionDelay(pm, UUPSUpgradeable.upgradeToAndCall.selector, UPGRADE_DELAY);
        delays[1] = GianoTimelock.FunctionDelay(pm, IAccessControl.grantRole.selector, ROLE_DELAY);
        delays[2] = GianoTimelock.FunctionDelay(pm, IAccessControl.revokeRole.selector, ROLE_DELAY);
        delays[3] = GianoTimelock.FunctionDelay(pm, IAccessControl.renounceRole.selector, ROLE_DELAY);
        delays[4] = GianoTimelock.FunctionDelay(pm, GianoPaymaster.setTenantWithdrawAddress.selector, WITHDRAW_ADDRESS_DELAY);
        delays[5] = GianoTimelock.FunctionDelay(pm, GianoPaymaster.setDefaultFee.selector, DEFAULT_FEE_DELAY);
        delays[6] = GianoTimelock.FunctionDelay(pm, GianoPaymaster.setTenantFee.selector, TENANT_FEE_DELAY);

        address[] memory proposers = new address[](1);
        proposers[0] = address(safe);
        address[] memory executors = new address[](1);
        executors[0] = address(0); // anyone may execute a ready operation
        timelock = new GianoTimelock(MIN_DELAY, proposers, executors, delays);

        // The hand-off a deployment performs: the timelock takes every timelocked role and the
        // bootstrap holders give theirs up. The immediate roles stay on their operational keys.
        vm.startPrank(roleAdmin);
        paymaster.grantRole(paymaster.UPGRADER_ROLE(), address(timelock));
        paymaster.grantRole(paymaster.FEE_ADMIN_ROLE(), address(timelock));
        paymaster.grantRole(paymaster.WITHDRAW_ADDRESS_ADMIN_ROLE(), address(timelock));
        paymaster.grantRole(paymaster.ROLE_ADMIN(), address(timelock));
        paymaster.revokeRole(paymaster.UPGRADER_ROLE(), upgrader);
        paymaster.revokeRole(paymaster.FEE_ADMIN_ROLE(), feeAdmin);
        paymaster.revokeRole(paymaster.WITHDRAW_ADDRESS_ADMIN_ROLE(), withdrawAddressAdmin);
        paymaster.renounceRole(paymaster.ROLE_ADMIN(), roleAdmin);
        vm.stopPrank();
    }

    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    function _schedule(address target, bytes memory data, uint256 delay) internal returns (bytes32 id) {
        vm.prank(safeOwner);
        safe.exec(address(timelock), abi.encodeCall(TimelockController.schedule, (target, 0, data, bytes32(0), bytes32(0), delay)));
        id = timelock.hashOperation(target, 0, data, bytes32(0), bytes32(0));
    }

    function _expectScheduleRejected(address target, bytes memory data, uint256 delay, uint256 required) internal {
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockInsufficientDelay.selector, delay, required));
        vm.prank(safeOwner);
        safe.exec(address(timelock), abi.encodeCall(TimelockController.schedule, (target, 0, data, bytes32(0), bytes32(0), delay)));
    }

    function _execute(address target, bytes memory data) internal {
        timelock.execute(target, 0, data, bytes32(0), bytes32(0));
    }

    /// @dev Schedules `data` with exactly its delay, shows it cannot run a second early, then runs it.
    function _scheduleWaitExecute(address target, bytes memory data, uint256 delay) internal {
        bytes32 id = _schedule(target, data, delay);
        vm.warp(block.timestamp + delay - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TimelockController.TimelockUnexpectedOperationState.selector,
                id,
                bytes32(1 << uint8(TimelockController.OperationState.Ready))
            )
        );
        _execute(target, data);
        vm.warp(block.timestamp + 1);
        _execute(target, data);
        assertTrue(timelock.isOperationDone(id));
    }

    // -----------------------------------------------------------------------------------------
    // Topology after the hand-off
    // -----------------------------------------------------------------------------------------

    function test_theTimelockIsTheOnlyHolderOfEveryTimelockedRole() public view {
        bytes32[4] memory roles = [
            paymaster.ROLE_ADMIN(),
            paymaster.UPGRADER_ROLE(),
            paymaster.FEE_ADMIN_ROLE(),
            paymaster.WITHDRAW_ADDRESS_ADMIN_ROLE()
        ];
        for (uint256 i = 0; i < roles.length; i++) {
            assertEq(paymaster.getRoleMemberCount(roles[i]), 1);
            assertEq(paymaster.getRoleMember(roles[i], 0), address(timelock));
        }
    }

    /// @dev Passing `address(0)` as admin upstream leaves the timelock administering only itself.
    function test_theTimelockHasNoAdminButItself() public view {
        bytes32 admin = timelock.DEFAULT_ADMIN_ROLE();
        assertTrue(timelock.hasRole(admin, address(timelock)));
        assertFalse(timelock.hasRole(admin, address(this)));
        assertFalse(timelock.hasRole(admin, address(safe)));
        assertTrue(timelock.hasRole(timelock.PROPOSER_ROLE(), address(safe)));
        assertTrue(timelock.hasRole(timelock.CANCELLER_ROLE(), address(safe)));
    }

    /// @dev The decisions: signers, parameters, unpause and stake stay immediate on their own keys.
    function test_theImmediateOperationsStayImmediate() public {
        address newSigner = makeAddr('newSigner');
        vm.prank(signerAdmin);
        paymaster.addSigner(newSigner);
        vm.prank(signerAdmin);
        paymaster.removeSigner(newSigner);

        vm.prank(paramAdmin);
        paymaster.setPostOpGasAllowance(50_000);
        vm.prank(paramAdmin);
        paymaster.setPenaltyBps(2000);

        vm.prank(pauser);
        paymaster.pause();
        vm.prank(pauser);
        paymaster.unpause();

        vm.deal(stakeAdmin, 1 ether);
        vm.prank(stakeAdmin);
        paymaster.addStake{value: 1 ether}(1 days);
        vm.prank(stakeAdmin);
        paymaster.unlockStake();

        vm.prank(tenantAdmin);
        paymaster.registerTenant(bytes16(uint128(0xC0FFEE)), makeAddr('c'), 'tenant-c');
    }

    function test_theBootstrapHoldersLostTheTimelockedPowers() public {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, feeAdmin, paymaster.FEE_ADMIN_ROLE()));
        vm.prank(feeAdmin);
        paymaster.setDefaultFee(1);

        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                withdrawAddressAdmin,
                paymaster.WITHDRAW_ADDRESS_ADMIN_ROLE()
            )
        );
        vm.prank(withdrawAddressAdmin);
        paymaster.setTenantWithdrawAddress(TENANT_A, withdrawAddressAdmin);

        bytes32 pauserRole = paymaster.PAUSER_ROLE();
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, roleAdmin, paymaster.ROLE_ADMIN()));
        vm.prank(roleAdmin);
        paymaster.grantRole(pauserRole, roleAdmin);
    }

    // -----------------------------------------------------------------------------------------
    // Each timelocked operation waits its own delay
    // -----------------------------------------------------------------------------------------

    function test_theDelaysAreIndependent() public view {
        address pm = address(paymaster);
        assertEq(timelock.getEffectiveDelay(pm, UUPSUpgradeable.upgradeToAndCall.selector), UPGRADE_DELAY);
        assertEq(timelock.getEffectiveDelay(pm, IAccessControl.grantRole.selector), ROLE_DELAY);
        assertEq(timelock.getEffectiveDelay(pm, GianoPaymaster.setTenantWithdrawAddress.selector), WITHDRAW_ADDRESS_DELAY);
        assertEq(timelock.getEffectiveDelay(pm, GianoPaymaster.setDefaultFee.selector), DEFAULT_FEE_DELAY);
        assertEq(timelock.getEffectiveDelay(pm, GianoPaymaster.setTenantFee.selector), TENANT_FEE_DELAY);
    }

    function test_setDefaultFeeWaitsItsOwnDelay() public {
        bytes memory data = abi.encodeCall(GianoPaymaster.setDefaultFee, (1 gwei));
        _expectScheduleRejected(address(paymaster), data, DEFAULT_FEE_DELAY - 1, DEFAULT_FEE_DELAY);
        _scheduleWaitExecute(address(paymaster), data, DEFAULT_FEE_DELAY);
        assertEq(paymaster.defaultFeeWei(), 1 gwei);
    }

    function test_setTenantFeeWaitsItsOwnDelay() public {
        bytes memory data = abi.encodeCall(GianoPaymaster.setTenantFee, (TENANT_A, true, 7));
        _expectScheduleRejected(address(paymaster), data, TENANT_FEE_DELAY - 1, TENANT_FEE_DELAY);
        _scheduleWaitExecute(address(paymaster), data, TENANT_FEE_DELAY);
        assertEq(paymaster.feeFor(TENANT_A), 7);
    }

    function test_setTenantWithdrawAddressWaitsItsOwnDelay() public {
        address newExit = makeAddr('newExit');
        bytes memory data = abi.encodeCall(GianoPaymaster.setTenantWithdrawAddress, (TENANT_A, newExit));
        _expectScheduleRejected(address(paymaster), data, WITHDRAW_ADDRESS_DELAY - 1, WITHDRAW_ADDRESS_DELAY);

        _fund(TENANT_A, 1 ether);
        bytes32 id = _schedule(address(paymaster), data, WITHDRAW_ADDRESS_DELAY);

        // The point of the delay: the tenant sees the change coming and leaves first.
        assertTrue(timelock.isOperationPending(id));
        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 1 ether, tenantAWithdraw);
        assertEq(tenantAWithdraw.balance, 1 ether);

        vm.warp(block.timestamp + WITHDRAW_ADDRESS_DELAY);
        _execute(address(paymaster), data);
        assertEq(paymaster.getTenant(TENANT_A).withdrawAddress, newExit);
    }

    function test_anUpgradeWaitsItsOwnDelay() public {
        GianoPaymaster next = new GianoPaymaster();
        bytes memory data = abi.encodeCall(UUPSUpgradeable.upgradeToAndCall, (address(next), ''));
        _expectScheduleRejected(address(paymaster), data, UPGRADE_DELAY - 1, UPGRADE_DELAY);
        _scheduleWaitExecute(address(paymaster), data, UPGRADE_DELAY);
        bytes32 slot = vm.load(address(paymaster), 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc);
        assertEq(address(uint160(uint256(slot))), address(next));
    }

    /// @dev Granting a timelocked role to an EOA would bypass that role's delay from then on, so a
    ///      grant must wait at least as long as the longest delay it could skip.
    function test_aRoleGrantWaitsTheRoleDelay() public {
        bytes memory data = abi.encodeCall(IAccessControl.grantRole, (paymaster.UPGRADER_ROLE(), outsider));
        _expectScheduleRejected(address(paymaster), data, ROLE_DELAY - 1, ROLE_DELAY);
        _scheduleWaitExecute(address(paymaster), data, ROLE_DELAY);
        assertTrue(paymaster.hasRole(paymaster.UPGRADER_ROLE(), outsider));
    }

    function test_anUnconfiguredCallWaitsTheMinimumDelay() public {
        // The timelock holds no role this needs, so it reverts on execution — but scheduling is
        // what the delay governs, and it falls back to minDelay.
        bytes memory data = abi.encodeCall(GianoPaymaster.setPenaltyBps, (1));
        assertEq(timelock.getDelay(address(paymaster), data), MIN_DELAY);
        _expectScheduleRejected(address(paymaster), data, MIN_DELAY - 1, MIN_DELAY);
        _schedule(address(paymaster), data, MIN_DELAY);
    }

    function test_aCallWithoutASelectorWaitsTheMinimumDelay() public view {
        assertEq(timelock.getDelay(address(paymaster), hex'00'), MIN_DELAY);
        assertEq(timelock.getDelay(address(paymaster), ''), MIN_DELAY);
    }

    /// @dev A batch cannot launder a long delay through a short one.
    function test_aBatchWaitsItsLongestDelay() public {
        address[] memory targets = new address[](2);
        targets[0] = address(paymaster);
        targets[1] = address(paymaster);
        uint256[] memory values = new uint256[](2);
        bytes[] memory payloads = new bytes[](2);
        payloads[0] = abi.encodeCall(GianoPaymaster.setTenantFee, (TENANT_A, true, 7));
        payloads[1] = abi.encodeCall(GianoPaymaster.setDefaultFee, (1 gwei));

        assertEq(timelock.getBatchDelay(targets, payloads), DEFAULT_FEE_DELAY);

        vm.expectRevert(
            abi.encodeWithSelector(TimelockController.TimelockInsufficientDelay.selector, TENANT_FEE_DELAY, DEFAULT_FEE_DELAY)
        );
        vm.prank(safeOwner);
        safe.exec(
            address(timelock),
            abi.encodeCall(TimelockController.scheduleBatch, (targets, values, payloads, bytes32(0), bytes32(0), TENANT_FEE_DELAY))
        );

        vm.prank(safeOwner);
        safe.exec(
            address(timelock),
            abi.encodeCall(TimelockController.scheduleBatch, (targets, values, payloads, bytes32(0), bytes32(0), DEFAULT_FEE_DELAY))
        );
        vm.warp(block.timestamp + DEFAULT_FEE_DELAY);
        timelock.executeBatch(targets, values, payloads, bytes32(0), bytes32(0));
        assertEq(paymaster.defaultFeeWei(), 1 gwei);
        assertEq(paymaster.feeFor(TENANT_A), 7);
    }

    // -----------------------------------------------------------------------------------------
    // Changing a delay is timelocked by the delay it changes
    // -----------------------------------------------------------------------------------------

    function test_onlyTheTimelockCanSetAFunctionDelay() public {
        vm.expectRevert(abi.encodeWithSelector(TimelockController.TimelockUnauthorizedCaller.selector, safeOwner));
        vm.prank(safeOwner);
        timelock.setFunctionDelay(address(paymaster), GianoPaymaster.setDefaultFee.selector, 0);
    }

    /// @dev Otherwise a proposer could shorten the upgrade delay after only the minimum delay and
    ///      then upgrade quickly — every delay would be as short as the shortest.
    function test_shorteningADelayWaitsTheDelayBeingShortened() public {
        bytes4 upgrade = UUPSUpgradeable.upgradeToAndCall.selector;
        bytes memory data = abi.encodeCall(GianoTimelock.setFunctionDelay, (address(paymaster), upgrade, 1 hours));
        assertEq(timelock.getDelay(address(timelock), data), UPGRADE_DELAY);
        _expectScheduleRejected(address(timelock), data, MIN_DELAY, UPGRADE_DELAY);

        _scheduleWaitExecute(address(timelock), data, UPGRADE_DELAY);
        assertEq(timelock.getEffectiveDelay(address(paymaster), upgrade), 1 hours);
    }

    function test_lengtheningADelayAlsoWaitsTheCurrentDelay() public {
        bytes4 fee = GianoPaymaster.setTenantFee.selector;
        bytes memory data = abi.encodeCall(GianoTimelock.setFunctionDelay, (address(paymaster), fee, 30 days));
        _scheduleWaitExecute(address(timelock), data, TENANT_FEE_DELAY);
        assertEq(timelock.getFunctionDelay(address(paymaster), fee), 30 days);
    }

    function test_clearingADelayFallsBackToTheMinimum() public {
        bytes4 fee = GianoPaymaster.setTenantFee.selector;
        bytes memory data = abi.encodeCall(GianoTimelock.setFunctionDelay, (address(paymaster), fee, 0));
        _scheduleWaitExecute(address(timelock), data, TENANT_FEE_DELAY);
        assertEq(timelock.getFunctionDelay(address(paymaster), fee), 0);
        assertEq(timelock.getEffectiveDelay(address(paymaster), fee), MIN_DELAY);
    }

    /// @dev The floor still governs: raising minDelay lifts every function below it.
    function test_minDelayIsTheFloorForEveryFunction() public {
        bytes memory data = abi.encodeCall(TimelockController.updateDelay, (10 days));
        _expectScheduleRejected(address(timelock), data, MIN_DELAY - 1, MIN_DELAY);
        _scheduleWaitExecute(address(timelock), data, MIN_DELAY);

        assertEq(timelock.getEffectiveDelay(address(paymaster), GianoPaymaster.setTenantFee.selector), 10 days);
        assertEq(timelock.getEffectiveDelay(address(paymaster), UUPSUpgradeable.upgradeToAndCall.selector), 10 days);
    }

    function test_theConstructorEmitsEachInitialDelay() public {
        GianoTimelock.FunctionDelay[] memory delays = new GianoTimelock.FunctionDelay[](1);
        delays[0] = GianoTimelock.FunctionDelay(address(paymaster), GianoPaymaster.setDefaultFee.selector, 5 days);
        vm.expectEmit(true, true, false, true);
        emit GianoTimelock.FunctionDelayChange(address(paymaster), GianoPaymaster.setDefaultFee.selector, 0, 5 days);
        new GianoTimelock(MIN_DELAY, new address[](0), new address[](0), delays);
    }

    // -----------------------------------------------------------------------------------------
    // Proposers and cancellation
    // -----------------------------------------------------------------------------------------

    function test_onlyAProposerCanSchedule() public {
        bytes memory data = abi.encodeCall(GianoPaymaster.setDefaultFee, (1));
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, safeOwner, timelock.PROPOSER_ROLE())
        );
        vm.prank(safeOwner);
        timelock.schedule(address(paymaster), 0, data, bytes32(0), bytes32(0), DEFAULT_FEE_DELAY);
    }

    function test_theProposerCanCancelAPendingOperation() public {
        bytes memory data = abi.encodeCall(GianoPaymaster.setDefaultFee, (1));
        bytes32 id = _schedule(address(paymaster), data, DEFAULT_FEE_DELAY);
        vm.prank(safeOwner);
        safe.exec(address(timelock), abi.encodeCall(TimelockController.cancel, (id)));
        assertFalse(timelock.isOperation(id));
    }
}
