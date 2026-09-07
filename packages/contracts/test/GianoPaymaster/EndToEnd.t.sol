// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from 'forge-std/Vm.sol';
import {console2} from 'forge-std/Test.sol';
import {PackedUserOperation} from '@account-abstraction/contracts/interfaces/PackedUserOperation.sol';
import {IEntryPoint} from '@account-abstraction/contracts/interfaces/IEntryPoint.sol';

import {PaymasterTestBase} from './PaymasterTestBase.sol';
import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';
import {GianoSmartWallet} from '../../src/GianoSmartWallet.sol';
import {MockGianoSmartWallet} from '../mocks/MockGianoSmartWallet.sol';
import {MockTarget} from '../mocks/MockTarget.sol';

/// @dev The whole sponsored path against the real EntryPoint: a real account, a real bundler call,
///      real deposit accounting.
///
///      This is the only place the accounting invariant is genuinely under test. Settlement unit
///      tests debit the ledger while the deposit sits still, so they cannot tell an over-generous
///      overhead allowance from an under-generous one. Here the EntryPoint really does charge the
///      deposit for `postOp`'s own gas and for its penalty on unused gas limits, so the assertion
///      that the ledger fell at least as far as the deposit means something.
contract EndToEndTest is PaymasterTestBase {
    MockGianoSmartWallet internal account;
    MockTarget internal target;

    uint256 internal ownerKey = 0xa11ce;
    address internal owner = vm.addr(0xa11ce);
    address payable internal beneficiary = payable(makeAddr('bundlerBeneficiary'));

    function setUp() public override {
        super.setUp();

        account = new MockGianoSmartWallet();
        bytes[] memory owners = new bytes[](1);
        owners[0] = abi.encode(owner);
        account.initialize(owners);

        target = new MockTarget();

        _fund(TENANT_A, 1 ether);
        _stake();
    }

    // -----------------------------------------------------------------------------------------

    function test_aSponsoredTransactionLandsAndTheTenantPaysForIt() public {
        uint256 depositBefore = ENTRY_POINT.balanceOf(address(paymaster));
        uint256 balanceBefore = paymaster.getTenant(TENANT_A).balance;

        vm.recordLogs();
        _runSponsoredOp(_defaultOpParams(address(account)));
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // the user's transaction actually executed
        assertEq(target.datahash(), keccak256(hex'c0ffee'));

        (uint256 gasCostWei, uint256 feeWei, uint256 overheadWei, uint256 newBalance, bool success) = _sponsoredEvent(logs);
        assertTrue(success, 'the sponsored call succeeded');
        assertEq(feeWei, DEFAULT_FEE_WEI, 'the pinned fee was charged in full');
        assertGt(gasCostWei, 0);
        assertGt(overheadWei, 0);

        assertEq(newBalance, balanceBefore - gasCostWei - feeWei - overheadWei, 'balance = gas + fee + overhead');
        assertEq(paymaster.getTenant(TENANT_A).balance, newBalance);
        assertEq(paymaster.treasury(), DEFAULT_FEE_WEI, 'the fee, and only the fee, reached the treasury');
        assertEq(paymaster.getTenant(TENANT_A).deficit, 0, 'no deficit on a well-funded tenant');

        // D1's direction: the ledger must fall at least as fast as the deposit.
        uint256 depositDrop = depositBefore - ENTRY_POINT.balanceOf(address(paymaster));
        uint256 ledgerDrop = balanceBefore - (paymaster.getTenant(TENANT_A).balance + paymaster.treasury());
        assertGe(ledgerDrop, depositDrop, 'the ledger must not fall slower than the deposit');
        _assertInvariant();
    }

    /// @dev The slack this leaves behind is the calibration signal §8.4 monitors: it must be
    ///      positive (never insolvent) but not absurd (tenants would be overcharged).
    function test_theOverheadAllowanceCoversTheDepositCostsTheContractCannotSee() public {
        uint256 depositBefore = ENTRY_POINT.balanceOf(address(paymaster));
        uint256 ledgerBefore = paymaster.getTenant(TENANT_A).balance + paymaster.treasury();

        _runSponsoredOp(_defaultOpParams(address(account)));

        uint256 depositDrop = depositBefore - ENTRY_POINT.balanceOf(address(paymaster));
        uint256 ledgerDrop = ledgerBefore - (paymaster.getTenant(TENANT_A).balance + paymaster.treasury());
        uint256 slack = ledgerDrop - depositDrop;

        console2.log('deposit drop', depositDrop);
        console2.log('ledger  drop', ledgerDrop);
        console2.log('slack       ', slack);
        assertGt(slack, 0, 'the allowance must err generous');
        assertLt(slack, depositDrop, 'but not by more than the whole cost of the operation');
    }

    /// @dev A client that grossly over-estimates `callGasLimit` is exactly the case a flat overhead
    ///      figure under-covers, because the EntryPoint's penalty scales with the over-estimate
    ///      (O2). The bound derived from the op's own limits has to hold here too.
    function test_theAllowanceStillCoversAGrosslyOverEstimatedCallGasLimit() public {
        OpParams memory p = _defaultOpParams(address(account));
        p.callGasLimit = 3_000_000; // the call needs a tiny fraction of this
        p.pmPostOpGasLimit = 300_000;

        uint256 depositBefore = ENTRY_POINT.balanceOf(address(paymaster));
        uint256 ledgerBefore = paymaster.getTenant(TENANT_A).balance + paymaster.treasury();

        _runSponsoredOp(p);

        uint256 depositDrop = depositBefore - ENTRY_POINT.balanceOf(address(paymaster));
        uint256 ledgerDrop = ledgerBefore - (paymaster.getTenant(TENANT_A).balance + paymaster.treasury());
        assertGe(ledgerDrop, depositDrop, 'the penalty on wasted gas must still be covered');
        _assertInvariant();
    }

    function test_theSameAuthorisationCannotBeUsedTwice() public {
        OpParams memory p = _defaultOpParams(address(account));
        _runSponsoredOp(p);

        // The nonce is spent, and the authorisation is bound to it, so a replay fails at the
        // EntryPoint before the paymaster is even consulted.
        PackedUserOperation memory op = _signedSponsoredOp(p, TENANT_A, uint48(block.timestamp + 300), 0, DEFAULT_FEE_WEI);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert();
        ENTRY_POINT.handleOps(ops, beneficiary);
    }

    function test_anExpiredAuthorisationIsRejectedOnChainAndNothingIsCharged() public {
        OpParams memory p = _defaultOpParams(address(account));
        PackedUserOperation memory op = _signedSponsoredOp(p, TENANT_A, uint48(block.timestamp + 60), 0, DEFAULT_FEE_WEI);

        vm.warp(block.timestamp + 120);

        uint256 balanceBefore = paymaster.getTenant(TENANT_A).balance;
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert(); // AA32 expired or not due
        ENTRY_POINT.handleOps(ops, beneficiary);
        assertEq(paymaster.getTenant(TENANT_A).balance, balanceBefore, 'nothing debited');
    }

    function test_anAuthorisationUsedBeforeItsWindowIsRejected() public {
        OpParams memory p = _defaultOpParams(address(account));
        PackedUserOperation memory op = _signedSponsoredOp(
            p,
            TENANT_A,
            uint48(block.timestamp + 3600),
            uint48(block.timestamp + 1800),
            DEFAULT_FEE_WEI
        );

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert();
        ENTRY_POINT.handleOps(ops, beneficiary);
    }

    /// @dev R-40: a reverting user transaction still consumed real gas the deposit paid for, and
    ///      still consumed the service.
    function test_aRevertingUserTransactionIsStillChargedGasAndFee() public {
        OpParams memory p = _defaultOpParams(address(account));
        p.callData = abi.encodeCall(
            GianoSmartWallet.execute,
            (address(target), 0, abi.encodeCall(MockTarget.revertWithTargetError, (hex'dead')))
        );

        vm.recordLogs();
        _runSponsoredOp(p);
        (uint256 gasCostWei, uint256 feeWei, , , bool success) = _sponsoredEvent(vm.getRecordedLogs());

        assertFalse(success, 'the inner call reverted');
        assertGt(gasCostWei, 0);
        assertEq(feeWei, DEFAULT_FEE_WEI);
        assertEq(paymaster.treasury(), DEFAULT_FEE_WEI);
        _assertInvariant();
    }

    /// @dev R-31, enforced by the chain rather than by the backend: the operation names the tenant
    ///      it bills, and no other tenant's balance moves.
    function test_oneTenantsTransactionNeverTouchesAnotherTenantsBalance() public {
        _fund(TENANT_B, 1 ether);
        uint256 bBefore = paymaster.getTenant(TENANT_B).balance;

        _runSponsoredOp(_defaultOpParams(address(account)));

        assertEq(paymaster.getTenant(TENANT_B).balance, bBefore, "tenant B's balance is untouched");
        assertLt(paymaster.getTenant(TENANT_A).balance, 1 ether);
    }

    function test_aPausedPaymasterRefusesNewSponsorshipButNotWithdrawal() public {
        vm.prank(pauser);
        paymaster.pause();

        OpParams memory p = _defaultOpParams(address(account));
        PackedUserOperation memory op = _signedSponsoredOp(p, TENANT_A, uint48(block.timestamp + 300), 0, DEFAULT_FEE_WEI);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        vm.expectRevert();
        ENTRY_POINT.handleOps(ops, beneficiary);

        vm.prank(tenantAWithdraw);
        paymaster.withdrawTenant(TENANT_A, 1 ether, tenantAWithdraw);
        assertEq(tenantAWithdraw.balance, 1 ether);
    }

    /// @dev R-20: both keys are valid in the middle of a rotation, so there is no window in which
    ///      sponsorship stops.
    function test_signingKeyRotationCausesNoDowntime() public {
        uint256 nextKey = 0x5161;
        address nextSigner = vm.addr(nextKey);

        vm.prank(signerAdmin);
        paymaster.addSigner(nextSigner);

        // an op authorised by the new key works while the old one is still listed
        OpParams memory p = _defaultOpParams(address(account));
        _runSponsoredOpWithKey(p, nextKey, nextSigner);

        vm.prank(signerAdmin);
        paymaster.removeSigner(sponsor);

        // and continues to work after the old key is revoked
        OpParams memory p2 = _defaultOpParams(address(account));
        p2.nonce = 1;
        _runSponsoredOpWithKey(p2, nextKey, nextSigner);
        _assertInvariant();
    }

    // -----------------------------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------------------------

    function _runSponsoredOp(OpParams memory p) internal {
        _runSponsoredOpWithKey(p, sponsorKey, sponsor);
    }

    function _runSponsoredOpWithKey(OpParams memory p, uint256 key, address signerAddr) internal {
        PackedUserOperation memory op = _signedSponsoredOpWithKey(
            p,
            TENANT_A,
            uint48(block.timestamp + 300),
            0,
            DEFAULT_FEE_WEI,
            key,
            signerAddr
        );
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ENTRY_POINT.handleOps(ops, beneficiary);
    }

    function _signedSponsoredOp(
        OpParams memory p,
        bytes16 tenantId,
        uint48 validUntil,
        uint48 validAfter,
        uint128 feeWei
    ) internal view returns (PackedUserOperation memory) {
        return _signedSponsoredOpWithKey(p, tenantId, validUntil, validAfter, feeWei, sponsorKey, sponsor);
    }

    /// @dev Builds the operation the way production does: the sponsorship authorisation goes in
    ///      first, and the account signature is then taken over the whole operation *including*
    ///      it — which is what makes the two signatures mutually binding.
    function _signedSponsoredOpWithKey(
        OpParams memory p,
        bytes16 tenantId,
        uint48 validUntil,
        uint48 validAfter,
        uint128 feeWei,
        uint256 key,
        address signerAddr
    ) internal view returns (PackedUserOperation memory op) {
        if (p.callData.length == 0) {
            p.callData = abi.encodeCall(
                GianoSmartWallet.execute,
                (address(target), 0, abi.encodeCall(MockTarget.setData, (hex'c0ffee')))
            );
        }
        op = _bareOp(p);

        bytes32 digest = _authorisationDigest(op, p, tenantId, validUntil, validAfter, feeWei);
        (uint8 av, bytes32 ar, bytes32 as_) = vm.sign(key, digest);
        op.paymasterAndData = abi.encodePacked(
            _paymasterPrefix(p),
            _authorisationHeader(tenantId, validUntil, validAfter, feeWei, signerAddr),
            ar,
            as_,
            av
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, ENTRY_POINT.getUserOpHash(op));
        op.signature = abi.encode(GianoSmartWallet.SignatureWrapper(abi.encode(owner), abi.encodePacked(r, s, v)));
    }

    function _sponsoredEvent(
        Vm.Log[] memory logs
    ) internal view returns (uint256 gasCostWei, uint256 feeWei, uint256 overheadWei, uint256 newBalance, bool success) {
        bytes32 topic = keccak256('Sponsored(bytes16,address,bytes32,uint256,uint256,uint256,uint256,bool)');
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(paymaster) && logs[i].topics[0] == topic) {
                return abi.decode(logs[i].data, (uint256, uint256, uint256, uint256, bool));
            }
        }
        revert('no Sponsored event');
    }
}
