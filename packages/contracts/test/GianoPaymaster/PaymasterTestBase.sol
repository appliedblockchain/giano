// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from 'forge-std/Test.sol';
import {IEntryPoint} from '@account-abstraction/contracts/interfaces/IEntryPoint.sol';
import {PackedUserOperation} from '@account-abstraction/contracts/interfaces/PackedUserOperation.sol';

import {GianoPaymaster} from '../../src/paymaster/GianoPaymaster.sol';
import {GianoPaymasterDeployer} from '../../src/paymaster/GianoPaymasterDeployer.sol';
import {Static} from '../GianoSmartWallet/Static.sol';

/// @dev Shared fixture for the paymaster suite.
///
///      The real EntryPoint v0.7 bytecode is etched at its canonical address, so deposits, stake
///      and withdrawals are exercised against the contract that will actually hold the money
///      rather than a mock that agrees with us.
///
///      Every role is held by its own address. That is the only way role-gating tests can say
///      anything: if the fixture held them all on one account, "the fee admin cannot collect fees"
///      would pass for the wrong reason.
contract PaymasterTestBase is Test {
    IEntryPoint internal constant ENTRY_POINT = IEntryPoint(0x0000000071727De22E5E9d8BAf0edAc6f37da032);

    bytes32 internal constant DEPLOY_SALT = 0xAB000000000000000000000000000000000000000000000000000000000000AB;

    /// @dev Mirrors the contract's own type hash. Written out again on purpose: a test that reads
    ///      the constant from the contract under test cannot catch the constant being wrong.
    bytes32 internal constant AUTHORISATION_TYPEHASH =
        keccak256(
            'SponsorshipAuthorisation(address sender,uint256 nonce,bytes32 callDataHash,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,uint256 paymasterVerificationGasLimit,uint256 paymasterPostOpGasLimit,bytes16 tenantId,uint48 validUntil,uint48 validAfter,uint128 feeWei)'
        );

    GianoPaymaster internal paymaster;
    GianoPaymaster internal implementation;
    GianoPaymasterDeployer internal deployer;

    // Role holders, one address each.
    address internal roleAdmin = makeAddr('roleAdmin');
    address internal signerAdmin = makeAddr('signerAdmin');
    address internal feeAdmin = makeAddr('feeAdmin');
    address internal feeCollector = makeAddr('feeCollector');
    address internal stakeAdmin = makeAddr('stakeAdmin');
    address internal tenantAdmin = makeAddr('tenantAdmin');
    address internal paramAdmin = makeAddr('paramAdmin');
    address internal pauser = makeAddr('pauser');
    address internal upgrader = makeAddr('upgrader');

    address internal outsider = makeAddr('outsider');
    address internal walletOwner = makeAddr('walletOwner');

    uint256 internal sponsorKey = 0x5160;
    address internal sponsor = vm.addr(0x5160);

    bytes16 internal constant TENANT_A = bytes16(uint128(0xA11CE));
    bytes16 internal constant TENANT_B = bytes16(uint128(0xB0B));
    address internal tenantAWithdraw = makeAddr('tenantAWithdraw');
    address internal tenantBWithdraw = makeAddr('tenantBWithdraw');

    uint128 internal constant DEFAULT_FEE_WEI = 0.0001 ether;
    uint32 internal constant POST_OP_GAS_ALLOWANCE = 40_000;
    uint16 internal constant PENALTY_BPS = 1000;

    function setUp() public virtual {
        vm.etch(address(ENTRY_POINT), Static.ENTRY_POINT_BYTES);

        implementation = new GianoPaymaster();
        deployer = new GianoPaymasterDeployer();

        paymaster = GianoPaymaster(
            payable(
                deployer.deploy(
                    DEPLOY_SALT,
                    address(implementation),
                    abi.encodeCall(
                        GianoPaymaster.initialize,
                        (address(ENTRY_POINT), roleAdmin, DEFAULT_FEE_WEI, POST_OP_GAS_ALLOWANCE, PENALTY_BPS)
                    )
                )
            )
        );

        vm.startPrank(roleAdmin);
        paymaster.grantRole(paymaster.SIGNER_ADMIN_ROLE(), signerAdmin);
        paymaster.grantRole(paymaster.FEE_ADMIN_ROLE(), feeAdmin);
        paymaster.grantRole(paymaster.FEE_COLLECTOR_ROLE(), feeCollector);
        paymaster.grantRole(paymaster.STAKE_ADMIN_ROLE(), stakeAdmin);
        paymaster.grantRole(paymaster.TENANT_ADMIN_ROLE(), tenantAdmin);
        paymaster.grantRole(paymaster.PARAM_ADMIN_ROLE(), paramAdmin);
        paymaster.grantRole(paymaster.PAUSER_ROLE(), pauser);
        paymaster.grantRole(paymaster.UPGRADER_ROLE(), upgrader);
        vm.stopPrank();

        vm.prank(signerAdmin);
        paymaster.addSigner(sponsor);

        vm.startPrank(tenantAdmin);
        paymaster.registerTenant(TENANT_A, tenantAWithdraw, 'tenant-a');
        paymaster.registerTenant(TENANT_B, tenantBWithdraw, 'tenant-b');
        vm.stopPrank();
    }

    // -----------------------------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------------------------

    function _fund(bytes16 tenantId, uint256 amount) internal {
        vm.deal(address(this), address(this).balance + amount);
        paymaster.depositFor{value: amount}(tenantId);
    }

    function _stake() internal {
        vm.deal(stakeAdmin, 2 ether);
        vm.prank(stakeAdmin);
        paymaster.addStake{value: 1 ether}(1 days);
    }

    // -----------------------------------------------------------------------------------------
    // UserOperation construction
    // -----------------------------------------------------------------------------------------

    struct OpParams {
        address sender;
        uint256 nonce;
        bytes callData;
        uint128 verificationGasLimit;
        uint128 callGasLimit;
        uint256 preVerificationGas;
        uint128 maxPriorityFeePerGas;
        uint128 maxFeePerGas;
        uint128 pmVerificationGasLimit;
        uint128 pmPostOpGasLimit;
    }

    function _defaultOpParams(address sender) internal pure returns (OpParams memory p) {
        p.sender = sender;
        p.nonce = 0;
        p.callData = hex'';
        p.verificationGasLimit = 500_000;
        p.callGasLimit = 200_000;
        p.preVerificationGas = 50_000;
        p.maxPriorityFeePerGas = 1 gwei;
        p.maxFeePerGas = 2 gwei;
        p.pmVerificationGasLimit = 150_000;
        p.pmPostOpGasLimit = 100_000;
    }

    /// @dev Builds an operation whose `paymasterAndData` carries a valid authorisation from
    ///      `sponsorKey`. Individual tests corrupt one field at a time from here.
    function _sponsoredOp(
        OpParams memory p,
        bytes16 tenantId,
        uint48 validUntil,
        uint48 validAfter,
        uint128 feeWei
    ) internal view returns (PackedUserOperation memory op) {
        op = _bareOp(p);
        bytes memory header = _authorisationHeader(tenantId, validUntil, validAfter, feeWei, sponsor);
        bytes32 digest = _authorisationDigest(op, p, tenantId, validUntil, validAfter, feeWei);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sponsorKey, digest);
        op.paymasterAndData = abi.encodePacked(_paymasterPrefix(p), header, r, s, v);
    }

    function _bareOp(OpParams memory p) internal pure returns (PackedUserOperation memory op) {
        op = PackedUserOperation({
            sender: p.sender,
            nonce: p.nonce,
            initCode: '',
            callData: p.callData,
            accountGasLimits: bytes32((uint256(p.verificationGasLimit) << 128) | uint256(p.callGasLimit)),
            preVerificationGas: p.preVerificationGas,
            gasFees: bytes32((uint256(p.maxPriorityFeePerGas) << 128) | uint256(p.maxFeePerGas)),
            paymasterAndData: '',
            signature: ''
        });
    }

    function _paymasterPrefix(OpParams memory p) internal view returns (bytes memory) {
        return abi.encodePacked(address(paymaster), p.pmVerificationGasLimit, p.pmPostOpGasLimit);
    }

    function _authorisationHeader(
        bytes16 tenantId,
        uint48 validUntil,
        uint48 validAfter,
        uint128 feeWei,
        address signer
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(uint8(0x01), tenantId, validUntil, validAfter, feeWei, signer);
    }

    function _authorisationDigest(
        PackedUserOperation memory op,
        OpParams memory p,
        bytes16 tenantId,
        uint48 validUntil,
        uint48 validAfter,
        uint128 feeWei
    ) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                AUTHORISATION_TYPEHASH,
                op.sender,
                op.nonce,
                keccak256(op.callData),
                op.accountGasLimits,
                op.preVerificationGas,
                op.gasFees,
                uint256(p.pmVerificationGasLimit),
                uint256(p.pmPostOpGasLimit),
                tenantId,
                validUntil,
                validAfter,
                feeWei
            )
        );
        return keccak256(abi.encodePacked('\x19\x01', _domainSeparator(), structHash));
    }

    function _domainSeparator() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'),
                    keccak256('GianoPaymaster'),
                    keccak256('1'),
                    block.chainid,
                    address(paymaster)
                )
            );
    }

    // -----------------------------------------------------------------------------------------
    // Assertions
    // -----------------------------------------------------------------------------------------

    /// @dev The property the whole design rests on: claims never exceed the deposit.
    function _assertInvariant() internal view {
        uint256 claims = uint256(paymaster.getTenant(TENANT_A).balance) +
            uint256(paymaster.getTenant(TENANT_B).balance) +
            paymaster.treasury();
        assertLe(claims, ENTRY_POINT.balanceOf(address(paymaster)), 'invariant breached: claims exceed deposit');
    }

    function _overheadWei(uint256 feePerGas, uint256 executionGasLimit) internal view returns (uint256) {
        return feePerGas * (uint256(paymaster.postOpGasAllowance()) + (executionGasLimit * paymaster.penaltyBps()) / 10_000);
    }

    receive() external payable {}
}
