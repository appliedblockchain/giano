// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IEntryPoint} from '@account-abstraction/contracts/interfaces/IEntryPoint.sol';
import {IPaymaster} from '@account-abstraction/contracts/interfaces/IPaymaster.sol';
import {PackedUserOperation} from '@account-abstraction/contracts/interfaces/PackedUserOperation.sol';
import {UserOperationLib} from '@account-abstraction/contracts/core/UserOperationLib.sol';
import {_packValidationData, SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from '@account-abstraction/contracts/core/Helpers.sol';

import {AccessControlEnumerableUpgradeable} from '@openzeppelin/contracts-upgradeable/access/extensions/AccessControlEnumerableUpgradeable.sol';
import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import {EIP712Upgradeable} from '@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol';
import {PausableUpgradeable} from '@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol';
import {SignatureChecker} from '@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol';
import {SafeCast} from '@openzeppelin/contracts/utils/math/SafeCast.sol';
import {EnumerableSet} from '@openzeppelin/contracts/utils/structs/EnumerableSet.sol';

/// @title Giano validating paymaster
///
/// @notice Sponsors ERC-4337 UserOperations that carry an authorisation signature from a Giano
///         signing key, debiting the sponsoring tenant's own segregated balance for the gas
///         consumed, a fixed platform fee credited to Giano's treasury, and an overhead allowance
///         covering the network costs this contract cannot observe at settlement.
///
/// @dev    The accounting invariant this contract preserves is
///
///           Sum(tenant balances) + treasury <= EntryPoint.balanceOf(address(this))
///
///         "at most", never "equal": the EntryPoint debits the deposit for `postOp`'s own gas and
///         for its penalty on over-estimated gas limits, both of which fall outside the
///         `actualGasCost` handed to `postOp`. The overhead allowance is therefore charged as a
///         deliberately generous upper bound so the ledger always falls at least as fast as the
///         deposit. The residue is unattributed slack, which is safe; equality would not be.
///
///         There is no owner and no superuser. Every privileged action is gated by its own role,
///         and every role's admin is `ROLE_ADMIN`, which in a real deployment is held by a
///         timelock. `DEFAULT_ADMIN_ROLE` is never granted.
///
/// @author Applied Blockchain (https://github.com/appliedblockchain/giano)
contract GianoPaymaster is
    IPaymaster,
    Initializable,
    AccessControlEnumerableUpgradeable,
    PausableUpgradeable,
    EIP712Upgradeable,
    UUPSUpgradeable
{
    using UserOperationLib for PackedUserOperation;
    using EnumerableSet for EnumerableSet.AddressSet;

    // ---------------------------------------------------------------------------------------
    // Roles
    // ---------------------------------------------------------------------------------------

    /// @notice Grants and revokes every role below, including itself. Held by the timelock.
    bytes32 public constant ROLE_ADMIN = keccak256('giano.paymaster.ROLE_ADMIN');
    /// @notice May add and revoke sponsorship signing keys. May not move funds.
    bytes32 public constant SIGNER_ADMIN_ROLE = keccak256('giano.paymaster.SIGNER_ADMIN_ROLE');
    /// @notice May set the platform fee and per-tenant overrides. May not collect the fees it sets.
    bytes32 public constant FEE_ADMIN_ROLE = keccak256('giano.paymaster.FEE_ADMIN_ROLE');
    /// @notice May withdraw accrued treasury, capped at what has accrued. May not change the rate.
    bytes32 public constant FEE_COLLECTOR_ROLE = keccak256('giano.paymaster.FEE_COLLECTOR_ROLE');
    /// @notice May add, unlock and withdraw the EntryPoint stake. May not touch the deposit.
    bytes32 public constant STAKE_ADMIN_ROLE = keccak256('giano.paymaster.STAKE_ADMIN_ROLE');
    /// @notice May register tenants and set their withdrawal addresses. May not move their funds.
    bytes32 public constant TENANT_ADMIN_ROLE = keccak256('giano.paymaster.TENANT_ADMIN_ROLE');
    /// @notice May set the overhead allowance and operational limits. May not move funds.
    bytes32 public constant PARAM_ADMIN_ROLE = keccak256('giano.paymaster.PARAM_ADMIN_ROLE');
    /// @notice May halt acceptance of new sponsorships. May not move funds or alter configuration.
    bytes32 public constant PAUSER_ROLE = keccak256('giano.paymaster.PAUSER_ROLE');
    /// @notice May replace the implementation. Held by the timelock; see R-50/R-51.
    bytes32 public constant UPGRADER_ROLE = keccak256('giano.paymaster.UPGRADER_ROLE');

    // ---------------------------------------------------------------------------------------
    // Constants
    // ---------------------------------------------------------------------------------------

    /// @dev The only `paymasterData` layout this implementation recognises.
    uint8 internal constant PAYMASTER_DATA_VERSION = 0x01;

    /// @dev Offsets within `paymasterData` (the bytes after the EntryPoint's 20+16+16 prefix).
    uint256 internal constant OFFSET_TENANT_ID = 1;
    uint256 internal constant OFFSET_VALID_UNTIL = 17;
    uint256 internal constant OFFSET_VALID_AFTER = 23;
    uint256 internal constant OFFSET_FEE_WEI = 29;
    uint256 internal constant OFFSET_SIGNER = 45;
    uint256 internal constant OFFSET_SIGNATURE = 65;

    /// @dev Minimum `paymasterData` length: the fixed header plus a 65-byte ECDSA signature. A
    ///      longer tail is accepted so that an ERC-1271 signer (D2's future per-tenant key held in
    ///      a contract) needs no change here.
    uint256 internal constant MIN_PAYMASTER_DATA_LENGTH = OFFSET_SIGNATURE + 65;

    /// @dev EIP-712 type hash for the authorisation the Giano backend signs.
    bytes32 internal constant SPONSORSHIP_AUTHORISATION_TYPEHASH =
        keccak256(
            'SponsorshipAuthorisation(address sender,uint256 nonce,bytes32 callDataHash,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,uint256 paymasterVerificationGasLimit,uint256 paymasterPostOpGasLimit,bytes16 tenantId,uint48 validUntil,uint48 validAfter,uint128 feeWei)'
        );

    /// @dev Upper bound accepted for `penaltyBps`. The EntryPoint's own penalty is 10% (1000 bps);
    ///      the cap leaves room for a chain whose EntryPoint charges more without permitting a
    ///      value that would let a mis-set parameter drain a tenant.
    uint16 internal constant MAX_PENALTY_BPS = 5000;

    // ---------------------------------------------------------------------------------------
    // Storage
    // ---------------------------------------------------------------------------------------

    /// @notice One tenant's mutable accounting and configuration.
    struct Tenant {
        bool registered;
        bool enabled;
        bool hasFeeOverride;
        address withdrawAddress;
        uint128 balance;
        uint128 deficit;
        uint128 feeWeiOverride;
    }

    /// @notice The authorisation header carried in `paymasterData`, decoded once per validation.
    struct Authorisation {
        bytes16 tenantId;
        uint48 validUntil;
        uint48 validAfter;
        uint128 feeWei;
        address signer;
    }

    /// @notice Everything `postOp` needs that it cannot read from the operation, pinned into the
    ///         validation context. All members are static, so it round-trips through the
    ///         `abi.encode` that `validatePaymasterUserOp` returns.
    struct SettlementContext {
        bytes16 tenantId;
        uint128 feeWei;
        uint256 executionGasLimit;
        address sender;
        bytes32 userOpHash;
    }

    /// @dev The `Sponsored` event's fields, gathered in memory — see `_emitSponsored`.
    struct Settled {
        bytes16 tenantId;
        address sender;
        bytes32 userOpHash;
        uint256 gasCostWei;
        uint256 feeWei;
        uint256 overheadWei;
        uint256 newBalance;
        bool success;
    }

    /// @custom:storage-location erc7201:giano.storage.Paymaster
    struct PaymasterStorage {
        IEntryPoint entryPoint;
        mapping(bytes16 tenantId => Tenant) tenants;
        uint256 treasury;
        uint128 defaultFeeWei;
        uint32 postOpGasAllowance;
        uint16 penaltyBps;
        EnumerableSet.AddressSet signers;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("giano.storage.Paymaster")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PAYMASTER_STORAGE_LOCATION =
        0xd300d82671ae3bd8bef68c344f1237c18f73a9609dd918905fb2b2e3e09d5300;

    function _s() private pure returns (PaymasterStorage storage $) {
        assembly {
            $.slot := PAYMASTER_STORAGE_LOCATION
        }
    }

    // ---------------------------------------------------------------------------------------
    // Events
    // ---------------------------------------------------------------------------------------

    event TenantRegistered(bytes16 indexed tenantId, address indexed withdrawAddress, string slug);
    event TenantWithdrawAddressChanged(bytes16 indexed tenantId, address oldAddress, address newAddress);
    event TenantEnabledChanged(bytes16 indexed tenantId, bool enabled, address indexed actor);
    event TenantFunded(bytes16 indexed tenantId, address indexed from, uint256 amount, uint256 deficitCleared, uint256 newBalance);
    event TenantWithdrawn(bytes16 indexed tenantId, address indexed to, uint256 amount, uint256 newBalance);
    event Sponsored(
        bytes16 indexed tenantId,
        address indexed sender,
        bytes32 indexed userOpHash,
        uint256 gasCostWei,
        uint256 feeWei,
        uint256 overheadWei,
        uint256 newBalance,
        bool success
    );
    event SponsorshipDeficit(bytes16 indexed tenantId, bytes32 indexed userOpHash, uint256 shortfallWei, uint256 totalDeficitWei);
    event FeesAccrued(bytes16 indexed tenantId, uint256 amount, uint256 newTreasury);
    event FeesWithdrawn(address indexed to, uint256 amount, uint256 newTreasury);
    event SignerAdded(address indexed signer);
    event SignerRemoved(address indexed signer);
    event FeeChanged(uint128 oldFeeWei, uint128 newFeeWei);
    event TenantFeeChanged(bytes16 indexed tenantId, bool hasOverride, uint128 feeWei);
    event ParamChanged(string indexed name, uint256 oldValue, uint256 newValue);

    // ---------------------------------------------------------------------------------------
    // Errors
    // ---------------------------------------------------------------------------------------

    error NotEntryPoint();
    error PaymasterPaused();
    error UnknownTenant(bytes16 tenantId);
    error TenantAlreadyRegistered(bytes16 tenantId);
    error TenantDisabled(bytes16 tenantId);
    error BadPaymasterData();
    error UnauthorisedSigner(address signer);
    error InsufficientTenantBalance(bytes16 tenantId, uint256 required, uint256 available);
    error TenantInDeficit(bytes16 tenantId, uint256 deficit);
    error NotWithdrawAddress(bytes16 tenantId, address caller);
    error ExceedsTreasury(uint256 requested, uint256 available);
    error ZeroAddress();
    error ZeroAmount();
    error DirectTransferNotAllowed();
    error PenaltyBpsTooHigh(uint16 penaltyBps);
    error AlreadySigner(address signer);
    error NotASigner(address signer);

    // ---------------------------------------------------------------------------------------
    // Construction and initialisation
    // ---------------------------------------------------------------------------------------

    /// @dev The implementation takes no constructor arguments, so its bytecode — and therefore its
    ///      CREATE2 address — is identical across deployments (D10). All configuration is set by
    ///      `initialize`.
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialises the proxy. Called once, in the same transaction as the proxy deploy, by
    ///         `GianoPaymasterDeployer` — see §4.2 of the specification for why.
    /// @param entryPoint_         EntryPoint this paymaster is bound to.
    /// @param roleAdmin           Sole `ROLE_ADMIN` holder. A `TimelockController` in production.
    /// @param defaultFeeWei_      Deployment-wide platform fee per sponsored operation.
    /// @param postOpGasAllowance_ Gas units charged for the settlement step's own gas.
    /// @param penaltyBps_         Basis points of the execution gas limits charged as a bound on
    ///                            the EntryPoint's unused-gas penalty (1000 = its 10%).
    function initialize(
        address entryPoint_,
        address roleAdmin,
        uint128 defaultFeeWei_,
        uint32 postOpGasAllowance_,
        uint16 penaltyBps_
    ) external initializer {
        if (entryPoint_ == address(0) || roleAdmin == address(0)) revert ZeroAddress();
        if (penaltyBps_ > MAX_PENALTY_BPS) revert PenaltyBpsTooHigh(penaltyBps_);

        __AccessControlEnumerable_init();
        __Pausable_init();
        __EIP712_init('GianoPaymaster', '1');
        __UUPSUpgradeable_init();

        PaymasterStorage storage $ = _s();
        $.entryPoint = IEntryPoint(entryPoint_);
        $.defaultFeeWei = defaultFeeWei_;
        $.postOpGasAllowance = postOpGasAllowance_;
        $.penaltyBps = penaltyBps_;

        // Every role is administered by ROLE_ADMIN, which administers itself. DEFAULT_ADMIN_ROLE
        // is never granted, so there is no account that can grant itself a role without going
        // through ROLE_ADMIN's own constraints (R-46).
        _setRoleAdmin(ROLE_ADMIN, ROLE_ADMIN);
        _setRoleAdmin(SIGNER_ADMIN_ROLE, ROLE_ADMIN);
        _setRoleAdmin(FEE_ADMIN_ROLE, ROLE_ADMIN);
        _setRoleAdmin(FEE_COLLECTOR_ROLE, ROLE_ADMIN);
        _setRoleAdmin(STAKE_ADMIN_ROLE, ROLE_ADMIN);
        _setRoleAdmin(TENANT_ADMIN_ROLE, ROLE_ADMIN);
        _setRoleAdmin(PARAM_ADMIN_ROLE, ROLE_ADMIN);
        _setRoleAdmin(PAUSER_ROLE, ROLE_ADMIN);
        _setRoleAdmin(UPGRADER_ROLE, ROLE_ADMIN);

        _grantRole(ROLE_ADMIN, roleAdmin);
    }

    // ---------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------

    function entryPoint() public view returns (IEntryPoint) {
        return _s().entryPoint;
    }

    function treasury() public view returns (uint256) {
        return _s().treasury;
    }

    function defaultFeeWei() public view returns (uint128) {
        return _s().defaultFeeWei;
    }

    function postOpGasAllowance() public view returns (uint32) {
        return _s().postOpGasAllowance;
    }

    function penaltyBps() public view returns (uint16) {
        return _s().penaltyBps;
    }

    function getTenant(bytes16 tenantId) external view returns (Tenant memory) {
        return _s().tenants[tenantId];
    }

    /// @notice The fee in force for a tenant: its override if it has one, otherwise the default.
    function feeFor(bytes16 tenantId) public view returns (uint128) {
        PaymasterStorage storage $ = _s();
        Tenant storage t = $.tenants[tenantId];
        return t.hasFeeOverride ? t.feeWeiOverride : $.defaultFeeWei;
    }

    function isSigner(address signer) external view returns (bool) {
        return _s().signers.contains(signer);
    }

    function signerCount() external view returns (uint256) {
        return _s().signers.length();
    }

    function signerAt(uint256 index) external view returns (address) {
        return _s().signers.at(index);
    }

    /// @notice The whole authorised signer set, for `giano-doctor` and role review (R-55).
    function getSigners() external view returns (address[] memory) {
        return _s().signers.values();
    }

    /// @notice This paymaster's deposit at the EntryPoint — the right-hand side of the invariant.
    function getDeposit() external view returns (uint256) {
        return _s().entryPoint.balanceOf(address(this));
    }

    // ---------------------------------------------------------------------------------------
    // Tenant administration
    // ---------------------------------------------------------------------------------------

    /// @notice Registers a tenant. `slug` is emitted, not stored: it exists so the on-chain record
    ///         can be read against the backend's tenant table without a side channel.
    function registerTenant(bytes16 tenantId, address withdrawAddress, string calldata slug) external onlyRole(TENANT_ADMIN_ROLE) {
        if (tenantId == bytes16(0)) revert UnknownTenant(tenantId);
        if (withdrawAddress == address(0)) revert ZeroAddress();
        Tenant storage t = _s().tenants[tenantId];
        if (t.registered) revert TenantAlreadyRegistered(tenantId);

        t.registered = true;
        t.enabled = true;
        t.withdrawAddress = withdrawAddress;

        emit TenantRegistered(tenantId, withdrawAddress, slug);
    }

    function setTenantWithdrawAddress(bytes16 tenantId, address withdrawAddress) external onlyRole(TENANT_ADMIN_ROLE) {
        if (withdrawAddress == address(0)) revert ZeroAddress();
        Tenant storage t = _requireTenant(tenantId);
        address old = t.withdrawAddress;
        t.withdrawAddress = withdrawAddress;
        emit TenantWithdrawAddressChanged(tenantId, old, withdrawAddress);
    }

    function setTenantEnabled(bytes16 tenantId, bool enabled) external onlyRole(TENANT_ADMIN_ROLE) {
        Tenant storage t = _requireTenant(tenantId);
        t.enabled = enabled;
        emit TenantEnabledChanged(tenantId, enabled, _msgSender());
    }

    // ---------------------------------------------------------------------------------------
    // Funding and withdrawal
    // ---------------------------------------------------------------------------------------

    /// @notice The only way funds enter this contract. Reverts for an unregistered tenant, so
    ///         money can never arrive un-attributed (R-30). Any outstanding deficit is cleared
    ///         first, which is what un-blocks that tenant's authorisations (§7.5).
    function depositFor(bytes16 tenantId) external payable {
        if (msg.value == 0) revert ZeroAmount();
        Tenant storage t = _requireTenant(tenantId);

        uint256 remaining = msg.value;
        uint256 deficitCleared = 0;
        if (t.deficit > 0) {
            deficitCleared = t.deficit <= remaining ? t.deficit : remaining;
            t.deficit = SafeCast.toUint128(t.deficit - deficitCleared);
            remaining -= deficitCleared;
        }
        t.balance = SafeCast.toUint128(uint256(t.balance) + remaining);

        // The deposit is credited with the full value, including the part that cleared a deficit:
        // that part is repaying the pooled deposit for a shortfall it already absorbed.
        _s().entryPoint.depositTo{value: msg.value}(address(this));

        emit TenantFunded(tenantId, _msgSender(), msg.value, deficitCleared, t.balance);
    }

    /// @notice A bare transfer carries no tenant, and silently pooling it would break attribution.
    receive() external payable {
        revert DirectTransferNotAllowed();
    }

    /// @notice Withdraws a tenant's unspent balance. Callable only by that tenant's registered
    ///         withdrawal address — no role defined by this contract can reach it (R-33, R-48) —
    ///         and deliberately available while paused, because a pause must not trap funds (R-53).
    function withdrawTenant(bytes16 tenantId, uint256 amount, address to) external {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        Tenant storage t = _requireTenant(tenantId);
        if (_msgSender() != t.withdrawAddress) revert NotWithdrawAddress(tenantId, _msgSender());
        if (amount > t.balance) revert InsufficientTenantBalance(tenantId, amount, t.balance);

        // Ledger first, deposit second: the invariant holds at every observable point.
        t.balance = SafeCast.toUint128(uint256(t.balance) - amount);
        _s().entryPoint.withdrawTo(payable(to), amount);

        emit TenantWithdrawn(tenantId, to, amount, t.balance);
    }

    /// @notice Withdraws accrued platform fees, capped at what has accrued. The cap is what makes
    ///         R-33 true: without it this path would reach tenant funds.
    function withdrawFees(address to, uint256 amount) external onlyRole(FEE_COLLECTOR_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        PaymasterStorage storage $ = _s();
        if (amount > $.treasury) revert ExceedsTreasury(amount, $.treasury);

        $.treasury -= amount;
        $.entryPoint.withdrawTo(payable(to), amount);

        emit FeesWithdrawn(to, amount, $.treasury);
    }

    // ---------------------------------------------------------------------------------------
    // Stake administration
    // ---------------------------------------------------------------------------------------

    function addStake(uint32 unstakeDelaySec) external payable onlyRole(STAKE_ADMIN_ROLE) {
        _s().entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyRole(STAKE_ADMIN_ROLE) {
        _s().entryPoint.unlockStake();
    }

    function withdrawStake(address payable to) external onlyRole(STAKE_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress();
        _s().entryPoint.withdrawStake(to);
    }

    // ---------------------------------------------------------------------------------------
    // Signer, fee and parameter administration
    // ---------------------------------------------------------------------------------------

    function addSigner(address signer) external onlyRole(SIGNER_ADMIN_ROLE) {
        if (signer == address(0)) revert ZeroAddress();
        if (!_s().signers.add(signer)) revert AlreadySigner(signer);
        emit SignerAdded(signer);
    }

    function removeSigner(address signer) external onlyRole(SIGNER_ADMIN_ROLE) {
        if (!_s().signers.remove(signer)) revert NotASigner(signer);
        emit SignerRemoved(signer);
    }

    function setDefaultFee(uint128 feeWei) external onlyRole(FEE_ADMIN_ROLE) {
        PaymasterStorage storage $ = _s();
        uint128 old = $.defaultFeeWei;
        $.defaultFeeWei = feeWei;
        emit FeeChanged(old, feeWei);
    }

    function setTenantFee(bytes16 tenantId, bool hasOverride, uint128 feeWei) external onlyRole(FEE_ADMIN_ROLE) {
        Tenant storage t = _requireTenant(tenantId);
        t.hasFeeOverride = hasOverride;
        t.feeWeiOverride = hasOverride ? feeWei : 0;
        emit TenantFeeChanged(tenantId, hasOverride, t.feeWeiOverride);
    }

    function setPostOpGasAllowance(uint32 gasUnits) external onlyRole(PARAM_ADMIN_ROLE) {
        PaymasterStorage storage $ = _s();
        uint32 old = $.postOpGasAllowance;
        $.postOpGasAllowance = gasUnits;
        emit ParamChanged('postOpGasAllowance', old, gasUnits);
    }

    function setPenaltyBps(uint16 bps) external onlyRole(PARAM_ADMIN_ROLE) {
        if (bps > MAX_PENALTY_BPS) revert PenaltyBpsTooHigh(bps);
        PaymasterStorage storage $ = _s();
        uint16 old = $.penaltyBps;
        $.penaltyBps = bps;
        emit ParamChanged('penaltyBps', old, bps);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // ---------------------------------------------------------------------------------------
    // Validation
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        PaymasterStorage storage $ = _s();
        if (msg.sender != address($.entryPoint)) revert NotEntryPoint();
        if (paused()) revert PaymasterPaused();

        bytes calldata pmData = userOp.paymasterAndData[UserOperationLib.PAYMASTER_DATA_OFFSET:];
        Authorisation memory auth = _decodeAuthorisation(pmData);

        Tenant storage t = $.tenants[auth.tenantId];
        if (!t.registered) revert UnknownTenant(auth.tenantId);
        if (!t.enabled) revert TenantDisabled(auth.tenantId);

        // The cheap set lookup first: a revoked key never reaches the cryptography.
        if (!$.signers.contains(auth.signer)) revert UnauthorisedSigner(auth.signer);

        if (!SignatureChecker.isValidSignatureNow(auth.signer, _authorisationDigest(userOp, auth), pmData[OFFSET_SIGNATURE:])) {
            // A bad signature is the one condition the bundler must read as an invalid operation
            // rather than a paymaster fault, so it is returned rather than reverted.
            return ('', SIG_VALIDATION_FAILED);
        }

        if (t.deficit > 0) revert TenantInDeficit(auth.tenantId, t.deficit);

        uint256 executionGasLimit = userOp.unpackCallGasLimit() + userOp.unpackPostOpGasLimit();
        uint256 requiredCharge = maxCost + auth.feeWei + _overheadWei(userOp.unpackMaxFeePerGas(), executionGasLimit);
        if (requiredCharge > t.balance) revert InsufficientTenantBalance(auth.tenantId, requiredCharge, t.balance);

        return (
            abi.encode(auth.tenantId, auth.feeWei, executionGasLimit, userOp.getSender(), userOpHash),
            _packValidationData(false, auth.validUntil, auth.validAfter)
        );
    }

    // ---------------------------------------------------------------------------------------
    // Settlement
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc IPaymaster
    ///
    /// @dev Never reverts on a shortfall. By the time this runs the operation has executed and the
    ///      deposit has already paid, so refusing to settle would revert work the network has
    ///      charged for. Clamping and recording an explicit deficit is the only safe behaviour
    ///      (R-35), and a tenant carrying one cannot authorise again until it funds.
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas) external {
        if (msg.sender != address(_s().entryPoint)) revert NotEntryPoint();
        _settle(abi.decode(context, (SettlementContext)), mode == PostOpMode.opSucceeded, actualGasCost, actualUserOpFeePerGas);
    }

    /// @dev The whole of the accounting, in one place: gas and overhead leave the ledger mirroring
    ///      the money that left the deposit, the fee moves from the tenant to the treasury, and
    ///      anything the balance could not cover becomes an explicit, alerted deficit.
    function _settle(SettlementContext memory c, bool success, uint256 actualGasCost, uint256 actualUserOpFeePerGas) internal {
        PaymasterStorage storage $ = _s();
        Tenant storage t = $.tenants[c.tenantId];

        uint256 overheadWei = _overheadWei(actualUserOpFeePerGas, c.executionGasLimit);
        uint256 owed = actualGasCost + overheadWei;
        uint256 balance = t.balance;

        // Gas and overhead first: they mirror money that has already left the deposit. The fee is
        // taken from whatever remains, and only the part actually taken reaches the treasury.
        uint256 gasTaken = owed <= balance ? owed : balance;
        balance -= gasTaken;
        uint256 feeTaken = c.feeWei <= balance ? c.feeWei : balance;
        balance -= feeTaken;
        uint256 shortfall = (owed - gasTaken) + (c.feeWei - feeTaken);

        t.balance = SafeCast.toUint128(balance);
        if (feeTaken > 0) {
            $.treasury += feeTaken;
            emit FeesAccrued(c.tenantId, feeTaken, $.treasury);
        }
        if (shortfall > 0) {
            t.deficit = SafeCast.toUint128(uint256(t.deficit) + shortfall);
            emit SponsorshipDeficit(c.tenantId, c.userOpHash, shortfall, t.deficit);
        }

        _emitSponsored(
            Settled({
                tenantId: c.tenantId,
                sender: c.sender,
                userOpHash: c.userOpHash,
                gasCostWei: actualGasCost,
                feeWei: feeTaken,
                overheadWei: overheadWei,
                newBalance: balance,
                success: success
            })
        );
    }

    /// @dev `Sponsored` carries eight fields — R-43 wants gas, fee and overhead separately visible
    ///      — which is one stack slot too many to emit inline. Emitting from a memory struct keeps
    ///      the event complete without forcing the whole repository's test build onto `viaIR`.
    function _emitSponsored(Settled memory e) private {
        emit Sponsored(e.tenantId, e.sender, e.userOpHash, e.gasCostWei, e.feeWei, e.overheadWei, e.newBalance, e.success);
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    /// @dev A strict upper bound on the network costs that fall outside `actualGasCost`: this
    ///      function's own gas, plus the EntryPoint's penalty, charged against the whole execution
    ///      gas limit even though the EntryPoint levies it only on the unused part. Charging the
    ///      bound is what keeps the ledger falling at least as fast as the deposit (D1, R-41).
    function _overheadWei(uint256 feePerGas, uint256 executionGasLimit) internal view returns (uint256) {
        PaymasterStorage storage $ = _s();
        return feePerGas * (uint256($.postOpGasAllowance) + (executionGasLimit * $.penaltyBps) / 10_000);
    }

    /// @dev Parses the authorisation header the sponsorship service placed in `paymasterData`.
    function _decodeAuthorisation(bytes calldata pmData) internal pure returns (Authorisation memory auth) {
        if (pmData.length < MIN_PAYMASTER_DATA_LENGTH || uint8(pmData[0]) != PAYMASTER_DATA_VERSION) revert BadPaymasterData();
        auth.tenantId = bytes16(pmData[OFFSET_TENANT_ID:OFFSET_VALID_UNTIL]);
        auth.validUntil = uint48(bytes6(pmData[OFFSET_VALID_UNTIL:OFFSET_VALID_AFTER]));
        auth.validAfter = uint48(bytes6(pmData[OFFSET_VALID_AFTER:OFFSET_FEE_WEI]));
        auth.feeWei = uint128(bytes16(pmData[OFFSET_FEE_WEI:OFFSET_SIGNER]));
        auth.signer = address(bytes20(pmData[OFFSET_SIGNER:OFFSET_SIGNATURE]));
    }

    /// @dev The EIP-712 digest the Giano backend signed. It deliberately covers everything that
    ///      determines the operation's cost and intent — and the tenant that pays — but not the
    ///      account signature, which is applied afterwards over the whole operation including
    ///      this authorisation. Neither signature can be altered without invalidating the other.
    function _authorisationDigest(PackedUserOperation calldata userOp, Authorisation memory auth) internal view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                SPONSORSHIP_AUTHORISATION_TYPEHASH,
                userOp.getSender(),
                userOp.nonce,
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                userOp.unpackPaymasterVerificationGasLimit(),
                userOp.unpackPostOpGasLimit(),
                auth.tenantId,
                auth.validUntil,
                auth.validAfter,
                auth.feeWei
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function _requireTenant(bytes16 tenantId) internal view returns (Tenant storage t) {
        t = _s().tenants[tenantId];
        if (!t.registered) revert UnknownTenant(tenantId);
    }

    /// @dev The one power that can override the custody guarantee (D14). Held by the timelock, so
    ///      every upgrade is queued publicly and executable only after the published delay.
    function _authorizeUpgrade(address) internal override onlyRole(UPGRADER_ROLE) {}
}
