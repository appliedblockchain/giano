// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PrivateEventEmitter} from "./utils/PrivateEventEmitter.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title UCEF (User Confidential ERC20 Funds)
 * @dev Implementation of a confidential ERC20 token where balance visibility is restricted.
 * This contract extends the standard ERC20 implementation with additional privacy features
 * that control who can view token balances and events.
 *
 * Key features:
 * - Balance visibility control through authorization mechanism
 * - Private Events for selective event visibility
 * - Standard ERC20 functionality
 * - Protected balance and allowance access
 *
 * Private Events Integration:
 * This contract implements the Silent Data Private Events system, which enables selective
 * visibility of on-chain events. Events are emitted as PrivateEvent logs with:
 * - allowedViewers: addresses authorized to view the event
 * - eventType: hash of the original event signature
 * - payload: ABI-encoded event arguments
 *
 * Extension system:
 * The contract provides two official extensions:
 * 1. UCEFOwned - Implements strict privacy where only account owners can view their balances
 * 2. UCEFRegulated - Adds a regulator role that can view all balances alongside account owners
 *
 * Custom extensions can be created by:
 * 1. Inheriting from this contract
 * 2. Implementing the _authorizeBalance function with custom logic
 * 3. Overriding _getTransferEventViewers and _getApprovalEventViewers for event privacy
 * 4. Overriding _emitTransferEvent and _emitApprovalEvent for custom emission logic
 * 5. Choosing between silent failure (return false) or explicit revert for unauthorized access
 *
 * Security considerations:
 * - Balance authorization must be properly implemented in derived contracts
 * - Event viewer lists should align with the privacy model
 * - The contract maintains actual balances internally while exposing only authorized views
 * - Extensions should carefully consider their privacy model and access control
 */
abstract contract UCEF is ERC20, PrivateEventEmitter {
    // Event type constants for Private Events
    /**
    * @notice Transfer event parameter mapping:
    *   - address param0: from  - Token sender (address(0) for minting)
    *   - address param1: to    - Token receiver (address(0) for burning)
    *   - uint256 param2: value - Amount of tokens transferred
    * @custom:signature Transfer(address from, address to, uint256 value)
    */
    bytes32 public constant EVENT_TYPE_TRANSFER = keccak256("Transfer(address,address,uint256)");
    /**
    * @notice Approval event parameter mapping:
    *   - address param0: from  - Token sender (address(0) for minting)
    *   - address param1: to    - Token receiver (address(0) for burning)
    *   - uint256 param2: value - Amount of tokens approved
    * @custom:signature Approval(address from, address to, uint256 value)
    */
    bytes32 public constant EVENT_TYPE_APPROVAL = keccak256("Approval(address,address,uint256)");

    mapping(address account => uint256) private _balances;
    uint256 private _totalSupply;
    mapping(address account => mapping(address spender => uint256)) private _allowances;

    /**
     * @dev Thrown when an unauthorized address attempts to view a balance
     * @param sender The address attempting to view the balance
     * @param account The address whose balance was attempted to be viewed
     */
    error UCEFUnauthorizedBalanceAccess(address sender, address account);

    /**
     * @dev Thrown when an unauthorized address attempts to mint tokens
     * @param sender The address attempting to mint
     * @param to The address that would have received the minted tokens
     * @param amount The number of tokens that were attempted to be minted
     */
    error UCEFUnauthorizedMint(address sender, address to, uint256 amount);

    /**
     * @dev Constructor that sets the name and symbol of the token
     * @param name The name of the token
     * @param symbol The symbol of the token
     */
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    /**
     * @dev Internal function to determine if an address is authorized to view a balance
     * Must be implemented by derived contracts to define authorization logic
     * @param account The address to check authorization for
     * @return bool True if authorized, false otherwise
     *
     * @notice Implementation behavior:
     * - Return true to allow balance visibility (will return actual balance)
     * - Return false to deny balance visibility (will return 0)
     * - Revert with UCEFUnauthorizedBalanceAccess or custom error if explicit error handling is required
     *
     * @custom:security Implementing contracts should carefully consider their authorization logic
     * as it directly impacts the privacy of user balances
     */
    function _authorizeBalance(address account) internal view virtual returns (bool);

    /**
     * @dev Internal function to authorize a mint operation.
     * Must be implemented by derived contracts to define mint authorization logic.
     * Called automatically during every mint (when `from == address(0)` in `_update`).
     *
     * @param to The address that will receive the minted tokens
     * @param amount The number of tokens to mint
     *
     * @notice Implementation behavior:
     * - Should revert with UCEFUnauthorizedMint or a custom error if the caller is not authorized to mint
     * - A no-op implementation (empty body) explicitly allows unrestricted minting
     *
     * @custom:security This function is abstract to force every concrete UCEF token to define
     * a minting policy. Without an implementation the contract will not compile, preventing
     * accidental deployment of tokens with unprotected minting.
     */
    function _authorizeMint(address to, uint256 amount) internal view virtual;

    /**
     * @dev Returns the balance of the specified account if authorized
     * @param account The address to query the balance of
     * @return uint256 The balance if authorized, 0 if unauthorized
     */
    function balanceOf(address account) public view override virtual returns (uint256) {
        bool authorized = _authorizeBalance(account);
        return authorized ? _balanceOf(account): 0;
    }

    /**
     * @dev Returns the total supply of the token
     * @return uint256 The total token supply
     */
    function totalSupply() public view override virtual returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev Internal function to get the actual balance of an account
     * @param account The address to query the balance of
     * @return uint256 The actual balance of the account
     */
    function _balanceOf(address account) internal view returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev Internal function to update balances during transfers
     * Handles minting, burning, and transfers between addresses
     * @param from The sending address (address(0) for minting)
     * @param to The receiving address (address(0) for burning)
     * @param value The amount of tokens to transfer
     */
    function _update(address from, address to, uint256 value) internal override virtual {
        if (from == address(0)) {
            _authorizeMint(to, value);
            // Overflow check required: The rest of the code assumes that totalSupply never overflows
            _totalSupply += value;
        } else {
            uint256 fromBalance = _balances[from];
            if (fromBalance < value) {
                revert ERC20InsufficientBalance(from, fromBalance, value);
            }
            unchecked {
                // Overflow not possible: value <= fromBalance <= totalSupply.
                _balances[from] = fromBalance - value;
            }
        }

        if (to == address(0)) {
            unchecked {
                // Overflow not possible: value <= totalSupply or value <= fromBalance <= totalSupply.
                _totalSupply -= value;
            }
        } else {
            unchecked {
                // Overflow not possible: balance + value is at most totalSupply, which we know fits into a uint256.
                _balances[to] += value;
            }
        }

        _emitTransferEvent(from, to, value);
    }

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     * 
     * Access Control:
     * - Only the token owner or the approved spender can view the allowance
     * - Any other address attempting to view the allowance will trigger UCEFUnauthorizedBalanceAccess
     * 
     * Requirements:
     * - msg.sender must be either the owner or the spender of the allowance
     * 
     * @param owner The address that owns the tokens
     * @param spender The address that can spend the tokens
     * @return uint256 The number of tokens the spender is allowed to spend
     * @custom:error UCEFUnauthorizedBalanceAccess Thrown when an unauthorized address attempts to view the allowance
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        if (msg.sender != owner && msg.sender != spender) {
            revert UCEFUnauthorizedBalanceAccess(msg.sender, owner);
        }
        return _allowance(owner, spender);
    }

    /**
     * @dev Internal helper function to access the allowance mapping directly.
     * This function provides raw access to the allowance value without any access control checks.
     * It should only be used by internal functions that have already performed necessary validations.
     *
     * @param owner The address that owns the tokens and has granted the allowance
     * @param spender The address that has been granted spending privileges
     * @return uint256 The raw allowance value from the mapping
     *
     * Note: This function is separated from the public allowance() function to maintain
     * a clear separation between access-controlled and internal raw data access
     */
    function _allowance(address owner, address spender) internal view returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev Sets `value` as the allowance of `spender` over the `owner` s tokens.
     * 
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Requirements:
     * - `owner` cannot be the zero address
     * - `spender` cannot be the zero address
     *
     * @param owner The address that owns the tokens
     * @param spender The address that can spend the tokens
     * @param value The amount of tokens to allow
     * @param emitEvent Whether to emit the Approval event
     */
    function _approve(address owner, address spender, uint256 value, bool emitEvent) internal override virtual {
        if (owner == address(0)) {
            revert ERC20InvalidApprover(address(0));
        }
        if (spender == address(0)) {
            revert ERC20InvalidSpender(address(0));
        }
        _allowances[owner][spender] = value;
        if (emitEvent) {
            _emitApprovalEvent(owner, spender, value);
        }
    }

    /**
     * @dev Updates the allowance of a spender for a given owner when tokens are spent via transferFrom.
     * This internal function is used to reduce the spender's allowance by the specified value.
     * 
     * Special cases:
     * - If the current allowance is the maximum uint256 value, it represents an infinite allowance
     *   and will not be reduced (acts as an infinite approval)
     * - If the requested value exceeds the current allowance, the transaction will revert
     * 
     * Requirements:
     * - `value` must not exceed the current allowance
     * - Current allowance must be finite (less than max uint256) for it to be reduced
     *
     * @param owner The address that owns the tokens and has granted the allowance
     * @param spender The address that is spending the tokens
     * @param value The amount of tokens being spent
     *
     * Note: This function calls _approve internally with emitEvent=false to avoid
     * unnecessary event emissions during transfers
     */
    function _spendAllowance(address owner, address spender, uint256 value) internal override virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance < type(uint256).max) {
            if (currentAllowance < value) {
                revert ERC20InsufficientAllowance(address(0), 0, 0);
            }
            unchecked {
                _approve(owner, spender, currentAllowance - value, false);
            }
        }
    }

    /**
     * @dev Internal function to emit Transfer events
     * Can be overridden by derived contracts to implement custom emission logic
     * Default implementation emits private events with selective visibility
     * @param from The sending address (address(0) for minting)
     * @param to The receiving address (address(0) for burning)
     * @param value The amount of tokens transferred
     */
    function _emitTransferEvent(address from, address to, uint256 value) internal virtual {
        address[] memory allowedViewers = _getTransferEventViewers(from, to, value);
        bytes memory payload = abi.encode(from, to, value);

        emit PrivateEvent(allowedViewers, EVENT_TYPE_TRANSFER, payload);
    }

    /**
     * @dev Internal function to determine who can view Transfer events
     * Can be overridden by derived contracts to implement custom viewer logic
     * Default implementation: only sender and receiver can view
     * @param from The sending address
     * @param to The receiving address
     * @param value The amount of tokens transferred (available for derived contracts)
     * @return allowedViewers Array of addresses authorized to view this transfer
     */
    function _getTransferEventViewers(
        address from,
        address to,
        uint256 value
    ) internal view virtual returns (address[] memory allowedViewers) {
        value; // Available for derived contracts

        // Count unique non-zero addresses
        uint256 viewerCount = 0;
        if (from != address(0)) viewerCount++;
        if (to != address(0) && to != from) viewerCount++;

        allowedViewers = new address[](viewerCount);
        uint256 index = 0;

        // Populate viewer list
        if (from != address(0)) {
            allowedViewers[index++] = from;
        }
        if (to != address(0) && to != from) {
            allowedViewers[index] = to;
        }
    }

    /**
     * @dev Internal function to emit Approval events
     * Can be overridden by derived contracts to implement custom emission logic
     * Default implementation emits private events with selective visibility
     * @param owner The address that owns the tokens
     * @param spender The address that can spend the tokens
     * @param value The amount of tokens approved
     */
    function _emitApprovalEvent(address owner, address spender, uint256 value) internal virtual {
        address[] memory allowedViewers = _getApprovalEventViewers(owner, spender, value);
        bytes memory payload = abi.encode(owner, spender, value);

        emit PrivateEvent(allowedViewers, EVENT_TYPE_APPROVAL, payload);
    }

    /**
     * @dev Internal function to determine who can view Approval events
     * Can be overridden by derived contracts to implement custom viewer logic
     * Default implementation: only owner and spender can view
     * @param owner The address that owns the tokens
     * @param spender The address that can spend the tokens
     * @param value The amount of tokens approved (available for derived contracts)
     * @return allowedViewers Array of addresses authorized to view this approval
     */
    function _getApprovalEventViewers(
        address owner,
        address spender,
        uint256 value
    ) internal view virtual returns (address[] memory allowedViewers) {
        value; // Available for derived contracts

        // Count unique non-zero addresses
        uint256 viewerCount = 0;
        if (owner != address(0)) viewerCount++;
        if (spender != address(0) && spender != owner) viewerCount++;

        allowedViewers = new address[](viewerCount);
        uint256 index = 0;

        // Populate viewer list
        if (owner != address(0)) {
            allowedViewers[index++] = owner;
        }
        if (spender != address(0) && spender != owner) {
            allowedViewers[index] = spender;
        }
    }
} 