// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {TimelockController} from '@openzeppelin/contracts/governance/TimelockController.sol';

/// @title Giano timelock
///
/// @notice An OpenZeppelin `TimelockController` whose delay can differ per function. It holds the
///         paymaster's timelocked roles (ROLE_ADMIN, UPGRADER_ROLE, FEE_ADMIN_ROLE and
///         WITHDRAW_ADDRESS_ADMIN_ROLE), so every call it makes with them is public for its delay
///         before it can execute. During that window anyone, tenants included, can see what is
///         coming and react (R-51).
///
/// @dev    A stock `TimelockController` has one `minDelay` for everything, so giving an upgrade a
///         different delay from a fee change would take one controller per delay, each holding its
///         own role. Here a `(target, selector)` pair can carry its own delay instead, and the
///         delay an operation must be scheduled with is
///
///           max(minDelay, functionDelay(target, selector))
///
///         taken over every call in a batch. `minDelay` is therefore the floor and the delay of
///         anything not configured. A function delay can only raise a call above it.
///
///         Changing a delay is itself timelocked, and waits as long as the delay it changes:
///         `setFunctionDelay(t, s, d)` must be scheduled with at least the current delay of
///         `(t, s)`, and `updateDelay` with at least the current `minDelay` (as upstream). Without
///         that, a short configuration delay would let a proposer shorten a long one and then use
///         it, so every delay would be only as long as the shortest.
///
///         There is no admin: the constructor passes `address(0)` upstream, so the proposer,
///         executor and canceller roles are administered only by the timelock itself.
///
///         Keying on the selector is sound only because a timelock call reaches its target
///         directly (`target.call`, never `delegatecall`) and the paymaster has no multicall or
///         other function that dispatches to another of its own functions. A target that gains
///         one must have that function's delay set at least as high as anything it can reach.
///
/// @author Applied Blockchain (https://github.com/appliedblockchain/giano)
contract GianoTimelock is TimelockController {
    /// @notice A per-function delay, as passed to the constructor.
    struct FunctionDelay {
        address target;
        bytes4 selector;
        uint256 delay;
    }

    mapping(address target => mapping(bytes4 selector => uint256 delay)) private _functionDelays;

    /// @notice A function's own delay changed. `0` means it has none and falls back to `minDelay`.
    event FunctionDelayChange(address indexed target, bytes4 indexed selector, uint256 oldDuration, uint256 newDuration);

    /// @param minDelay       Floor for every operation, and the delay of any function not configured.
    /// @param proposers      Accounts that may schedule and cancel. A Safe in production (R3).
    /// @param executors      Accounts that may execute a ready operation. `address(0)` opens it to anyone.
    /// @param functionDelays The initial per-function delays.
    constructor(
        uint256 minDelay,
        address[] memory proposers,
        address[] memory executors,
        FunctionDelay[] memory functionDelays
    ) TimelockController(minDelay, proposers, executors, address(0)) {
        for (uint256 i = 0; i < functionDelays.length; ++i) {
            _setFunctionDelay(functionDelays[i].target, functionDelays[i].selector, functionDelays[i].delay);
        }
    }

    // ---------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------

    /// @notice The delay configured for `selector` on `target`, or 0 if it has none (see {getDelay}).
    function getFunctionDelay(address target, bytes4 selector) public view returns (uint256) {
        return _functionDelays[target][selector];
    }

    /// @notice The delay a call to `selector` on `target` waits: its own delay, never below `minDelay`.
    function getEffectiveDelay(address target, bytes4 selector) public view returns (uint256) {
        uint256 own = _functionDelays[target][selector];
        uint256 floor = getMinDelay();
        return own > floor ? own : floor;
    }

    /// @notice The least delay {schedule} accepts for this call.
    function getDelay(address target, bytes calldata data) public view returns (uint256) {
        // A call without a selector (a plain value transfer, or a fallback) has no function delay.
        if (data.length < 4) return getMinDelay();
        bytes4 selector = bytes4(data[:4]);
        uint256 delay = getEffectiveDelay(target, selector);

        // Re-configuring a delay waits as long as the delay being changed.
        if (target == address(this) && selector == this.setFunctionDelay.selector) {
            (address changedTarget, bytes4 changedSelector, ) = abi.decode(data[4:], (address, bytes4, uint256));
            uint256 current = getEffectiveDelay(changedTarget, changedSelector);
            if (current > delay) delay = current;
        }
        return delay;
    }

    /// @notice The least delay {scheduleBatch} accepts: the longest of its calls'.
    function getBatchDelay(address[] calldata targets, bytes[] calldata payloads) public view returns (uint256 delay) {
        delay = getMinDelay();
        for (uint256 i = 0; i < targets.length && i < payloads.length; ++i) {
            uint256 callDelay = getDelay(targets[i], payloads[i]);
            if (callDelay > delay) delay = callDelay;
        }
    }

    // ---------------------------------------------------------------------------------------
    // Scheduling
    // ---------------------------------------------------------------------------------------

    /// @inheritdoc TimelockController
    /// @dev Also requires `delay` to cover the called function's own delay ({getDelay}).
    function schedule(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public virtual override {
        uint256 required = getDelay(target, data);
        if (delay < required) revert TimelockInsufficientDelay(delay, required);
        super.schedule(target, value, data, predecessor, salt, delay);
    }

    /// @inheritdoc TimelockController
    /// @dev Also requires `delay` to cover the longest function delay in the batch ({getBatchDelay}).
    function scheduleBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata payloads,
        bytes32 predecessor,
        bytes32 salt,
        uint256 delay
    ) public virtual override {
        uint256 required = getBatchDelay(targets, payloads);
        if (delay < required) revert TimelockInsufficientDelay(delay, required);
        // Upstream rejects mismatched lengths, so the bound in getBatchDelay never hides a call.
        super.scheduleBatch(targets, values, payloads, predecessor, salt, delay);
    }

    // ---------------------------------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------------------------------

    /// @notice Sets `selector` on `target` to wait `newDelay`; `0` removes its own delay so it falls
    ///         back to `minDelay`. Callable only by the timelock itself, through a scheduled
    ///         operation that waits at least the delay being changed ({getDelay}).
    function setFunctionDelay(address target, bytes4 selector, uint256 newDelay) external virtual {
        if (msg.sender != address(this)) revert TimelockUnauthorizedCaller(msg.sender);
        _setFunctionDelay(target, selector, newDelay);
    }

    function _setFunctionDelay(address target, bytes4 selector, uint256 newDelay) internal {
        emit FunctionDelayChange(target, selector, _functionDelays[target][selector], newDelay);
        _functionDelays[target][selector] = newDelay;
    }
}
