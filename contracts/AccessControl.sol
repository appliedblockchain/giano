// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

import './Context.sol';

abstract contract AccessControl is Context {
    error AccessControlUnauthorizedAccount(bytes32 publicKeyHash, bytes32 neededRole);

    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);
    event RoleGranted(bytes32 indexed role, bytes32 indexed publicKeyHash, address indexed sender);
    event RoleRevoked(bytes32 indexed role, bytes32 indexed publicKeyHash, address indexed sender);

    struct RoleData {
        mapping(bytes32 publicKeyHash => bool) hasRole;
        bytes32 adminRole;
    }

    mapping(bytes32 role => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with an {AccessControlUnauthorizedAccount} error including the required role.
     */
    modifier onlyRole(bytes32 role, bytes32 publicKeyHash) {
        _checkRole(role, publicKeyHash);
        _;
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, bytes32 publicKeyHash) public view virtual returns (bool) {
        return _roles[role].hasRole[publicKeyHash];
    }

    // /**
    //  * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `_msgSender()`
    //  * is missing `role`. Overriding this function changes the behavior of the {onlyRole} modifier.
    //  */
    // function _checkRole(bytes32 role) internal view virtual {
    //     _checkRole(role, _msgSender());
    // }

    /**
     * @dev Reverts with an {AccessControlUnauthorizedAccount} error if `account`
     * is missing `role`.
     */
    function _checkRole(bytes32 role, bytes32 publicKeyHash) internal view virtual {
        if (!hasRole(role, publicKeyHash)) {
            revert AccessControlUnauthorizedAccount(publicKeyHash, role);
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, bytes32 publicKeyHash) public virtual onlyRole(getRoleAdmin(role), publicKeyHash) {
        _grantRole(role, publicKeyHash);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, bytes32 publicKeyHash) public virtual onlyRole(getRoleAdmin(role), publicKeyHash) {
        _revokeRole(role, publicKeyHash);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `callerConfirmation`.
     *
     * May emit a {RoleRevoked} event.
     */
    // function renounceRole(bytes32 role, address callerConfirmation) public virtual {
    //     if (callerConfirmation != _msgSender()) {
    //         revert AccessControlBadConfirmation();
    //     }

    //     _revokeRole(role, callerConfirmation);
    // }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Attempts to grant `role` to `account` and returns a boolean indicating if `role` was granted.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, bytes32 publicKeyHash) internal virtual returns (bool) {
        if (!hasRole(role, publicKeyHash)) {
            _roles[role].hasRole[publicKeyHash] = true;
            emit RoleGranted(role, publicKeyHash, _msgSender());
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Attempts to revoke `role` to `account` and returns a boolean indicating if `role` was revoked.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, bytes32 publicKeyHash) internal virtual returns (bool) {
        if (hasRole(role, publicKeyHash)) {
            _roles[role].hasRole[publicKeyHash] = false;
            emit RoleRevoked(role, publicKeyHash, _msgSender());
            return true;
        } else {
            return false;
        }
    }
}
