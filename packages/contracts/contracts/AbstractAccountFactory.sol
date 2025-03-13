// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';

/// @title Abstract Account Factory
/// @notice Abstract contract for creating and managing user accounts with associated public keys
/// @dev This contract serves as a base for implementing account factories with specific deployment logic
abstract contract AbstractAccountFactory {
    /// @notice Structure representing a user with their ID, public key, and account address
    /// @param id Unique identifier for the user
    /// @param publicKey User's public key for authentication
    /// @param account Address of the user's deployed account contract
    struct User {
        uint256 id;
        Types.PublicKey publicKey;
        address account;
    }

    /// @notice Mapping from user ID to User struct
    mapping(uint256 => User) private _users;

    /// @notice Emitted when a new user account is created
    /// @param userId The ID of the created user
    /// @param publicKey The public key associated with the user
    /// @param account The address of the deployed account contract
    event UserCreated(uint256 userId, Types.PublicKey publicKey, address account);

    /// @notice Error thrown when attempting to create a user with an ID that already exists
    /// @param id The ID that was attempted to be used
    error UserAlreadyExists(uint256 id);

    /// @notice Retrieves user information by their ID
    /// @param id The ID of the user to look up
    /// @return User struct containing the user's information
    function getUser(uint256 id) public view returns (User memory) {
        return _users[id];
    }

    /// @notice Creates a new user with the given ID and public key
    /// @dev Deploys a new account contract and associates it with the user
    /// @param id The ID for the new user
    /// @param publicKey The public key to associate with the user
    /// @custom:throws UserAlreadyExists if a user with the given ID already exists
    function createUser(uint256 id, Types.PublicKey memory publicKey) public {
        if (_users[id].account != address(0)) {
            revert UserAlreadyExists(id);
        }
        address account = deployContract(publicKey);
        _users[id] = User(id, publicKey, account);

        emit UserCreated(id, publicKey, account);
    }

    /// @notice Internal function to deploy the actual account contract
    /// @dev Must be implemented by derived contracts
    /// @param publicKey The public key to use in the account contract deployment
    /// @return address The address of the deployed account contract
    function deployContract(Types.PublicKey memory publicKey) internal virtual returns (address);
}
