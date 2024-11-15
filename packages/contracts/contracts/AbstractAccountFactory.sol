// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Types} from './Types.sol';

abstract contract AbstractAccountFactory {
    struct User {
        uint256 id;
        Types.PublicKey publicKey;
        address account;
    }

    mapping(uint256 => User) private _users;

    event UserCreated(uint256 userId, Types.PublicKey publicKey, address account);
    error UserAlreadyExists(uint256 id);

    function getUser(uint256 id) public view returns (User memory) {
        return _users[id];
    }

    function createUser(uint256 id, Types.PublicKey memory publicKey) public {
        if (_users[id].account != address(0)) {
            revert UserAlreadyExists(id);
        }
        address account = deployContract(publicKey);
        _users[id] = User(id, publicKey, account);

        emit UserCreated(id, publicKey, account);
    }

    function deployContract(Types.PublicKey memory publicKey) internal virtual returns (address);
}
