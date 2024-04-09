// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Account} from "./Account.sol";

contract AccountFactory {
    struct User {
        uint256 id;
        Account.PublicKey publicKey;
        address account;
    }

    mapping(uint256 => User) users;

    event UserCreated(uint256 userId, Account.PublicKey publicKey, address account);

    function getUser(uint256 id) public view returns (User memory) {
        return users[id];
    }

    function createUser(uint256 id, Account.PublicKey memory publicKey) public {
        Account account = new Account(publicKey);
        users[id] = User(id, publicKey, address(account));
        emit UserCreated(id, publicKey, address(account));
    }
}
