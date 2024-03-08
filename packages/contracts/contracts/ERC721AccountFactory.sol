// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC721Account} from "./ERC721Account.sol";

contract ERC721AccountFactory {
    struct User {
        uint256 id;
        ERC721Account.PublicKey publicKey;
        address account;
    }

    mapping(uint256 => User) users;

    event UserCreated(uint256 userId, ERC721Account.PublicKey publicKey, address account);

    function getUser(uint256 id) public view returns (User memory) {
        return users[id];
    }

    function createUser(uint256 id, ERC721Account.PublicKey memory publicKey) public {
        ERC721Account account = new ERC721Account(publicKey);
        users[id] = User(id, publicKey, address(account));
        emit UserCreated(id, publicKey, address(account));
    }
}
