// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC721SafeTransferAccount} from "./ERC721SafeTransferAccount.sol";

contract ERC721SafeTransferAccountFactory {
    struct User {
        uint256 id;
        ERC721SafeTransferAccount.PublicKey publicKey;
        address account;
    }

    mapping(uint256 => User) users;

    event UserCreated(uint256 userId, ERC721SafeTransferAccount.PublicKey publicKey, address account);

    function getUser(uint256 id) public view returns (User memory) {
        return users[id];
    }

    function createUser(uint256 id, ERC721SafeTransferAccount.PublicKey memory publicKey) public {
        ERC721SafeTransferAccount account = new ERC721SafeTransferAccount(publicKey);
        users[id] = User(id, publicKey, address(account));
        emit UserCreated(id, publicKey, address(account));
    }
}