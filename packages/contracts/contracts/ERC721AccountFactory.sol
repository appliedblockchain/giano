// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC721Account} from './ERC721Account.sol';
contract ERC721AccountFactory {

	struct User {
		uint256 id;
		bytes32[2] publicKey;
		address account;
	}

	mapping(uint256 => User) users;

	event AccountCreated(address account, bytes32[2] publicKey);

	function createAccount(uint256 id, bytes32[2] memory publicKey) public {
		ERC721Account account = new ERC721Account(publicKey);
		users[id] = User(id, publicKey, address(account));
		emit AccountCreated(address(account), publicKey);
	}
}