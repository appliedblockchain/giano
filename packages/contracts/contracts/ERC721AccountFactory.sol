// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC721Account} from './ERC721Account.sol';

contract ERC721AccountFactory {
	event AccountCreated(ERC721Account.PublicKey pubKey, address account);

	function createAccount(ERC721Account.PublicKey memory publicKey) public {
		ERC721Account account = new ERC721Account(publicKey);
		emit AccountCreated(publicKey, address(account));
	}
}