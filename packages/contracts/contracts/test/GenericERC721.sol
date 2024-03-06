// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ERC721} from '@openzeppelin/contracts/token/ERC721/ERC721.sol';

contract GenericERC721 is ERC721 {

	constructor() ERC721('GenericERC721', 'NFT') {}

	function mint(address to, uint256 tokenId) public {
		_mint(to, tokenId);
	}
}