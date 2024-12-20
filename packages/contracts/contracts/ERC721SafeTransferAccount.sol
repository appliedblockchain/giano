// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import { Account } from './Account.sol';
import { Types } from './Types.sol';
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract ERC721SafeTransferAccount is Account, IERC721Receiver {
    constructor(Types.PublicKey memory publicKey) Account(publicKey) {}

    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
		return IERC721Receiver.onERC721Received.selector;
	}
}
