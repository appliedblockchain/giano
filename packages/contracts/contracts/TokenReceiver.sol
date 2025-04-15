// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IERC721Receiver} from '@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol';
import {IERC1155Receiver} from '@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol';
import {IERC165} from '@openzeppelin/contracts/utils/introspection/IERC165.sol';

abstract contract TokenReceiver is IERC721Receiver, IERC1155Receiver {
    /**
     * @notice Handles the receipt of an ERC721 token
     * @dev Implements IERC721Receiver interface
     * @return The ERC721Receiver selector
     */
    function onERC721Received(address, address, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }

    /**
     * @notice Handles the receipt of a single ERC1155 token
     * @dev Implements IERC1155Receiver interface
     * @return The ERC1155Receiver selector
     */
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155Received.selector;
    }

    /**
     * @notice Handles the receipt of multiple ERC1155 tokens
     * @dev Implements IERC1155Receiver interface
     * @return The ERC1155BatchReceived selector
     */
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure override returns (bytes4) {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    /**
     * @notice Indicates which interfaces this contract supports
     * @dev Implements the ERC-165 standard
     * @param interfaceId The interface identifier to check
     * @return Boolean indicating whether the interface is supported
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return
            interfaceId == type(IERC165).interfaceId || interfaceId == type(IERC1155Receiver).interfaceId || interfaceId == type(IERC721Receiver).interfaceId;
    }
}
