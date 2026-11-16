// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PrivateEventEmitter
 * @dev Declares the PrivateEvent shared by UCEF and its privacy modules (e.g. PrivateVotes),
 * so contracts that inherit several of them declare the event only once.
 */
abstract contract PrivateEventEmitter {
    /**
     * @dev Private Event for selective visibility of on-chain events
     * @param allowedViewers List of addresses authorized to view the event
     * @param eventType The keccak256 hash of the original event signature
     * @param payload The ABI-encoded event arguments
     */
    event PrivateEvent(
        address[] allowedViewers,
        bytes32 indexed eventType,
        bytes payload
    );
}
