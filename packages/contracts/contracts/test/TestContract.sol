// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

/**
 * @title TestContract
 * @author Giano Team
 * @notice A simple contract for testing account execution
 * @dev Used in tests to verify that accounts can correctly execute transactions
 */
contract TestContract {
    uint256 public value;
    address public lastCaller;
    string public message;
    mapping(address => uint256) public balances;
    
    event ValueUpdated(uint256 newValue, address updatedBy);
    event MessageUpdated(string newMessage, address updatedBy);
    event EtherReceived(address from, uint256 amount);

    /**
     * @notice Updates the stored value
     * @param _value The new value to store
     */
    function setValue(uint256 _value) external {
        value = _value;
        lastCaller = msg.sender;
        emit ValueUpdated(_value, msg.sender);
    }
    
    /**
     * @notice Updates the stored message
     * @param _message The new message to store
     */
    function setMessage(string calldata _message) external {
        message = _message;
        lastCaller = msg.sender;
        emit MessageUpdated(_message, msg.sender);
    }
    
    /**
     * @notice Deposits ETH to the caller's balance
     */
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit EtherReceived(msg.sender, msg.value);
    }
    
    /**
     * @notice Withdraws ETH from the caller's balance
     * @param _amount The amount to withdraw
     */
    function withdraw(uint256 _amount) external {
        require(balances[msg.sender] >= _amount, "Insufficient balance");
        balances[msg.sender] -= _amount;
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
    }
    
    /**
     * @notice A function that will revert with a custom message
     * @param _message The error message
     */
    function willRevert(string calldata _message) external pure {
        revert(_message);
    }
    
    /**
     * @notice A function that performs multiple operations
     * @param _value The value to store
     * @param _message The message to store
     */
    function multiOperation(uint256 _value, string calldata _message) external payable {
        value = _value;
        message = _message;
        lastCaller = msg.sender;
        if (msg.value > 0) {
            balances[msg.sender] += msg.value;
            emit EtherReceived(msg.sender, msg.value);
        }
        emit ValueUpdated(_value, msg.sender);
        emit MessageUpdated(_message, msg.sender);
    }
    
    /**
     * @notice Getter function that returns multiple values
     * @return The current value, message, and last caller
     */
    function getState() external view returns (uint256, string memory, address) {
        return (value, message, lastCaller);
    }
    
    /**
     * @notice Allows the contract to receive ETH
     */
    receive() external payable {
        emit EtherReceived(msg.sender, msg.value);
    }
} 