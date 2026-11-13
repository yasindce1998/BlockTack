// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Vulnerable vault with external call before state update
/// @notice Deliberately vulnerable fixture for BTV-L2-001 (reentrancy):
///         withdraw sends ETH before zeroing the balance, so the
///         receiver can re-enter and drain the vault.
contract ReentrantVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "nothing to withdraw");

        // Vulnerable: external call before state update.
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0;
    }

    receive() external payable {}
}
