// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// A tiny deliberately-vulnerable fixture for symbolic-execution
/// validation: claim() pays out only with the right guess, capped by
/// the vault balance. The solver must discover both the secret and the
/// maximal payout amount on its own.
contract LockedVault {
    uint256 constant SECRET = 0x1337beefcafe;
    uint256 public loot;

    constructor() payable {
        loot = msg.value;
    }

    function claim(uint256 guess, uint256 amount) external {
        require(guess == SECRET, "wrong guess");
        require(amount <= loot, "too greedy");
        loot -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "pay failed");
    }
}
