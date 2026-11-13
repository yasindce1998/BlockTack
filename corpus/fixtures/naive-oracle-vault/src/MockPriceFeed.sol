// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Stand-in for a Chainlink-style aggregator whose price anyone
///         can set. Represents an oracle backed by a manipulable liquidity
///         pool (the fixture's attack surface).
contract MockPriceFeed {
    int256 public price = 2_000e8; // $2000.00, 8 decimals

    function setPrice(int256 p) external {
        price = p;
    }

    function latestAnswer() external view returns (int256) {
        return price;
    }
}
