// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Stand-in for a Chainlink-style aggregator whose data feed
///         stopped updating two days ago — the BTV-L4-001 fixture: a
///         protocol consuming this feed acts on stale prices.
contract StalePriceFeed {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        // Round 1, $2000, but the last update was 2 days ago.
        return (1, 2_000e8, block.timestamp - 2 days, block.timestamp - 2 days, 1);
    }

    function latestAnswer() external view returns (int256) {
        return 2_000e8;
    }
}
