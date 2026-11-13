// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceFeed {
    function latestAnswer() external view returns (int256);
}

/// @title Naive collateral vault priced by a single feed
/// @notice Deliberately vulnerable fixture for BTV-L2-003 (manipulable
///         price oracle). The vault values collateral with a spot feed
///         that an attacker can skew, then borrows against the inflated
///         value — the Mango Markets / Euler exploit shape.
contract NaiveOracleVault {
    IPriceFeed public immutable priceFeed;
    uint256 public constant COLLATERAL_FACTOR = 80; // 80%

    mapping(address => uint256) public deposits;

    constructor(address feed) {
        priceFeed = IPriceFeed(feed);
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external {
        // Vulnerable: trusts a manipulable spot price at face value.
        uint256 collateralValue = (deposits[msg.sender] * uint256(priceFeed.latestAnswer())) / 1e8;
        require((collateralValue * COLLATERAL_FACTOR) / 100 >= amount, "insufficient collateral");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    receive() external payable {}
}
