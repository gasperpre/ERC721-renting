// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/CollateralizedRenting.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";
import {ERC721Mock} from "@openzeppelin/contracts/mocks/ERC721Mock.sol";

contract CounterTest is Test {
    CollateralizedRenting internal collateralizedRenting;
    ERC20Mock internal erc20Mock;
    ERC721Mock internal erc721Mock;

    uint256 internal alicePrivateKey = 0xA11CE;
    uint256 internal bobPrivateKey = 0xB0B;

    address internal alice = vm.addr(alicePrivateKey);
    address internal bob = vm.addr(bobPrivateKey);

    function setUp() public {
        collateralizedRenting = new CollateralizedRenting(address(1));
        erc20Mock = new ERC20Mock("TestERC20", "T", alice, 100e18);
        erc721Mock = new ERC721Mock("TestERC721", "T");
        collateralizedRenting.setERC20Token(address(erc20Mock), true, 1000);
    }

    function testMatchOrders() public {
        erc721Mock.mint(bob, 1);
        vm.prank(bob);
        erc721Mock.approve(address(collateralizedRenting), 1);
        vm.prank(alice);
        erc20Mock.approve(address(collateralizedRenting), 10e18);

        CollateralizedRenting.Order memory orderBob = CollateralizedRenting.Order({
            nftContractAddress: address(erc721Mock),
            tokenId: 1,
            lesor: bob,
            lesee: address(0),
            erc20Token: address(erc20Mock),
            price: 1e16,
            collateral: 1e18,
            duration: 100,
            maxExpiration: uint40(block.timestamp + 2000),
            salt: 1
        });

        bytes32 orderBobHash = collateralizedRenting.hashOrder(orderBob);

        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(bobPrivateKey, collateralizedRenting.hashToSign(orderBobHash));

        CollateralizedRenting.Order memory orderAlice = CollateralizedRenting.Order({
            nftContractAddress: address(erc721Mock),
            tokenId: 1,
            lesor: address(0),
            lesee: alice,
            erc20Token: address(erc20Mock),
            price: 1e16,
            collateral: 1e18,
            duration: 100,
            maxExpiration: uint40(block.timestamp + 2000),
            salt: 1
        });
        
        bytes32 orderAliceHash = collateralizedRenting.hashOrder(orderAlice);

        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(alicePrivateKey, collateralizedRenting.hashToSign(orderAliceHash));

        vm.prank(address(this));
        collateralizedRenting.matchOrders(orderBob, orderAlice, abi.encodePacked(rB,sB,vB), abi.encodePacked(rA,sA,vA));

        (address nftContractAddress, uint256 tokenId, uint128 expiration, uint128 collateral, address erc20Token) = collateralizedRenting.leases(0);

        assertEq(expiration, block.timestamp + 100);
        assertEq(nftContractAddress, address(erc721Mock));
        assertEq(tokenId, 1);
        assertEq(collateral, 1e18);
        assertEq(erc20Token, address(erc20Mock));
        assertEq(erc721Mock.ownerOf(1), alice);
        assertEq(collateralizedRenting.ownerOf(0), bob);
    }
}
