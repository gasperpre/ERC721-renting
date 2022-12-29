// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/BasicRenter.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";
import {ERC721Mock} from "@openzeppelin/contracts/mocks/ERC721Mock.sol";

contract CounterTest is Test {
    BasicRenter internal basicRenter;
    ERC20Mock internal erc20Mock;
    ERC721Mock internal erc721Mock;

    uint256 internal alicePrivateKey = 0xA11CE;
    uint256 internal bobPrivateKey = 0xB0B;

    address internal alice = vm.addr(alicePrivateKey);
    address internal bob = vm.addr(bobPrivateKey);

    function setUp() public {
        basicRenter = new BasicRenter();
        erc20Mock = new ERC20Mock("TestERC20", "T", alice, 100e18);
        erc721Mock = new ERC721Mock("TestERC721", "T");
        basicRenter.setERC20Token(address(erc20Mock), true, 1000);
    }

    function testMatchOrders() public {
        erc721Mock.mint(bob, 1);
        vm.prank(bob);
        erc721Mock.approve(address(basicRenter), 1);
        vm.prank(alice);
        erc20Mock.approve(address(basicRenter), 10e18);

        BasicRenter.Order memory orderBob = BasicRenter.Order({
            nftContractAddress: address(erc721Mock),
            tokenId: 1,
            from: bob,
            to: address(0),
            erc20Token: address(erc20Mock),
            price: 1e16,
            duration: 100,
            expiration: uint40(block.timestamp + 2000),
            salt: 1
        });

        bytes32 orderBobHash = basicRenter.hashOrder(orderBob);

        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(bobPrivateKey, basicRenter.hashToSign(orderBobHash));

        BasicRenter.Order memory orderAlice = BasicRenter.Order({
            nftContractAddress: address(erc721Mock),
            tokenId: 1,
            from: address(0),
            to: alice,
            erc20Token: address(erc20Mock),
            price: 1e16,
            duration: 100,
            expiration: uint40(block.timestamp + 2000),
            salt: 1
        });
        
        bytes32 orderAliceHash = basicRenter.hashOrder(orderAlice);

        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(alicePrivateKey, basicRenter.hashToSign(orderAliceHash));
        vm.prank(address(this));
        basicRenter.matchOrders(orderBob, orderAlice, abi.encodePacked(rB,sB,vB), abi.encodePacked(rA,sA,vA));

        (address to, uint256 until)= basicRenter.rents(address(erc721Mock), 1);

        assertEq(to, alice);
        assertEq(until, block.timestamp + 100);
        assertEq(basicRenter.userOf(address(erc721Mock), 1), alice);
        assertEq(basicRenter.ownerOf(address(erc721Mock), 1), bob);
        assertEq(basicRenter.filledOrCanceled(alice, orderAliceHash), true);
        assertEq(basicRenter.filledOrCanceled(bob, orderBobHash), true);
    }
}
