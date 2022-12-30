// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/BasicRenting.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";
import {ERC721Mock} from "@openzeppelin/contracts/mocks/ERC721Mock.sol";

contract CounterTest is Test {
    BasicRenting internal basicRenting;
    ERC20Mock internal erc20Mock;
    ERC721Mock internal erc721Mock;

    uint256 internal alicePrivateKey = 0xA11CE;
    uint256 internal bobPrivateKey = 0xB0B;

    address internal alice = vm.addr(alicePrivateKey);
    address internal bob = vm.addr(bobPrivateKey);

    function setUp() public {
        basicRenting = new BasicRenting();
        erc20Mock = new ERC20Mock("TestERC20", "T", alice, 100e18);
        erc721Mock = new ERC721Mock("TestERC721", "T");
        basicRenting.setERC20Token(address(erc20Mock), true, 1000);
    }

    function testMatchOrders() public {
        erc721Mock.mint(bob, 1);
        vm.prank(bob);
        erc721Mock.approve(address(basicRenting), 1);
        vm.prank(alice);
        erc20Mock.approve(address(basicRenting), 10e18);

        BasicRenting.Order memory orderBob = BasicRenting.Order({
            nftContractAddress: address(erc721Mock),
            tokenId: 1,
            lesor: bob,
            lesee: address(0),
            erc20Token: address(erc20Mock),
            price: 1e16,
            duration: 100,
            maxExpiration: uint40(block.timestamp + 2000),
            salt: 1
        });

        bytes32 orderBobHash = basicRenting.hashOrder(orderBob);

        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(bobPrivateKey, basicRenting.hashToSign(orderBobHash));

        BasicRenting.Order memory orderAlice = BasicRenting.Order({
            nftContractAddress: address(erc721Mock),
            tokenId: 1,
            lesor: address(0),
            lesee: alice,
            erc20Token: address(erc20Mock),
            price: 1e16,
            duration: 100,
            maxExpiration: uint40(block.timestamp + 2000),
            salt: 1
        });
        
        bytes32 orderAliceHash = basicRenting.hashOrder(orderAlice);

        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(alicePrivateKey, basicRenting.hashToSign(orderAliceHash));

        vm.prank(address(this));
        basicRenting.matchOrders(orderBob, orderAlice, abi.encodePacked(rB,sB,vB), abi.encodePacked(rA,sA,vA));

        (address lesee, uint256 expiration)= basicRenting.leases(address(erc721Mock), 1);

        assertEq(lesee, alice);
        assertEq(expiration, block.timestamp + 100);
        assertEq(basicRenting.userOf(address(erc721Mock), 1), alice);
        assertEq(basicRenting.ownerOf(address(erc721Mock), 1), bob);
        assertEq(basicRenting.filledOrCanceled(alice, orderAliceHash), true);
        assertEq(basicRenting.filledOrCanceled(bob, orderBobHash), true);
    }
}
