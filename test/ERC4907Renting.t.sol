// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/ERC4907Renting.sol";
import {ERC20Mock} from "@openzeppelin/contracts/mocks/ERC20Mock.sol";
import {ERC4907Mock} from "../src/mocks/ERC4907Mock.sol";

contract CounterTest is Test {
    ERC4907Renting internal rentingContract;
    ERC20Mock internal erc20Mock;
    ERC4907Mock internal erc4907Mock;

    uint256 internal alicePrivateKey = 0xA11CE;
    uint256 internal bobPrivateKey = 0xB0B;

    address internal alice = vm.addr(alicePrivateKey);
    address internal bob = vm.addr(bobPrivateKey);

    function setUp() public {
        rentingContract = new ERC4907Renting();
        erc20Mock = new ERC20Mock("TestERC20", "T", alice, 100e18);
        erc4907Mock = new ERC4907Mock("TestERC721", "T");
        rentingContract.setERC20Token(address(erc20Mock), true, 1000);
    }

    function testMatchOrders() public {
        erc4907Mock.mint(bob, 1);
        vm.prank(bob);
        erc4907Mock.approve(address(rentingContract), 1);
        vm.prank(alice);
        erc20Mock.approve(address(rentingContract), 10e18);

        ERC4907Renting.Order memory orderBob = ERC4907Renting.Order({
            nftContractAddress: address(erc4907Mock),
            tokenId: 1,
            lessor: bob,
            lessee: address(0),
            erc20Token: address(erc20Mock),
            price: 1e16,
            duration: 100,
            maxExpiration: uint40(block.timestamp + 2000),
            salt: 1
        });

        bytes32 orderBobHash = rentingContract.hashOrder(orderBob);

        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(bobPrivateKey, rentingContract.hashToSign(orderBobHash));

        ERC4907Renting.Order memory orderAlice = ERC4907Renting.Order({
            nftContractAddress: address(erc4907Mock),
            tokenId: 1,
            lessor: address(0),
            lessee: alice,
            erc20Token: address(erc20Mock),
            price: 1e16,
            duration: 100,
            maxExpiration: uint40(block.timestamp + 2000),
            salt: 1
        });
        
        bytes32 orderAliceHash = rentingContract.hashOrder(orderAlice);

        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(alicePrivateKey, rentingContract.hashToSign(orderAliceHash));

        vm.prank(address(this));
        rentingContract.matchOrders(orderBob, orderAlice, abi.encodePacked(rB,sB,vB), abi.encodePacked(rA,sA,vA));

        assertEq(erc4907Mock.userOf(1), alice);
        assertEq(erc4907Mock.ownerOf(1), address(rentingContract));
        assertEq(erc4907Mock.userExpires(1), block.timestamp + 100);
        assertEq(rentingContract.ownerOf(address(erc4907Mock), 1), bob);
        assertEq(rentingContract.filledOrCanceled(alice, orderAliceHash), true);
        assertEq(rentingContract.filledOrCanceled(bob, orderBobHash), true);
    }
}
