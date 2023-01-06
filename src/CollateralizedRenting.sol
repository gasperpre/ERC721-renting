// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {RentingCore} from "./RentingCore.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {SafeCastLib} from "solmate/utils/SafeCastLib.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/**
* @author gasperpre
* Collateralized ERC721 renting contract.
* The purpose of this smart contract is to enable ERC721 renting without the need for the 
* ERC721 contracts to support any special renting standard.
* The lesee has to lock ERC20 collateral in this contract for the duration of lease. If he
* does not return the leased NFT by executing closeLease, the lease can be liquidated and 
* collateral sent to lesor by executing liquidateLease.
* Lease is represented by an ERC721 token. Owner of this token is considerred lesor and
* is the one who will receive NFT or collateral when lease ends.
* When creating a new lease, the owner of NFT (lesor) should construct an Order and sign
* it off-chain. Same goes for lesee (account who wants to use the NFT).
* Lesor and lesee Orderds can be matched by anyone.
*
* NOTICE: This smart contract is NOT audited or even well tested and should NOT be used in
* production before conducting a security review.
*/
contract CollateralizedRenting is RentingCore {
    using SafeTransferLib for ERC20;

    /*--------------- STRUCTS ---------------*/

    struct Order {
        /* ERC721 contract address */
        address nftContractAddress;
        /* NFT token ID */
        uint256 tokenId;
        /* NFT owner address, address(0) on lesee side Order means anyone can be owner */
        address lesor;
        /* User address, address(0) on lesor side Order means anyone can become user */
        address lesee;
        /* Payment ERC20 token address, must be allowed */
        address erc20Token;
        /* Rental price per second */
        uint128 price;
        /* On lesor side collateral is the minimum collateral amount, on lesee it is maximum */
        uint128 collateral;
        /* On owner side duration is the minimal duration of lease, on user side it is maximum */
        uint40 duration;
        /* Order expiration timestamp, lease must end before */
        uint40 maxExpiration;
        /* Order salt to prevent duplicate hashes */
        uint176 salt;
    }

    struct Lease {
        /* ERC721 contract address */
        address nftContractAddress;
        /* NFT token ID */
        uint256 tokenId;
        /* Lease expiration timestamp */
        uint128 expiration;
        /* Lease collateral */
        uint128 collateral;
        /* Collateral erc20 */
        address erc20Token;
    }


    /*--------------- CONSTANTS ---------------*/

    bytes32 constant ORDER_TYPEHASH = keccak256(
        "Order(address nftContractAddress,uint256 tokenId,address lesor,address lesee,address erc20Token,uint136 price,uint128 collateral,uint40 duration,uint40 maxExpiration,uint176 salt)"
    );

    /*--------------- VARIABLES ---------------*/

    address feeReceiver;

    /*--------------- MAPPINGS ---------------*/

    /* (lease) token ID => Lease */
    mapping(uint256 => Lease) public leases;

    /*--------------- EVENTS ---------------*/

    event OrdersMatched(
        uint256 indexed leaseId,
        Lease lease,
        address lesor,
        address lesee,
        uint256 total
    );

    event LeaseClosed(
        uint256 indexed leaseId,
        address closer
    );

    event LeaseLiquidated(
        uint256 indexed leaseId,
        address liquidator
    );

    /*--------------- CONSTRUCTOR ---------------*/

    constructor(address _feeReceiver) RentingCore("CollateralizedLease", "CL", "1") {
        feeReceiver = _feeReceiver;
    }

    /*--------------- HELPERS ---------------*/

    function hashOrder(Order memory _order)
        public
        pure
        returns (bytes32 hash)
    {
        return keccak256(abi.encode(
            ORDER_TYPEHASH,
            _order.nftContractAddress,
            _order.lesor,
            _order.lesee,
            _order.erc20Token,
            _order.price,
            _order.collateral,
            _order.duration,
            _order.maxExpiration,
            _order.salt
        ));
    }

    /*--------------- EXTERNAL ---------------*/

    /**
    * @notice Match two orders, one from owner (lesor) side and one from user (lesee) side.
    * @param _order1 - Order created by the NFT owner (lesor)
    * @param _order2 - Order created by account wanting to use the NFT (lesee)
    * @param _signature1 - ECDSA or ERC1271 signature of _order1 from the _order1.lesor address,
    *                      not required if msg.sender == _order1.lesor 
    * @param _signature2 - ECDSA or ERC1271 singature of _order2 from the _order2.lesee address,
    *                      not required if msg.sender == _order2.lesee
    * requirements:
    * - _order1 and _order2 must have the same nftContractAddress and tokenId 
    * - _order1.lesee must be address(0) or equal to _order2.lesee
    * - _order2.lesor must be address(0) or equal to _order1.lesor
    * - _order1.price must be lower or equal to _order2.price
    * - _order1.duration must be lower or equal to _order2.duration
    * - _order1.collateral must be lower or equal to _order2.collateral
    * - _order1 and _order2 must have the same erc20Token
    * - erc20Token must be allowed
    * - _order1.lesor must be owner of the NFT
    * - block.timestamp + _order2.duration must be lower or equal to 
    *   _order1 and _order2 maxExpiration
    */
    function matchOrders(
        Order calldata _order1,
        Order calldata _order2,
        bytes calldata _signature1,
        bytes calldata _signature2
    ) external {
        require(_order1.nftContractAddress == _order2.nftContractAddress && _order1.tokenId == _order2.tokenId, "Token missmatch");
        require(_order1.lesee == address(0) || _order1.lesee == _order2.lesee, "Order.lesee missmatch");
        require(_order2.lesor == address(0) || _order2.lesor == _order1.lesor, "Order.lesor missmatch");
        require(_order1.price <= _order2.price, "Order.price missmatch");
        require(_order1.duration <= _order2.duration, "Order.duration missmatch");
        require(_order1.collateral <= _order2.collateral, "Order.collateral missmatch");
        require(_order1.erc20Token == _order2.erc20Token && erc20Tokens[_order1.erc20Token].isAllowed, "Bad ERC20");
        require(IERC721(_order1.nftContractAddress).ownerOf(_order1.tokenId) == _order1.lesor, "Invalid token owner");

        uint256 expiration = block.timestamp + _order2.duration;

        require(expiration <= _order1.maxExpiration && expiration <= _order2.maxExpiration, "maxExpiration reached");

        
        if(_order1.lesor != msg.sender) {
            _fillOrder(_order1.lesor, hashOrder(_order1), _signature1);
        }

        if(_order2.lesee != msg.sender) {
            _fillOrder(_order2.lesee, hashOrder(_order2), _signature2);
        }

        uint256 leaseId = leaseCounter++;
        Lease memory lease = Lease(_order1.nftContractAddress, _order1.tokenId, SafeCastLib.safeCastTo128(expiration), _order1.collateral, _order1.erc20Token);
        leases[leaseId] = lease;

        uint256 total = _order1.price * _order2.duration;
        uint256 fee = total * erc20Tokens[_order1.erc20Token].feePercentage / 10_000;

        _mint(_order1.lesor, leaseId);

        IERC721(_order1.nftContractAddress).transferFrom(_order1.lesor, _order2.lesee, _order1.tokenId);

        if(fee > 0) {
            ERC20(_order1.erc20Token).safeTransferFrom(_order2.lesee, feeReceiver, fee);
        }

        ERC20(_order1.erc20Token).safeTransferFrom(_order2.lesee, _order1.lesor, total - fee);
        ERC20(_order1.erc20Token).safeTransferFrom(_order2.lesee, address(this), _order1.collateral);

        emit OrdersMatched(
            leaseId,
            lease,
            _order1.lesor,
            _order2.lesee,
            total
            );
    }

    /**
    * @notice Close a lease. Transfer NFT to lesor and ERC20 collateral to lesee.
    *
    * requirements:
    * - _leaseId must belong to a valid lease and match _nftContractAddress and
    *   _tokenId
    * - msg.sender must be the NFT owner
    */
    function closeLease(uint256 _leaseId, address _nftContractAddress, uint256 _tokenId) external {
        require(IERC721(_nftContractAddress).ownerOf(_tokenId) == msg.sender, "Not token owner");
        Lease memory lease = leases[_leaseId];
        require(lease.tokenId == _tokenId && lease.nftContractAddress == _nftContractAddress, "Token missmatch");

        address to = _ownerOf(_leaseId);

        delete leases[_leaseId];
        _burn(_leaseId);

        ERC20(lease.erc20Token).safeTransfer(msg.sender, lease.collateral);
        IERC721(_nftContractAddress).transferFrom(msg.sender, to, _tokenId);

        emit LeaseClosed(_leaseId, msg.sender);
    }

    /**
    * @notice Liquidate a lease. Transger ERC20 collateral to lesor.
    *
    * requirements:
    * - _leaseId must belong to a valid lease and match _nftContractAddress and
    *   _tokenId
    * - lease must be expired
    */
    function liquidateLease(uint256 _leaseId, address _nftContractAddress, uint256 _tokenId) external {
        Lease memory lease = leases[_leaseId];
        require(lease.expiration < block.timestamp, "Lease not ended");
        require(lease.tokenId == _tokenId && lease.nftContractAddress == _nftContractAddress, "Token missmatch");
        
        address leaseOwner = _ownerOf(_leaseId);

        delete leases[_leaseId];
        _burn(_leaseId);

        ERC20(lease.erc20Token).safeTransfer(leaseOwner, lease.collateral);

        emit LeaseLiquidated(_leaseId, msg.sender);
    }

    
    /*--------------- ONLY OWNER ---------------*/

    /**
    * @notice set feeReceiver address
    */
    function setFeeReceiver(address _feeReceiver) external onlyOwner {
        feeReceiver = _feeReceiver;
    }
}
