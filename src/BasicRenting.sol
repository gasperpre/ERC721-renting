// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {RentingCore} from "./RentingCore.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/**
* @author gasperpre
* Basic renting contract.
* The purpose of this smart contract is to enable ERC721 renting without the need for collateral
* and without the need for the ERC721 contracts to support any special renting standard.
* The NFT being rented is locked in this contract for the duration of the lease.
* To see who the NFT is being rented to `userOf(nftContractAddress, tokenId)` can be called.
* The owner of NFT (lesor) should construct an Order and sign it off-chain.
* Same goes for lesee (account who wants to use the NFT).
* Lesor and lesee Orderds can be matched by anyone.
*
* NOTICE: This smart contract is NOT audited or even well tested and should NOT be used in
* production before conducting a security review.
*/
contract BasicRenting is RentingCore {
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
        uint136 price;
        /* On owner side duration is the minimal duration of lease, on user side it is maximum */
        uint40 duration;
        /* Order expiration timestamp, lease must end before */
        uint40 maxExpiration;
        /* Order salt to prevent duplicate hashes */
        uint40 salt;
    }

    struct Lease {
        uint256 id;
        /* User address */
        address lesee;
        /* Lease expiration timestamp */
        uint256 expiration;
    }


    /*--------------- CONSTANTS ---------------*/

    bytes32 constant ORDER_TYPEHASH = keccak256(
        "Order(address nftContractAddress,uint256 tokenId,address lesor,address lesee,address erc20Token,uint136 price,uint40 duration,uint40 maxExpiration,uint40 salt)"
    );

    /*--------------- MAPPINGS ---------------*/

    /* nftContractAddress => tokenId => Lease */
    mapping(address => mapping(uint256 => Lease)) public leases;

    /*--------------- EVENTS ---------------*/

    event OrdersMatched(
        uint256 indexed leaseId,
        address indexed nftContractAddress,
        uint256 indexed tokenId,
        address lesor,
        address lesee,
        address erc20Token,
        uint256 total,
        uint256 expiration
    );

    /*--------------- CONSTRUCTOR ---------------*/

    constructor() RentingCore("BasicLease", "BL", "1") {
    }


    /*--------------- VIEWS ---------------*/

    /**
    * @notice returns owner of the NFT
    * @param _nftContractAddress - address of ERC721 contract
    * @param _tokenId - NFT token ID
    * @return nftOwner - address to which the NFT belongs to
    */
    function ownerOf(address _nftContractAddress, uint256 _tokenId) public view returns(address nftOwner) {
        nftOwner = IERC721(_nftContractAddress).ownerOf(_tokenId);

        if(nftOwner == address(this)) {
            nftOwner = _ownerOf(leases[_nftContractAddress][_tokenId].id); // lease IDs start with 1 so _ownerOf(0) will always be address(0)
        }
    }
    
    /**
    * @notice returns current user (lesee) of given NFT
    * @param _nftContractAddress - address of ERC721 contract
    * @param _tokenId - NFT token ID
    * @return user - address that currently has user rights for the NFT or address(0) if no one has.
    */
    function userOf(address _nftContractAddress, uint256 _tokenId) external view returns(address user) {
        if(leases[_nftContractAddress][_tokenId].expiration >= block.timestamp) {
            user = leases[_nftContractAddress][_tokenId].lesee;
        }
    }

    /**
    * @notice returns lease expiration of given NFT
    * @param _nftContractAddress - address of ERC721 contract
    * @param _tokenId - NFT token ID
    * @return expiration - lease expiration timestamp
    */
    function expirationOf(address _nftContractAddress, uint256 _tokenId) external view returns(uint256 expiration) {
        expiration = leases[_nftContractAddress][_tokenId].expiration;
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
            _order.duration,
            _order.maxExpiration,
            _order.salt
        ));
    }

    /*--------------- EXTERNAL ---------------*/

    /**
    * @notice Match two orders, one from owner (lesor) side and one from user (lesee) side.
    * @notice Can create a new lease or extend an existing one.
    * @param _order1 - Order created by the ERC721 owner (lesor)
    * @param _order2 - Order created by account wanting to use the ERC721 (lesee)
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
    * - _order1 and _order2 must have the same erc20Token
    * - erc20Token must be allowed
    * - _order1.lesor must be ownerOf(_order1.nftContractAddress, _order1.tokenId)
    * - if beginning new lease: 
    *     - there must be no active lease for given NFT
    *     - block.timestamp + _order2.duration must be lower or equal to 
    *       _order1 and _order2 maxExpiration
    * - if extending lease:
    *     - there must be an active lease for given NFT
    *     - _order2.duration + current lease expiration must be lower or equal to _order1 and 
    *       _order2 maxExpiration
    *     - _order2.lesee must be current lease lesee
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
        require(_order1.erc20Token == _order2.erc20Token && erc20Tokens[_order1.erc20Token].isAllowed, "Bad ERC20");
        require(ownerOf(_order1.nftContractAddress, _order1.tokenId) == _order1.lesor, "Invalid token owner");

        Lease storage lease = leases[_order1.nftContractAddress][_order1.tokenId];
        uint256 expiration;
        
        if(lease.expiration >= block.timestamp) {
            require(lease.lesee == _order2.lesee, "Already rented");
            expiration = lease.expiration + _order2.duration; // extend the rent period
        } else {
            expiration = block.timestamp + _order2.duration;
        }

        require(expiration <= _order1.maxExpiration && expiration <= _order2.maxExpiration, "maxExpiration reached");

        
        if(_order1.lesor != msg.sender) {
            bytes32 order1Hash = hashOrder(_order1);
            _fillOrder(_order1.lesor, order1Hash, _signature1);
        }

        if(_order2.lesee != msg.sender) {
            bytes32 order2Hash = hashOrder(_order2);
            _fillOrder(_order2.lesee, order2Hash, _signature2);
        }
    
        uint256 total = _order1.price * _order2.duration;
        uint256 fee = total * erc20Tokens[_order1.erc20Token].feePercentage / 10_000;
        
        lease.lesee = _order2.lesee;
        lease.expiration = expiration;

        if(lease.id == 0) {
            lease.id = _mint(_order1.lesor);
            IERC721(_order1.nftContractAddress).transferFrom(_order1.lesor, address(this), _order1.tokenId);
        }

        ERC20(_order1.erc20Token).safeTransferFrom(_order2.lesee, address(this), total);
        ERC20(_order1.erc20Token).safeTransfer(_order1.lesor, total - fee);

        emit OrdersMatched(lease.id, _order1.nftContractAddress, _order1.tokenId, _order1.lesor, _order2.lesee, _order1.erc20Token, total, expiration);
    }

    /**
    * @notice Retreive the nft from contract if it is not being rented
    * @param _nftContractAddress - address of ERC721 contract
    * @param _tokenId - NFT token ID
    * 
    * requirements:
    * - msg.sender must be ownerOf(_nftContractAddress, _tokenId)
    * - leases[_nftContractAddress][_tokenId].expiration must be less than block.timestamp
    */
    function retrieveNft(address _nftContractAddress, uint256 _tokenId) external {
        require(ownerOf(_nftContractAddress, _tokenId) == msg.sender, "Not NFT owner");
        require(leases[_nftContractAddress][_tokenId].expiration < block.timestamp, "Not expired");

        _burn(leases[_nftContractAddress][_tokenId].id);
        delete leases[_nftContractAddress][_tokenId];

        IERC721(_nftContractAddress).transferFrom(address(this), msg.sender, _tokenId);
    }

    
    /*--------------- ONLY OWNER ---------------*/

    /**
    * @notice withdraw ERC20 tokens from contract
    * @param _currency - address of ERC20 token
    * @param _amount - withdrawal amount
    * 
    * requirements:
    * - msg.sender must be contract owner
    */
    function withdraw(address _currency, uint256 _amount) external onlyOwner {
        ERC20(_currency).transfer(msg.sender, _amount);
    }
}
