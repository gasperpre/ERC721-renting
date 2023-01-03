// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {RentingCore} from "./RentingCore.sol";
import {IERC4907} from "./interfaces/IERC4907.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {SafeCastLib} from "solmate/utils/SafeCastLib.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

/**
* @author gasperpre
* ERC4907 renting contract.
* The purpose of this smart contract is to enable ERC721 renting without the need for collateral
* but it requires NFTs to implement ERC4907 renting standard.
* The NFT being rented is locked in this contract for the duration of the rent.
* The owner of NFT (lesor) should construct an Order and sign it off-chain.
* Same goes for lesee (account who wants to use the NFT).
* Lesor and lesee Orderds can be matched by anyone.
*
* NOTICE: This smart contract is NOT audited or even well tested and should NOT be used in
* production before conducting a security review.
*/
contract ERC4907Renting is RentingCore {
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

    /*--------------- CONSTANTS ---------------*/

    bytes32 constant ORDER_TYPEHASH = keccak256(
        "Order(address nftContractAddress,uint256 tokenId,address lesor,address lesee,address erc20Token,uint136 price,uint40 duration,uint40 maxExpiration,uint40 salt)"
    );
    
    /*--------------- MAPPINGS ---------------*/

    /* nftContractAddress => tokenId => Owner . Store the owner of nft when nft is transferred to contract */
    mapping(address => mapping(uint256 => address)) public owners;

    /*--------------- EVENTS ---------------*/

    event OrdersMatched(
        address indexed nftContractAddress,
        uint256 indexed tokenId,
        address lesor,
        address lesee,
        address erc20Token,
        uint256 price,
        uint256 expiration,
        uint256 fee
    );

    /*--------------- CONSTRUCTOR ---------------*/

    constructor() RentingCore("ERC4907Renting", "1") {
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
            nftOwner = owners[_nftContractAddress][_tokenId];
        }
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

    function _getUser(address _nftContractAddress, uint256 _tokenId) internal view returns(address user) {
        (bool success, bytes memory data) = _nftContractAddress.staticcall(
            abi.encodeWithSignature('userOf(uint256 tokenId)',_tokenId)
            );

        require(success, "getUser failed");
        (user) = abi.decode(data, (address));
    }

    function _getExpiration(address _nftContractAddress, uint256 _tokenId) internal view returns(uint256 expiration) {
        (bool success, bytes memory data) = _nftContractAddress.staticcall(
            abi.encodeWithSignature('userExpires(uint256 tokenId)',_tokenId)
            );

        require(success, "getExpiraion failed");
        (expiration) = abi.decode(data, (uint256));
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

        uint256 expiration = _getExpiration(_order1.nftContractAddress, _order1.tokenId);

        if(expiration >= block.timestamp) {
            require(_getUser(_order1.nftContractAddress, _order1.tokenId) == _order2.lesee, "Already rented");
            expiration += _order2.duration;
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

        if(IERC721(_order1.nftContractAddress).ownerOf(_order1.tokenId) != address(this)) {
            owners[_order1.nftContractAddress][_order1.tokenId] = _order1.lesor;
            IERC721(_order1.nftContractAddress).transferFrom(_order1.lesor, address(this), _order1.tokenId);
        }

        IERC4907(_order1.nftContractAddress).setUser(_order1.tokenId, _order2.lesee, SafeCastLib.safeCastTo64(expiration));

        ERC20(_order1.erc20Token).safeTransferFrom(_order2.lesee, address(this), total);
        ERC20(_order1.erc20Token).safeTransfer(_order1.lesor, total - fee);

        emit OrdersMatched(_order1.nftContractAddress, _order1.tokenId, _order1.lesor, _order2.lesee, _order1.erc20Token, _order1.price, expiration, fee);
    }

    /**
    * @notice Retreive the nft from contract if it is not being rented
    * @param _nftContractAddress - address of ERC721 contract
    * @param _tokenId - NFT token ID
    * 
    * requirements:
    * - msg.sender must be ownerOf(_nftContractAddress, _tokenId)
    * - getExpiration(_nftContractAddress, _tokenId) must be less than block.timestamp
    */
    function retrieveNft(address _nftContractAddress, uint256 _tokenId) external {
        require(ownerOf(_nftContractAddress, _tokenId) == msg.sender, "Not NFT owner");
        require(_getExpiration(_nftContractAddress, _tokenId) < block.timestamp, "Not expired");

        delete owners[_nftContractAddress][_tokenId];

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