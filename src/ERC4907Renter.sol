// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IERC4907} from "./libraries/IERC4907.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {SafeTransferLib} from "solmate/utils/SafeTransferLib.sol";
import {SafeCastLib} from "solmate/utils/SafeCastLib.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";

/**
* ERC4907 renting contract.
* The purpose of this smart contract is to enable ERC721 renting without the need for collateral
* but it requires NFTs to implement ERC4907 renting standard.
* The NFT being rented is locked in this contract for the duration of the rent.
* The owner of NFT should construct an Order and sign it off-chain. Same goes for the account
* that wants to rent / use the NFT.
* Owner and user side Orderds can be matched by anyone (owner, user, relayer...).
*
* NOTICE: This smart contract is NOT audited or even well tested and should NOT be used in
* production before conducting a security review.
*
* Author: gasperpre
*/
contract ERC4907Renter is Ownable2Step {
    using SafeTransferLib for ERC20;


    /*--------------- STRUCTS ---------------*/

    struct ERC20Token {
        /* ERC20 token is allowed flag */
        bool isAllowed;
        /* ERC20 platform fee percentage, 100 = 1% */
        uint32 feePercentage;
    }

    struct Order {
        /* ERC721 contract address */
        address nftContractAddress;
        /* NFT token ID */
        uint256 tokenId;
        /* NFT owner address, address(0) on user side Order means anyone can be owner */
        address from;
        /* User address, address(0) on owner side Order means anyone can become user */
        address to;
        /* Payment ERC20 token address, must be allowed */
        address erc20Token;
        /* Price of rental per second */
        uint136 price;
        /* On owner side duration is the minimal duration of rental, on user side it is maximum */
        uint40 duration;
        /* Order expiration timestamp, rental must end before */
        uint40 expiration;
        /* Order salt to prevent duplicate hashes */
        uint40 salt;
    }

    /*--------------- CONSTANTS ---------------*/

    bytes32 constant ORDER_TYPEHASH = keccak256(
        "Order(address nftContractAddress,address tokenId,address from,address to,address erc20Token,uint176 price,uint40 minDuration,uint40 expiration)"
    );
    
    bytes32 immutable DOMAIN_SEPARATOR;

    /*--------------- MAPPINGS ---------------*/

    /* nftContractAddress => tokenId => Owner . Store the owner of nft when nft is transferred to contract */
    mapping(address => mapping(uint256 => address)) public owners;
    /* erc20Token => ERC20Token */
    mapping(address => ERC20Token) public erc20Tokens; 
    /* orderCreator => orderHash => filled */
    mapping(address => mapping(bytes32 => bool)) public filledOrCanceled;


    /*--------------- EVENTS ---------------*/

    event OrdersMatched(
        address nftContractAddress,
        uint256 tokenId,
        address from,
        address to,
        address erc20Token,
        uint256 price,
        uint256 duration,
        uint256 until,
        uint256 fee
    );

    event OrderFilled(
        address signer,
        bytes32 order
    );

    event OrderCanceled(
        address signer,
        bytes32 order
    );

    event ERC20Set(
        address erc20Token,
        bool isAllowed,
        uint32 feePercentage
    );


    /*--------------- CONSTRUCTOR ---------------*/

    constructor() {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes("BasicRenter")),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
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

    function hashOrder(Order memory order)
        public
        pure
        returns (bytes32 hash)
    {
        return keccak256(abi.encode(
            ORDER_TYPEHASH,
            order.nftContractAddress,
            order.from,
            order.to,
            order.erc20Token,
            order.price,
            order.duration,
            order.expiration,
            order.salt
        ));
    }

    function hashToSign(bytes32 orderHash)
        public
        view
        returns (bytes32 hash)
    {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            orderHash
        ));
    }
    
    function requireNotFilledOrCanceled(address signer, bytes32 orderHash) internal view {
        require(!filledOrCanceled[signer][orderHash], "Already filledOrCanceled");
    }

    function requireValidSignature(address signer, bytes32 orderHash, bytes calldata signature) internal view {
        require(
                SignatureChecker.isValidSignatureNow(signer, hashToSign(orderHash), signature),
                "Invalid signature"
        );
    }

    /**
    * @notice Flag orderHash for signer as filledOrCanceled
    * @param signer - Order signer address
    * @param orderHash - Order hash
    * 
    * requiremetns:
    * - orderHash for signer must not be flaged filledOrCanceled
    */
    function fillOrCancelOrder(address signer, bytes32 orderHash) internal {
        requireNotFilledOrCanceled(signer, orderHash);
        filledOrCanceled[signer][orderHash] = true;
    }
    
    /**
    * @notice Checks if order signature is valid and marks order as filled
    * @param signer - Order signer address
    * @param orderHash - Order hash
    * @param signature - Order signature by the signer
    * 
    * requiremetns:
    * - signature must be valid for given orderHash and signer address
    * - orderHash for signer must not be flaged filledOrCanceled
    */
    function fillOrder(address signer, bytes32 orderHash, bytes calldata signature) internal {
            requireValidSignature(signer, orderHash, signature);
            fillOrCancelOrder(signer, orderHash);
            emit OrderFilled(signer, orderHash);
    }

    function getUser(address nftContractAddress, uint256 tokenId) internal view returns(address user) {
        (bool success, bytes memory data) = nftContractAddress.staticcall(
            abi.encodeWithSignature('userOf(uint256 tokenId)',tokenId)
            );

        require(success, "getUser failed");
        (user) = abi.decode(data, (address));
    }

    function getExpiration(address nftContractAddress, uint256 tokenId) internal view returns(uint256 expiration) {
        (bool success, bytes memory data) = nftContractAddress.staticcall(
            abi.encodeWithSignature('userExpires(uint256 tokenId)',tokenId)
            );

        require(success, "getExpiraion failed");
        (expiration) = abi.decode(data, (uint256));
    }

    /*--------------- EXTERNAL ---------------*/

    /**
    * @notice Match two orders, one from owner side and one from user side.
    * @notice Can begine new renting period or extend an existing one.
    * @param _order1 - Order created by the ERC721 owner
    * @param _order2 - Order created by the address wanting to use the ERC721
    * @param _signature1 - ECDSA or ERC1271 signature of _order1 from the _order1.from address,
    *                      not required if msg.sender == _order1.from 
    * @param _signature2 - ECDSA or ERC1271 singature of _order2 from the _order2.to address,
    *                      not required if msg.sender == _order2.to
    * requirements:
    * - _order1 and _order2 must have the same nftContractAddress and tokenId 
    * - _order1.to must be address(0) or equal to _order2.to
    * - _order2.from must be address(0) or equal to _order1.from
    * - _order1.price must be lower or equal to _order2.price
    * - _order1.duration must be lower or equal to _order2.duration
    * - _order1 and _order2 must have the same erc20Token
    * - erc20Token must be allowed
    * - _order1.from must be ownerOf(_order1.nftContractAddress, _order1.tokenId)
    * - if beginning new rent: 
    *     - block.timestamp + _order2.duration must be lower or equal to 
    *       _order1 and _order2 expiration
    *     - getExpiration(_order1.nftContractAddress, _order1.tokenId) must be lower than
    *       block.timestamp
    * - if extending rent:
    *     - _order2.duration + getExpiration(_order1.nftContractAddress, _order1.tokenId)
    *       must be lower or equal to _order1 and _order2 expiration
    *     - getExpiration(_order1.nftContractAddress, _order1.tokenId) must be higher or equal
    *       to block.timestamp
    *     - getUser(_order1.nftContractAddress, _order1.tokenId) must be _order2.to
    */
    function matchOrders(
        Order calldata _order1,
        Order calldata _order2,
        bytes calldata _signature1,
        bytes calldata _signature2
    ) external {
        require(_order1.nftContractAddress == _order2.nftContractAddress && _order1.tokenId == _order2.tokenId, "Token missmatch");
        require(_order1.to == address(0) || _order1.to == _order2.to, "Order.to missmatch");
        require(_order2.from == address(0) || _order2.from == _order1.from, "Order.from missmatch");
        require(_order1.price <= _order2.price, "Order.price missmatch");
        require(_order1.duration <= _order2.duration, "Order.duration missmatch");
        require(_order1.erc20Token == _order2.erc20Token && erc20Tokens[_order1.erc20Token].isAllowed, "Bad ERC20");
        require(IERC165(_order1.nftContractAddress).supportsInterface(type(IERC4907).interfaceId), "Non rentable NFT");
        require(ownerOf(_order1.nftContractAddress, _order1.tokenId) == _order1.from, "Invalid token owner");

        uint256 expiration = getExpiration(_order1.nftContractAddress, _order1.tokenId);

        if(expiration >= block.timestamp) {
            require(getUser(_order1.nftContractAddress, _order1.tokenId) == _order2.to, "Already rented");
            expiration += _order2.duration;
        } else {
            expiration = block.timestamp + _order2.duration;
        }

        require(expiration <= _order1.expiration && expiration <= _order2.expiration, "Cannot rent for that long");
        
        if(_order1.from != msg.sender) {
            bytes32 order1Hash = hashOrder(_order1);
            fillOrder(_order1.from, order1Hash, _signature1);
        }

        if(_order2.to != msg.sender) {
            bytes32 order2Hash = hashOrder(_order2);
            fillOrder(_order2.to, order2Hash, _signature2);
        }


        uint256 total = _order1.price * _order2.duration;
        uint256 fee = total * erc20Tokens[_order1.erc20Token].feePercentage / 10_000;

        IERC4907(_order1.nftContractAddress).setUser(_order1.tokenId, _order2.to, SafeCastLib.safeCastTo64(expiration));

        if(IERC721(_order1.nftContractAddress).ownerOf(_order1.tokenId) != address(this)) {
            owners[_order1.nftContractAddress][_order1.tokenId] = _order1.from;
            IERC721(_order1.nftContractAddress).transferFrom(_order1.from, address(this), _order1.tokenId);
        }

        ERC20(_order1.erc20Token).safeTransferFrom(_order2.to, address(this), total);
        ERC20(_order1.erc20Token).safeTransfer(_order1.from, total - fee);

        emit OrdersMatched(_order1.nftContractAddress, _order1.tokenId, _order1.from, _order2.to, _order1.erc20Token, _order1.price, _order2.duration, expiration, fee);
    }

    /**
    * @notice Flags order hash for msg.sender as filledOrCancelled
    * @param _orderHash - hash of the order being canceled
    *
    * requirements:
    * - _orderHash for msg.sender must not be flagged filledOrCancelled
    */
    function cancelOrder(bytes32 _orderHash) external {
        fillOrCancelOrder(msg.sender, _orderHash);
        emit OrderCanceled(msg.sender, _orderHash);
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
        require(getExpiration(_nftContractAddress, _tokenId) < block.timestamp, "Not expired");

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

    /**
    * @notice Set ERC20 token isAllowed and feePercentage
    * @param _erc20Token - address of ERC20 token
    * @param _isAllowed - isAllowed flag
    * @param _feePercentage - platform fee percentage
    * 
    * requirements:
    * - _feePercentage must be less or equal to 1000 (10%)
    */
    function setERC20Token(address _erc20Token, bool _isAllowed, uint32 _feePercentage) external onlyOwner {
        require(_feePercentage <= 1000, "Fee too high");
        erc20Tokens[_erc20Token].isAllowed = _isAllowed;
        erc20Tokens[_erc20Token].feePercentage = _feePercentage;
        emit ERC20Set(_erc20Token, _isAllowed, _feePercentage);
    }
}