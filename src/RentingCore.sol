// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {AllowedERC20} from "./utils/AllowedERC20.sol";

/**
* @author gasperpre
* Core renting contract.
* The purpose of this smart contract is to hold the basic functions that are
* intherited by all the renting types.
*/
contract RentingCore is ERC721, Ownable2Step, AllowedERC20 {

    /*--------------- CONSTANTS ---------------*/
    
    bytes32 immutable DOMAIN_SEPARATOR;

    /*--------------- VARIABLES ---------------*/

    uint256 leaseCounter;

    /*--------------- MAPPINGS ---------------*/

    /* orderCreator => orderHash => filled */
    mapping(address => mapping(bytes32 => bool)) public filledOrCanceled;


    /*--------------- EVENTS ---------------*/

    event OrderFilled(
        address indexed signer,
        bytes32 indexed order
    );

    event OrderCanceled(
        address indexed signer,
        bytes32 indexed order
    );

    /*--------------- CONSTRUCTOR ---------------*/

    constructor(string memory _name, string memory _symbol,  string memory _version) ERC721(_name, _symbol) {
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256(bytes(_name)),
                keccak256(bytes(_version)),
                block.chainid,
                address(this)
            )
        );
    }

    /*--------------- HELPERS ---------------*/

    function hashToSign(bytes32 _orderHash)
        public
        view
        returns (bytes32 hash)
    {
        return keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            _orderHash
        ));
    }
    
    function _requireNotFilledOrCanceled(address _signer, bytes32 _orderHash) internal view {
        require(!filledOrCanceled[_signer][_orderHash], "Already filledOrCanceled");
    }

    function _requireValidSignature(address _signer, bytes32 _orderHash, bytes calldata _signature) internal view {
        require(
                SignatureChecker.isValidSignatureNow(_signer, hashToSign(_orderHash), _signature),
                "Invalid signature"
        );
    }

    /**
    * @notice Flag orderHash for signer as filledOrCanceled
    * @param _signer - Order signer address
    * @param _orderHash - Order hash
    * 
    * requiremetns:
    * - _orderHash for _signer must not be flaged filledOrCanceled
    */
    function _fillOrCancelOrder(address _signer, bytes32 _orderHash) internal {
        _requireNotFilledOrCanceled(_signer, _orderHash);
        filledOrCanceled[_signer][_orderHash] = true;
    }
    
     /**
    * @notice Checks if order signature is valid and marks order as filled
    * @param _signer - Order signer address
    * @param _orderHash - Order hash
    * @param _signature - Order signature by the signer
    * 
    * requiremetns:
    * - _signature must be valid for given orderHash and signer address
    * - _orderHash for _signer must not be flaged filledOrCanceled
    */
    function _fillOrder(address _signer, bytes32 _orderHash, bytes calldata _signature) internal {
            _requireValidSignature(_signer, _orderHash, _signature);
            _fillOrCancelOrder(_signer, _orderHash);
            emit OrderFilled(_signer, _orderHash);
    }

    /*--------------- EXTERNAL ---------------*/

    /**
    * @notice Flags order hash for msg.sender as filledOrCancelled
    * @param _orderHash - hash of the order being canceled
    *
    * requirements:
    * - _orderHash for msg.sender must not be flagged filledOrCancelled
    */
    function cancelOrder(bytes32 _orderHash) external {
        _fillOrCancelOrder(msg.sender, _orderHash);
        emit OrderCanceled(msg.sender, _orderHash);
    }
    
    /*--------------- ONLY OWNER ---------------*/

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
        _setERC20Token(_erc20Token, _isAllowed, _feePercentage);
    }
}