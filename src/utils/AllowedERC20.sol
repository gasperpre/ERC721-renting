// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

/**
* @author gasperpre
*/
contract AllowedERC20 {

    struct ERC20Token {
        /* ERC20 token is allowed flag */
        bool isAllowed;
        /* ERC20 platform fee percentage, 100 = 1% */
        uint32 feePercentage;
    }

    /* erc20Token => ERC20Token */
    mapping(address => ERC20Token) public erc20Tokens; 

    event ERC20Set(
        address indexed erc20Token,
        bool isAllowed,
        uint32 feePercentage
    );

    function _onlyAllowedERC20(address _erc20Token) internal view {
        require(erc20Tokens[_erc20Token].isAllowed, "ERC20 not allowed");
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
    function _setERC20Token(address _erc20Token, bool _isAllowed, uint32 _feePercentage) internal {
        require(_feePercentage <= 1000, "Fee too high");
        erc20Tokens[_erc20Token].isAllowed = _isAllowed;
        erc20Tokens[_erc20Token].feePercentage = _feePercentage;
        emit ERC20Set(_erc20Token, _isAllowed, _feePercentage);
    }
}