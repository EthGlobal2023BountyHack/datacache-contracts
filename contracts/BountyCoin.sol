// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/**
 * @title BountyCoin
 * @custom:website www.datacache.xyz
 * @notice ERC20 implementation with variable, but optional, transfers taxing.
 */
contract BountyCoin is ERC20("BountyCoin", "BNTY") {
    constructor(uint256 supply) {
        _mint(msg.sender, supply);
    }
}
