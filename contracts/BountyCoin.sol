// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {ERC20Taxable} from "./extensions/ERC20Taxable.sol";

/**
 * @title BountyCoin
 * @custom:website www.datacache.xyz
 * @notice ERC20 implementation with variable, but optional, transfers taxing.
 */
contract BountyCoin is ERC20Taxable {
    constructor(
        string memory name,
        string memory symbol,
        uint256 totalSupply_
    ) ERC20Taxable(name, symbol) {
        _mint(msg.sender, totalSupply_);
    }
}
