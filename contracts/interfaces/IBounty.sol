// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./ICircuitValidator.sol";

interface IBounty {

    struct BountyInfo {
        string name;
        string description;
        string imageUrl;
    }

    struct Bounty {
        uint256 bountyId;
        string name;
        string description;
        string imageUrl;
        bytes32 rewardType;
        uint256 reward;
        address rewardAddress;
        address payoutFrom;
    }

    struct BountyBalance {
        address ownerOf;
        uint256 balance;
    }

    struct ZKPBountyRequest {
        uint64 requestId;
        ICircuitValidator validator;
        uint256 schema;
        uint256 claimPathKey;
        uint256 operator;
        uint256[] value;
    }

    event CreatedBounty(address ownerOf, uint256 bountyId, uint256 reward, bytes32 rewardType, address rewardAddress);

    event NewBountyRequestSet(
        uint64 requestId,
        ICircuitValidator validator,
        uint256 schema,
        uint256 claimPathKey,
        uint256 operator,
        uint256[] value
    );

    event ClaimedBounty(address addr, uint256 bountyId, uint256 value, bytes32 rewardType, address tokenAddress);

}
