// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

interface IBounty {

    struct Operation {
        address contractAddress;
        string functionName;
    }

    struct Bounty {
        uint256 bountyId;
        string name;
        string description;
        bytes32 rewardType;
        uint256 reward;
        Operation operation;
    }

    struct Commission {
        uint256 bountyId;
        uint256 value;
        uint256 lastClaimedAt;
        bool isVerified;
    }

    event CreateBounty(uint256 bountyId, string name);

    event JoinedBounty(uint256 bountyId, address joiner);

    event CommissionAdded(uint256 bountyId, uint256 value);

    event CommissionClaimed(uint256 bountyId, uint256 value);

    event CommissionVerified(uint256 bountyId, uint256 value);
}
