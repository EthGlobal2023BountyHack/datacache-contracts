// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {ERC2771Context, Context} from "@openzeppelin/contracts/metatx/ERC2771Context.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/interfaces/IERC20.sol";
import "@openzeppelin/contracts/interfaces/IERC721.sol";
import "@openzeppelin/contracts/interfaces/IERC1155.sol";
import {NativeMetaTransaction} from "./common/NativeMetaTransaction.sol";
import {IBounty} from "./interfaces/IBounty.sol";
import "./lib/GenesisUtils.sol";
import "./interfaces/ICircuitValidator.sol";
import "./verifiers/ZKPVerifier.sol";
import "hardhat/console.sol";

/**
 * @title CampaignMarket
 * @custom:website www.datacache.xyz
 * @dev ZK Integration inspired by https://github.com/0xPolygonID/tutorial-examples/blob/main/on-chain-verification/
 * @notice A campaign marketplace for data bounties
 */
contract CampaignMarket is
    ERC2771Context,
    NativeMetaTransaction,
    AccessControl,
    ReentrancyGuard,
    ZKPVerifier,
    IBounty
{

    uint64 public constant VERIFY_REQUEST_ID = 1;

    // @dev Reward types
    bytes32 public constant ERC20_REWARD = keccak256(abi.encodePacked("ERC20_REWARD"));
    bytes32 public constant ERC721_REWARD = keccak256(abi.encodePacked("ERC721_REWARD"));
    bytes32 public constant ERC1155_REWARD = keccak256(abi.encodePacked("ERC1155_REWARD"));

    // @dev Mapping that stores id to address and address to id to restrict more than 1 proof submission
    mapping(uint256 => address) public idToAddress;
    mapping(address => uint256) public addressToId;

    /// @dev Roles
    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant BOUNTY_MANAGER =
        keccak256("BOUNTY_MANAGER");

    /// @dev The bounty ids
    uint256 public bountyIds = 0;

    /// @dev The emergency withdraw address
    address public treasury;

    /// @dev Address id to commission info
    mapping(address => Commission[]) public commissions;

    /// @dev Bounty id to Bounty
    mapping(uint256 => Bounty) public bounties;

    /// @dev Bounty id to bounty ownership
    mapping(uint256 => BountyBalance) public bountyBalance;

    constructor(
        address _trustedForwarder
    ) ERC2771Context(_trustedForwarder) {
        // Setup roles
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(OWNER_ROLE, _msgSender());
        _setupRole(BOUNTY_MANAGER, _msgSender());

        // Setup emergency receiver
        treasury = payable(_msgSender());
    }

    // ========================================
    // Bounty CRUD
    // ========================================

    /**
     * @notice Creates a new data bounty
     * @param name The display name
     * @param description The description of data bounty
     * @param rewardType The reward type as a string, "ERC20_REWARD", "ERC721REWARD", "ERC1155_REWARD"
     * @param reward The reward value
     * @param tokenAddress token address for bounty collateral, zero address if native token
     * @param totalRewards The total rewards that are claimable
     */
    function createBounty(
        string calldata name,
        string calldata description,
        string calldata rewardType,
        uint256 reward,
        uint256 totalRewards,
        address tokenAddress
    ) external payable nonReentrant {
        bytes32 bountyType = keccak256(abi.encodePacked(rewardType));
        require(bountyType == ERC20_REWARD || bountyType == ERC721_REWARD || bountyType == ERC1155_REWARD , "Invalid Reward type");

        uint256 nextBountyId = bountyIds++;

        if(bountyType == ERC20_REWARD){
            // Process transferring token to escrow
            if(tokenAddress == address(0)){
                require(msg.value >= totalRewards, "Must pass at least one bounty worth of collateral");
                (bool sent, bytes memory data) = payable(address(this)).call{value: msg.value}("");
                // Store escrow balances by bounty id
                require(sent, "Failed to send native");
            } else {
                IERC20(tokenAddress).transferFrom(
                    _msgSender(),
                    address(this),
                    totalRewards
                );
            }

            // Add to bounty balance
            bountyBalance[nextBountyId] = BountyBalance({
                ownerOf: _msgSender(),
                balance: totalRewards
            });

            bounties[nextBountyId] = Bounty({
                bountyId: nextBountyId,
                name: name,
                description: description,
                rewardType: bountyType,
                reward: reward,
                rewardAddress: tokenAddress,
                payoutFrom: address(this)
            });

        } else if(bountyType == ERC721_REWARD){
            // TODO logic for erc721
        } else if(bountyType == ERC1155_REWARD){
            // TODO logic for erc1155
        }

    }

    /**
     * @notice Allow anyone to add more bounty balance to keep it running
     * @param bountyId The bounty id
     * @param totalRewards The total rewards that are claimable,
     * @param tokenAddress token address for bounty collateral, zero address if native token
     */
    function addBountyBalance(
        uint256 bountyId,
        uint256 totalRewards,
        address tokenAddress
    ) external payable {
        Bounty storage bounty = bounties[bountyId];
        if(bounty.rewardType == ERC20_REWARD){
            // Process transferring token to escrow
            if(tokenAddress == address(0)){
                require(msg.value >= totalRewards, "Must pass at least one bounty worth of collateral");
                (bool sent, bytes memory data) = payable(address(this)).call{value: msg.value}("");
                require(sent, "Failed to send native");
            } else {
                IERC20(tokenAddress).transferFrom(
                    _msgSender(),
                    address(this),
                    totalRewards
                );
            }
            // Add to bounty balance
            bountyBalance[bountyId].balance += totalRewards;
        }
    }

    /**
     * @notice Revokes a bounty, returns remaining balance back to owner
     * @param bountyId The bounty id reference
     */
    function revokeBounty(
        uint256 bountyId
    ) external payable nonReentrant {
        Bounty storage bounty = bounties[bountyId];
        BountyBalance storage current = bountyBalance[bountyId];
        // Return any left over token balance
        if(current.balance > 0){
            if(bounty.rewardType == ERC20_REWARD){
                uint256 refundable = current.balance;

                // Zero any balance remaining
                bountyBalance[bountyId].balance = 0;

                address ownerOf = payable(current.ownerOf);

                if(bounty.rewardAddress == address(0)){
                    (bool refunded, bytes memory data) = ownerOf.call{value: refundable}("");
                    require(refunded, "Failed to send native");
                } else {
                    IERC20(bounty.rewardAddress).transferFrom(
                        address(this),
                        ownerOf,
                        refundable
                    );
                }
            }
        }
    }

    /// @notice Returns bounty owner
    function getBountyOwner(uint256 bountyId) external returns (address) {
        return bountyBalance[bountyId].ownerOf;
    }

    /// @notice Returns bounty balance
    function getRemainingBounty(uint256 bountyId) external returns (uint256) {
        return bountyBalance[bountyId].balance;
    }

    /// @notice Returns all bounties
    function getAllBounties() external view returns (bytes[] memory) {
        bytes[] memory allBounties = new bytes[](bountyIds);

        Bounty memory current;

        for (uint256 i; i < bountyIds;) {
            current = bounties[i];

            allBounties[i] = abi.encode(
                current.bountyId,
                current.name,
                current.description,
                current.reward,
                current.rewardType,
                bountyBalance[i].balance,
                current.rewardAddress,
                current.payoutFrom
            );

            unchecked {
                ++i;
            }
        }

        return allBounties;
    }

    // ========================================
    // Reward CRUD
    // ========================================

    /**
     * @dev Adds a commission value for a particular token id
     * @param _address The address of commission owner
     * @param _bountyId The bounty id of the commission
     */
    function addCommission(
        uint256 _address,
        uint256 _bountyId
    ) internal {

    }

    /**
     * @dev Removes a commission value for a particular address and bounty
     * @param _address The address of commission owner
     * @param _bountyId The bounty id of the commission
     */
    function removeCommission(
        uint256 _address,
        uint256 _bountyId
    ) internal {

    }

    /**
     * @notice Verify commission for a particular bounty
     * @dev Set by a trusted bounty manager
     * @param _bountyId The bounty id
     * @param _receiver The address for the commission
     * @param _amount The amount of value to apply
     */
    function verifyCommission(
        uint256 _bountyId,
        address _receiver,
        uint256 _amount
    ) external onlyRole(BOUNTY_MANAGER) {
        // Update commissions for particular receiver and bounty
        emit CommissionVerified(_bountyId, _amount);
    }

    /**
     * @notice Returns all commission details for a batch of addresses in bytes32 for read
     * @param _owners The array of addresses
     */
    function getCommissions(
        address[] calldata _owners
    ) external view returns (bytes[] memory) {
        bytes[] memory allCommissions = new bytes[](_owners.length);

        Commission[] memory ownerCommissions;
        Commission memory current;

        for (uint256 i; i < _owners.length;) {
            ownerCommissions = commissions[_owners[i]];

            for (uint256 j; j < ownerCommissions.length;) {
                if(ownerCommissions.length > 0){
                    current = ownerCommissions[j];
                    allCommissions[i] = abi.encode("test");
                } else {
                    allCommissions[i] = "";
                }
                unchecked {
                    ++j;
                }
            }
            unchecked {
                ++i;
            }
        }

        return allCommissions;
    }

    /**
     * @dev Issues tokens only if there is a sufficient balance in the contract
     * @param contractAddress - Contract address
     * @param recipient - Address of recipient
     * @param amount - Amount in wei to transfer
     */
    function _safeTransferRewards(address contractAddress, address recipient, uint256 amount) internal {
        uint256 balance = IERC20(contractAddress).balanceOf(address(this));
        if (amount <= balance) {
            IERC20(contractAddress).transfer(recipient, amount);
        }
    }

    /**
     * @notice Withdraws any tokens from the contract
     * @param contractAddress - Token contract address
     * @param amount - Amount in wei to withdraw
     */
    function emergencyWithdrawERC20(address contractAddress, uint256 amount) external onlyRole(OWNER_ROLE) {
        _safeTransferRewards(contractAddress, _msgSender(), amount);
    }

    /// @notice Withdraws funds from contract
    function emergencyWithdraw() public onlyOwner {
        uint256 balance = address(this).balance;
        (bool success, ) = treasury.call{value: balance}("");
        require(success, "Unable to withdraw native token");
    }

    /**
     * @notice Sets the treasury recipient
     * @param _treasury The treasury address
     */
    function setTreasury(address _treasury) external onlyRole(OWNER_ROLE) {
        treasury = payable(_treasury);
    }


    // ========================================
    // Proof verification
    // ========================================

    function _beforeProofSubmit(
        uint64, /* requestId */
        uint256[] memory inputs,
        ICircuitValidator validator
    ) internal view override {
        // check that the challenge input of the proof is equal to the msg.sender
        address addr = GenesisUtils.int256ToAddress(
            inputs[validator.getChallengeInputIndex()]
        );
        require(
            _msgSender() == addr,
            "address in the proof is not a sender address"
        );
    }

    function _afterProofSubmit(
        uint64 requestId,
        uint256[] memory inputs,
        ICircuitValidator validator
    ) internal override {
        require(
            requestId == VERIFY_REQUEST_ID && addressToId[_msgSender()] == 0,
            "proof can not be submitted more than once"
        );

        uint256 id = inputs[validator.getChallengeInputIndex()];

        if (idToAddress[id] == address(0)) {

            addressToId[_msgSender()] = id;
            idToAddress[id] = _msgSender();

            // e.g., payout erc20 or airdrop mint
//            if(bountyType == ERC20_REWARD){
//                // TODO logic for erc20
//            } else if(bountyType == ERC721_REWARD){
//                // TODO logic for erc721
//            } else if(bountyType == ERC1155_REWARD){
//                // TODO logic for erc1155
//            }

            // TODO Update commission payout to verified
        }
    }

    receive() external payable {}

    fallback() external payable {}

    // ========================================
    // Native meta transactions
    // ========================================

    function _msgSender()
        internal
        view
        virtual
        override(ERC2771Context, Context)
        returns (address)
    {
        return ERC2771Context._msgSender();
    }

    function _msgData()
        internal
        view
        virtual
        override(ERC2771Context, Context)
        returns (bytes calldata)
    {
        return ERC2771Context._msgData();
    }
}
