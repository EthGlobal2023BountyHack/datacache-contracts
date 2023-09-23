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

    /// @dev Address id to commission info
    mapping(address => Commission[]) public commissions;

    constructor(
        address _trustedForwarder
    ) ERC2771Context(_trustedForwarder) {
        // Setup roles
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(OWNER_ROLE, _msgSender());
        _setupRole(BOUNTY_MANAGER, _msgSender());
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
     */
    function createBounty(
        string calldata name,
        string calldata description,
        string calldata rewardType,
        uint256 reward,
        address tokenAddress
    ) external payable {
        bytes32 bountyType = keccak256(abi.encodePacked(rewardType));
        require(bountyType == ERC20_REWARD || bountyType == ERC721_REWARD || bountyType == ERC1155_REWARD , "Invalid Reward type");

        uint256 nextBountyId = bountyIds++;

        if(bountyType == ERC20_REWARD){
            // TODO logic for erc20
        } else if(bountyType == ERC721_REWARD){
            // TODO logic for erc721
        } else if(bountyType == ERC1155_REWARD){
            // TODO logic for erc1155
        }

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
            if(bountyType == ERC20_REWARD){
                // TODO logic for erc20
            } else if(bountyType == ERC721_REWARD){
                // TODO logic for erc721
            } else if(bountyType == ERC1155_REWARD){
                // TODO logic for erc1155
            }

            // TODO Update commission payout to verified
        }
    }

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
