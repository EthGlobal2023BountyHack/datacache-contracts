import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
describe("CampaignMarket", function () {
  const trustedForwarder = "0x84a0856b038eaAd1cC7E297cF34A7e72685A8693";

  async function setup() {
    const [owner, alice, bob] = await ethers.getSigners();

    // DEPLOY ERC20 TOKEN
    const BountyCoin = await ethers.getContractFactory("BountyCoin");

    const bnty = await BountyCoin.deploy(
      "BountyCoin",
      "BNTY",
      ethers.BigNumber.from("100000000000000000000000000")
    );

    await bnty.deployed();

    console.log("Deployed to:", bnty.address);

    const SpongePoseidonLib = await ethers.getContractFactory("SpongePoseidon");
    const spongePoseidonLib = await SpongePoseidonLib.deploy();
    await spongePoseidonLib.deployed();

    console.log(`SpongePoseidon Address---> ${spongePoseidonLib.address}`)

    const PoseidonUnit6L = await ethers.getContractFactory("PoseidonUnit6L");
    const poseidon6Lib = await PoseidonUnit6L.deploy();
    await spongePoseidonLib.deployed();

    console.log(`PoseidonUnit6L Address---> ${poseidon6Lib.address}`)

    const CampaignMarket = await ethers.getContractFactory("CampaignMarket", {
      libraries: {
      SpongePoseidon: spongePoseidonLib,
          PoseidonUnit6L: poseidon6Lib
    }});

    const campaignMarket = await CampaignMarket.deploy(
      trustedForwarder
    );

    await campaignMarket.deployed();

    return { campaignMarket, owner, alice, bob, bnty };
  }

  describe("Deployment", function () {
    let campaignMarket;
    let owner;
    let alice;
    let bob;
    let bnty;

    before(async () => {
      ({ campaignMarket, owner, alice, bob, bnty } =
        await loadFixture(setup));
    });
  });
});
