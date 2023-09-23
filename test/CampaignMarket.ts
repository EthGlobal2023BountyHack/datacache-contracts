import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";

const deploySig = async () => {
  const stateAddress = "0x624ce98D2d27b20b8f8d521723Df8fC4db71D79D"; // current iden3 state smart contract on main
  const verifierContractWrapperName = "VerifierSigWrapper";
  const validatorContractName = "CredentialAtomicQuerySigValidator";
  const VerifierSigWrapper = await ethers.getContractFactory(
      verifierContractWrapperName
  );
  const verifierWrapper = await VerifierSigWrapper.deploy();

  await verifierWrapper.deployed();

  console.log(
      verifierContractWrapperName,
      " deployed to:",
      verifierWrapper.address
  );

  const CredentialAtomicQueryValidator = await ethers.getContractFactory(
      validatorContractName
  );

  const CredentialAtomicQueryValidatorProxy = await upgrades.deployProxy(
      CredentialAtomicQueryValidator,
      [verifierWrapper.address, stateAddress] // current state address on mumbai
  );

  await CredentialAtomicQueryValidatorProxy.deployed();

  console.log(
      validatorContractName,
      " deployed to:",
      CredentialAtomicQueryValidatorProxy.address
  );

}

const deployMTP = async () => {
  const stateAddress = "0x624ce98D2d27b20b8f8d521723Df8fC4db71D79D"; // current iden3 state smart contract on main
  const verifierContractWrapperName = "VerifierMTPWrapper";
  const validatorContractName = "CredentialAtomicQueryMTPValidator";
  const VerifierMTPWrapper = await ethers.getContractFactory(
      verifierContractWrapperName
  );
  const verifierWrapper = await VerifierMTPWrapper.deploy();

  await verifierWrapper.deployed();

  console.log(
      verifierContractWrapperName,
      " deployed to:",
      verifierWrapper.address
  );

  const CredentialAtomicQueryValidator = await ethers.getContractFactory(
      validatorContractName
  );

  const CredentialAtomicQueryValidatorProxy = await upgrades.deployProxy(
      CredentialAtomicQueryValidator,
      [verifierWrapper.address, stateAddress] // current state address on mumbai
  );

  await CredentialAtomicQueryValidatorProxy.deployed();

  console.log(
      validatorContractName,
      " deployed to:",
      CredentialAtomicQueryValidatorProxy.address
  );
}

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

    console.log("$BNTY Deployed to:", bnty.address);

    const PoseidonUnit6L = await ethers.getContractFactory("PoseidonUnit6L");
    const poseidon6Lib = await PoseidonUnit6L.deploy();
    await poseidon6Lib.deployed();

    console.log(`PoseidonUnit6L Address---> ${poseidon6Lib.address}`)

    const SpongePoseidonLib = await ethers.getContractFactory("SpongePoseidon", {
      libraries: {
        PoseidonUnit6L: poseidon6Lib.address
      }});

    const spongePoseidonLib = await SpongePoseidonLib.deploy();
    await spongePoseidonLib.deployed();

    console.log(`SpongePoseidon Address---> ${spongePoseidonLib.address}`)

    const CampaignMarket = await ethers.getContractFactory("CampaignMarket", {
      libraries: {
        SpongePoseidon: spongePoseidonLib.address,
        PoseidonUnit6L: poseidon6Lib.address
    }});

    const campaignMarket = await CampaignMarket.deploy(
      trustedForwarder
    );

    await campaignMarket.deployed();

    // Deploy validators
    await deployMTP();
    await deploySig();

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

    it("Should be able to add a commission", () => {
      const createBountyTx = "";
    })
  });
});
