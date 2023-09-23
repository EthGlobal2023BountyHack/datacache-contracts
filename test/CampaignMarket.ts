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
  const verifierWrapper = await VerifierMTPWrapper.deploy({
    gasPrice: ethers.utils.parseUnits('200', 'gwei')
  });

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
      [verifierWrapper.address, stateAddress]
  );

  await CredentialAtomicQueryValidatorProxy.deployed();

  console.log(
      validatorContractName,
      " deployed to:",
      CredentialAtomicQueryValidatorProxy.address
  );
}

const processBounties = (bounties) => bounties.reduce((acc, bytes) => {
  try {
    const [bountyId, name, description, reward, rewardType, rewardTotal, rewardAddress, payoutFrom] =
        ethers.utils.defaultAbiCoder.decode(
            ["uint256", "string", "string", "uint256", "bytes32", "uint256", "address", "address"],
            bytes,
            false
        );
    acc.push({
      bountyId, name, description, reward, rewardType, rewardTotal, rewardAddress, payoutFrom
    });
    return acc;
  } catch (e) {
    console.log(e);
    return acc;
  }
}, []);

describe("CampaignMarket", function () {
  const trustedForwarder = "0xf0511f123164602042ab2bCF02111fA5D3Fe97CD";

  async function setup() {
    const [owner, alice, bob] = await ethers.getSigners();

    // DEPLOY ERC20 TOKEN
    const BountyCoin = await ethers.getContractFactory("BountyCoin");

    const bnty = await BountyCoin.deploy(
      "BountyCoin",
      "BNTY",
      ethers.BigNumber.from("100000000000000000000000000"),
        {
          gasPrice: ethers.utils.parseUnits('200', 'gwei')
        }
    );

    await bnty.deployed();

    console.log("$BNTY Deployed to:", bnty.address);

    const PoseidonUnit6L = await ethers.getContractFactory("PoseidonUnit6L");
    const poseidon6Lib = await PoseidonUnit6L.deploy(
        {
          gasPrice: ethers.utils.parseUnits('200', 'gwei')
        });
    await poseidon6Lib.deployed();

    console.log(`PoseidonUnit6L Address---> ${poseidon6Lib.address}`)

    const SpongePoseidonLib = await ethers.getContractFactory("SpongePoseidon", {
      libraries: {
        PoseidonUnit6L: poseidon6Lib.address
      }});

    const spongePoseidonLib = await SpongePoseidonLib.deploy(
        {
          gasPrice: ethers.utils.parseUnits('200', 'gwei')
        });
    await spongePoseidonLib.deployed();

    console.log(`SpongePoseidon Address---> ${spongePoseidonLib.address}`)

    const CampaignMarket = await ethers.getContractFactory("CampaignMarket", {
      libraries: {
        SpongePoseidon: spongePoseidonLib.address,
        PoseidonUnit6L: poseidon6Lib.address
    }});

    const campaignMarket = await CampaignMarket.deploy(
      trustedForwarder,
        {
          gasPrice: ethers.utils.parseUnits('200', 'gwei')
        }
    );

    await campaignMarket.deployed();

    console.log(`Campaign Market Address---> ${campaignMarket.address}`)

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

    it("Should be able to add a bounty", async () => {

      const createBountyTx = await campaignMarket.createBounty(
          "Bounty 1",
          "Bounty 1 Description",
          "ERC20_REWARD",
          ethers.utils.parseEther('1'),
          ethers.utils.parseEther('500'),
          ethers.constants.AddressZero,
          {
            value: ethers.utils.parseEther('500')
          }
      );

      await createBountyTx.wait();

      const balance = await ethers.provider.getBalance(campaignMarket.address);

      expect(balance).to.be.equal(ethers.utils.parseEther('500'));

      const currentBounty = await campaignMarket.bountyBalance(0);

      expect(currentBounty.balance).to.be.equal(ethers.utils.parseEther('500'));

      const bounties = await campaignMarket.getAllBounties();

      const bountyData = processBounties(bounties)

      expect(bountyData.length).to.be.equal(1);

    })

    it("Should be able to revoke a bounty", async () => {

      const revokeBountyTx = await campaignMarket.revokeBounty(0);

      await revokeBountyTx.wait();

      const balance = await ethers.provider.getBalance(campaignMarket.address);

      expect(balance).to.be.equal(ethers.utils.parseEther('0'));

      const currentBounty = await campaignMarket.bountyBalance(0);

      expect(currentBounty.balance).to.be.equal(ethers.utils.parseEther('0'));

    })

    it("Should be able to add a b w/ arbitrary erc20 token", async () => {

      const approveTx = await bnty.approve(campaignMarket.address, ethers.utils.parseEther('50000'));
      await approveTx.wait();

      const createBountyTx = await campaignMarket.createBounty(
          "Bounty 2",
          "Bounty 2 Description Arbitrary ERC20",
          "ERC20_REWARD",
          ethers.utils.parseEther('1000'),
          ethers.utils.parseEther('50000'),
          bnty.address,
      );

      await createBountyTx.wait();

      const balance = await bnty.balanceOf(campaignMarket.address);

      expect(balance).to.be.equal(ethers.utils.parseEther('50000'));

      const currentBounty = await campaignMarket.bountyBalance(1);

      expect(currentBounty.balance).to.be.equal(ethers.utils.parseEther('50000'));

      const bounties = await campaignMarket.getAllBounties();

      const bountyData = processBounties(bounties)

      expect(bountyData.length).to.be.equal(2);

      console.log(bountyData[1]);

    })

  });
});
