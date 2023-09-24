import { time, loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { expect } from "chai";
import { ethers, upgrades } from "hardhat";
import {
  EthStateStorage,
  CredentialRequest,
  CircuitId,
  IIdentityWallet,
  ZeroKnowledgeProofRequest,
  AuthorizationRequestMessage,
  PROTOCOL_CONSTANTS,
  AuthHandler,
  core,
  CredentialStatusType,
} from "@0xpolygonid/js-sdk";

import {
  initInMemoryDataStorageAndWallets,
  initCircuitStorage,
  initProofService,
  initPackageManager,
} from "../lib/walletSetup";

const rhsUrl = 'https://rhs-staging.polygonid.me';

async function createIdentity(identityWallet: IIdentityWallet) {
  const { did, credential } = await identityWallet.createIdentity({
    method: core.DidMethod.Iden3,
    blockchain: core.Blockchain.Polygon,
    networkId: core.NetworkId.Main,
    revocationOpts: {
      type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
      id: rhsUrl,
    },
  });

  return {
    did,
    credential,
  };
}

function createKYCAgeCredentialRequest(
    circuitId: CircuitId,
    credentialRequest: CredentialRequest
): ZeroKnowledgeProofRequest {

  const proofReqSig: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQuerySigV2OnChain,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        documentType: {
          $eq: 99,
        },
      },
    },
  };

  const proofReqMtp: ZeroKnowledgeProofRequest = {
    id: 1,
    circuitId: CircuitId.AtomicQueryMTPV2OnChain,
    optional: false,
    query: {
      allowedIssuers: ["*"],
      type: credentialRequest.type,
      context:
          "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
      credentialSubject: {
        birthday: {
          $lt: 20020101,
        },
      },
    },
  };

  switch (circuitId) {
    case CircuitId.AtomicQuerySigV2OnChain:
      return proofReqSig;
    case CircuitId.AtomicQueryMTPV2OnChain:
      return proofReqMtp;
    default:
      return proofReqSig;
  }
}

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

  return CredentialAtomicQueryValidatorProxy;
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
  return CredentialAtomicQueryValidatorProxy;
}

const processBounties = (bounties) => bounties.reduce((acc, bytes) => {
  try {
    const [bountyId, name, description, imageUrl, reward, rewardType, rewardTotal, rewardAddress, payoutFrom] =
        ethers.utils.defaultAbiCoder.decode(
            ["uint256", "string", "string", "string", "uint256", "bytes32", "uint256", "address", "address"],
            bytes,
            false
        );
    acc.push({
      bountyId, name, description, imageUrl, reward, rewardType, rewardTotal, rewardAddress, payoutFrom
    });
    return acc;
  } catch (e) {
    console.log(e);
    return acc;
  }
}, []);

const createRequest = (validator) => {
  const Operators = {
    NOOP : 0, // No operation, skip query verification in circuit
    EQ : 1, // equal
    LT : 2, // less than
    GT : 3, // greater than
    IN : 4, // in
    NIN : 5, // not in
    NE : 6   // not equal
  }

  // Set up the proof request
  const schemaBigInt = "74977327600848231385663280181476307657"

  // merklized path to field in the W3C credential according to JSONLD  schema e.g. birthday in the KYCAgeCredential under the url "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"
  const schemaClaimPathKey = "20376033832371109177683048456014525905119173674985843915445634726167450989630"

  const requestId = 1;

  const query = {
    schema: schemaBigInt,
    claimPathKey  : schemaClaimPathKey,
    operator: Operators.LT, // operator
    value: [20020101, ...new Array(63).fill(0).map(i => 0)], // for operators 1-3 only first value matters
  };

  return [
    requestId,
    validator,
    query.schema,
    query.claimPathKey,
    query.operator,
    query.value
  ]
}

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
    const mtpValidator = await deployMTP();
    const sigValidator = await deploySig();

    return { campaignMarket, owner, alice, bob, bnty, mtpValidator, sigValidator };
  }

  describe("Deployment", function () {
    let campaignMarket;
    let owner;
    let alice;
    let bob;
    let bnty;
    let sigValidator;
    let mtpValidator;

    before(async () => {
      ({ campaignMarket, owner, alice, bob, bnty, sigValidator, mtpValidator } =
        await loadFixture(setup));
    });


    it("Should be able to add a bounty", async () => {

      const createBountyTx = await campaignMarket.createBounty(
          ["Bounty 1",
            "Bounty 1 Description",
            'https://avatars.githubusercontent.com/u/35270686?s=200&v=4'],
          "ERC20_REWARD",
          ethers.utils.parseEther('1'),
          ethers.utils.parseEther('500'),
          ethers.constants.AddressZero,
          createRequest(mtpValidator.address),
          {
            value: ethers.utils.parseEther('500'),
            gasPrice: ethers.utils.parseUnits('200', 'gwei')
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

    it("Should be able to add a b w/ arbitrary erc20 token", async () => {

      const approveTx = await bnty.approve(campaignMarket.address, ethers.utils.parseEther('50000'), {
        gasPrice: ethers.utils.parseUnits('200', 'gwei')
      });
      await approveTx.wait();

      const createBountyTx = await campaignMarket.createBounty(
          ["Bounty 2",
            "Bounty 2 Description Arbitrary ERC20",
            'https://avatars.githubusercontent.com/u/35270686?s=200&v=4'],
          "ERC20_REWARD",
          ethers.utils.parseEther('1000'),
          ethers.utils.parseEther('50000'),
          bnty.address,
          createRequest(mtpValidator.address),
          {
            gasPrice: ethers.utils.parseUnits('200', 'gwei')
          }
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

    it("Should be able to claim a bounty", async () => {

      // Generate a zk proof for the claim process as if from front end application with valid vc
      // Specifically uses polygon id sdk
      // https://0xpolygonid.github.io/js-sdk-tutorials/docs/api/js-sdk.proofservice.generateproof/#proofservicegenerateproof-method

      let { dataStorage, credentialWallet, identityWallet } =
          await initInMemoryDataStorageAndWallets("https://polygon-mainnet.g.alchemy.com/v2/LCNPCoXan5scqbRr4KOZK8kofDifu2fz", campaignMarket.address);

      const circuitStorage = await initCircuitStorage();

      const proofService = await initProofService(
          identityWallet,
          credentialWallet,
          dataStorage.states,
          circuitStorage
      );

      const { did: userDID, credential: authBJJCredentialUser } =
          await createIdentity(identityWallet);

      console.log("=============== user did ===============");
      console.log(userDID.string());

      const { did: issuerDID, credential: issuerAuthBJJCredential } =
          await createIdentity(identityWallet);

      const credentialRequest = {
        credentialSchema:
            "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json",
        type: "KYCAgeCredential",
        credentialSubject: {
          id: userDID.string(),
          birthday: 19960424,
          documentType: 99,
        },
        expiration: 12345678888,
        revocationOpts: {
          type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
          id: rhsUrl,
        },
      };

      const credential = await identityWallet.issueCredential(
          issuerDID,
          credentialRequest,
          {
            documentLoader: async (credentialSchema)=> ({
              document: {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "$metadata": {
                  "uris": {
                    "jsonLdContext": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
                    "jsonSchema": "https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json"
                  }
                },
                "required": [
                  "@context",
                  "id",
                  "type",
                  "issuanceDate",
                  "credentialSubject",
                  "credentialSchema",
                  "credentialStatus",
                  "issuer"
                ],
                "properties": {
                  "@context": {
                    "type": [
                      "string",
                      "array",
                      "object"
                    ]
                  },
                  "id": {
                    "type": "string"
                  },
                  "type": {
                    "type": [
                      "string",
                      "array"
                    ],
                    "items": {
                      "type": "string"
                    }
                  },
                  "issuer": {
                    "type": [
                      "string",
                      "object"
                    ],
                    "format": "uri",
                    "required": [
                      "id"
                    ],
                    "properties": {
                      "id": {
                        "type": "string",
                        "format": "uri"
                      }
                    }
                  },
                  "issuanceDate": {
                    "type": "string",
                    "format": "date-time"
                  },
                  "expirationDate": {
                    "type": "string",
                    "format": "date-time"
                  },
                  "credentialSchema": {
                    "type": "object",
                    "required": [
                      "id",
                      "type"
                    ],
                    "properties": {
                      "id": {
                        "type": "string",
                        "format": "uri"
                      },
                      "type": {
                        "type": "string"
                      }
                    }
                  },
                  "subjectPosition": {
                    "type": "string",
                    "enum": [
                      "none",
                      "index",
                      "value"
                    ]
                  },
                  "merklizationRootPosition": {
                    "type": "string",
                    "enum": [
                      "none",
                      "index",
                      "value"
                    ]
                  },
                  "revNonce": {
                    "type": "integer"
                  },
                  "version": {
                    "type": "integer"
                  },
                  "updatable": {
                    "type": "boolean"
                  },
                  "credentialSubject": {
                    "type": "object",
                    "required": [
                      "id",
                      "birthday",
                      "documentType"
                    ],
                    "properties": {
                      "id": {
                        "title": "Credential Subject ID",
                        "type": "string",
                        "format": "uri"
                      },
                      "birthday": {
                        "type": "integer"
                      },
                      "documentType": {
                        "type": "integer"
                      }
                    }
                  }
                }
              }
            })
          }
      );

      await dataStorage.credential.saveCredential(credential);
      //
      // console.log(
      //     "================= saved credential ======================="
      // );
      //
      // console.log(
      //     "================= generate Iden3SparseMerkleTreeProof ======================="
      // );
      //
      // const res = await identityWallet.addCredentialsToMerkleTree(
      //     [credential],
      //     issuerDID
      // );
      //
      // console.log("================= push states to rhs ===================");
      //
      // await identityWallet.publishStateToRHS(issuerDID, rhsUrl);
      //
      // console.log("================= publish to blockchain ===================");
      //
      // const txId = await proofService.transitState(
      //     issuerDID,
      //     res.oldTreeState,
      //     true,
      //     dataStorage.states,
      //     owner
      // );
      //
      // console.log(txId);
      //
      // console.log("================= published tx d ===================");
      //
      // const credsWithIden3MTPProof =
      //     await identityWallet.generateIden3SparseMerkleTreeProof(
      //         issuerDID,
      //         res.credentials,
      //         txId
      //     );
      //
      // console.log(credsWithIden3MTPProof);
      //
      // await credentialWallet.saveAll(credsWithIden3MTPProof);
      //
      // const proofReqMtp: ZeroKnowledgeProofRequest = createKYCAgeCredentialRequest(
      //     CircuitId.AtomicQueryMTPV2OnChain,
      //     credentialRequest
      // );
      //
      // const { proof: proofMTP } = await proofService.generateProof(
      //     proofReqMtp,
      //     userDID
      // );
      //
      // console.log(JSON.stringify(proofMTP));

      // const claimBountyTx = await campaignMarket.submitZKPResponse(
      //     [1, 0]
      // );
      //
      // await claimBountyTx.wait();

      // const currentBounty = await campaignMarket.bountyBalance(0);
      //
      // expect(currentBounty.balance).to.be.equal(ethers.utils.parseEther('499'));

    })

    it("Should be able to revoke a bounty", async () => {

      const revokeBountyTx = await campaignMarket.revokeBounty(0);

      await revokeBountyTx.wait();

      const balance = await ethers.provider.getBalance(campaignMarket.address);

      expect(balance).to.be.equal(ethers.utils.parseEther('0'));

      const currentBounty = await campaignMarket.bountyBalance(0);

      expect(currentBounty.balance).to.be.equal(ethers.utils.parseEther('0'));

    })

  });
});
