import hre, { ethers } from "hardhat";

async function main() {
  const { maxFeePerGas } = await ethers.provider.getFeeData();
  const gwei = ethers.utils.formatUnits(maxFeePerGas, "gwei");
  const fxChild = "0x8397259c983751DAf40400790063935a11afa28a";
  const trustedForwarder = "0xf0511f123164602042ab2bCF02111fA5D3Fe97CD";
  const parentContractAddress = "0x5b458F3B1c5FF24B966925601101F46fA5BB3904";

  console.log({
    gwei,
  });

  if (parseFloat(gwei) > 100) {
    console.log(
      `Gas is a bit high right now to send. Will send later. ${gwei}`
    );
    return;
  }

  /******************************
   * DEPLOY CHILD
   *****************************/
  const AcorneChild = await hre.ethers.getContractFactory("AcorneChild");

  const acorne = await AcorneChild.deploy(fxChild, trustedForwarder);

  await acorne.deployTransaction.wait();

  console.log(
    `AcorneChild --- npx hardhat verify --network matic ${acorne.address} ${fxChild} ${trustedForwarder}`
  );

  // Set root tunnel address
  const tunnelChildTx = await acorne.setFxRootTunnel(parentContractAddress);
  await tunnelChildTx.wait();

  console.log(`_fxRootTunnel: ${parentContractAddress}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
