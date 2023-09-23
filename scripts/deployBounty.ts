import { ethers } from "hardhat";

async function main() {
  const { maxFeePerGas } = await ethers.provider.getFeeData();
  const gwei = ethers.utils.formatUnits(maxFeePerGas, "gwei");
  const trustedForwarder = "0xf0511f123164602042ab2bCF02111fA5D3Fe97CD";
  
  console.log({
    gwei,
  });

  if (parseFloat(gwei) > 100) {
    console.log(
      `Gas is a bit high right now to send. Will send later. ${gwei}`
    );
    return;
  }

}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
