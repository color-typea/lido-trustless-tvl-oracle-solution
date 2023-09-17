import { ethers, lidoContracts } from "hardhat";

async function main() {
  // Lib prerequisites: GateArgument
  const Gate0 = await ethers.deployContract("Gate0");
  const Gate6 = await ethers.deployContract("Gate6");

  await Gate0.waitForDeployment();
  await Gate6.waitForDeployment();

  const GateArgument = await ethers.deployContract(
    "GateArgument", { libraries: { Gate0, Gate6 } }
  );

  // Lib prerequisites: Verifier
  const ProofVerifier = await ethers.deployContract("ProofVerifier");

  await ProofVerifier.waitForDeployment();

  const Verifier = await ethers.deployContract(
    "PlaceholderVerifier", { libraries: { ProofVerifier } }
  );

  const HashKeeper = await ethers.deployContract("BeaconBlockHashKeeper");

  await GateArgument.waitForDeployment();
  await Verifier.waitForDeployment();
  await HashKeeper.waitForDeployment();

  const CircuitParams = await ethers.deployContract("CircuitParams");
  await CircuitParams.waitForDeployment();

  const ZKTLVOracleContract = await ethers.deployContract(
    "ZKTVLOracleContract",
    [Verifier.getAddress(), GateArgument.getAddress(), lidoContracts.locator, HashKeeper.getAddress()]
  );

  await ZKTLVOracleContract.waitForDeployment();

  const version = await ZKTLVOracleContract.getContractVersion();

  console.log(`ZKTLVOracleContract (version: ${version}) with deployed to ${ZKTLVOracleContract.target}`);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
