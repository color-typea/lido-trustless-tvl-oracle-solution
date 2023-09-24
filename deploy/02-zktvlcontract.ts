import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction, Libraries} from 'hardhat-deploy/types';

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const {getNamedAccounts, deployments} = hre;
    const {deployer} = await getNamedAccounts();

    const libs = [
        'CircuitParams'
    ];

    let deployedLibs: Libraries = {};
    for (let lib of libs){
        await deployments.deploy(lib, {
            from: deployer,
            log: true,
        });
        deployedLibs[lib] = (await deployments.get(lib)).address;
    }

    const verifierAddress = hre.externalContracts.nil.verifier;
    const gateAddress = (await deployments.get('gates_gate_argument_split_gen')).address;
    const beaconBlockHashKeeperAddress = (await deployments.get('BeaconBlockHashKeeper')).address;
    const lidoLocatorAddress = hre.externalContracts.lido.locator;

    await deployments.deploy('ZKTVLOracleContract', {
        args: [
            verifierAddress,
            gateAddress,
            beaconBlockHashKeeperAddress,
            lidoLocatorAddress,
        ],
        from: deployer,
        libraries: deployedLibs,
        log : true,
    });
};
func.tags = ['ZKTVLOracleContract'];

export default func;
