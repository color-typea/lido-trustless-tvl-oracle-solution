import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction, Libraries} from 'hardhat-deploy/types';

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const {getNamedAccounts, deployments} = hre;
    const {deployer} = await getNamedAccounts();

    let deployedLibs: Libraries = {}

    await deployments.deploy('BeaconBlockHashKeeper', {
        from: deployer,
        libraries : deployedLibs,
        log : true,
    });
};
func.tags = ['BeaconBlockHashKeeper'];

export default func;

