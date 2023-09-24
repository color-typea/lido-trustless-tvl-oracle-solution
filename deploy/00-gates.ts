import * as fs from 'fs';
import * as losslessJSON from 'lossless-json';
import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {DeployFunction, Libraries} from 'hardhat-deploy/types';

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
    const {getNamedAccounts, deployments} = hre;
    const {deployer} = await getNamedAccounts();

    const libs = losslessJSON.parse(fs.readFileSync("./contracts/gates/linked_libs_list.json", 'utf8'));
    let deployedLibs: Libraries = {}

    for (let lib of libs){
        await deployments.deploy(lib, {
            from: deployer,
            log: true,
        });
        deployedLibs[lib] = (await deployments.get(lib)).address
    }
    await deployments.deploy('gates_gate_argument_split_gen', {
        from: deployer,
        libraries : deployedLibs,
        log : true,
    });
};
func.tags = ['ZKTVLGateArgument'];

export default func;

