import { HardhatUserConfig, extendEnvironment } from "hardhat/config";
import { config as dotEnvConfig } from "dotenv";
import "@nomicfoundation/hardhat-toolbox";
import { NetworksUserConfig } from "hardhat/types/config";

const dotenvConf =  dotEnvConfig();

if (dotenvConf.error) {
  console.error('Error loading .env file:', dotenvConf.error);
  process.exit(1); // Exit the application with an error code
}

const DEFAULT_NETWORK = 'hardhat';
const NETWORK_NAME = getNetworkName();

const networks: NetworksUserConfig = {
  hardhat: {
    chainId: 5,
    forking: {
      // url: 'https://goerli.infura.io/v3/' + process.env.WEB3_INFURA_PROJECT_ID,
      url: 'https://rpc.ankr.com/eth_goerli/' + process.env.ANKR_API_ID,
    },
  }
}


const config: HardhatUserConfig = {
  defaultNetwork: DEFAULT_NETWORK,
  networks: networks,
  solidity: {
    version: "0.8.19",
    settings: {
      optimizer: {
        enabled: true,
        runs: 50,
      },
    },
  },
  etherscan: {
    apiKey: process.env.ETHERSCAN_TOKEN
  }
};

function getNetworkName(): string {
  if (process.env.HARDHAT_NETWORK) {
    // Hardhat passes the network to its subprocesses via this env var
    return process.env.HARDHAT_NETWORK
  }
  const networkArgIndex = process.argv.indexOf('--network')
  return networkArgIndex !== -1 && networkArgIndex + 1 < process.argv.length
    ? process.argv[networkArgIndex + 1]
    : process.env.NETWORK_NAME || DEFAULT_NETWORK;
}

type LidoContracts = {
  locator: string,
  stakingRouter: string
}

function getLidoContracts(networkName: string): LidoContracts {
  switch (networkName) {
    case 'mainnet': 
      return {
        locator: "0xC1d0b3DE6792Bf6b4b37EccdcC24e45978Cfd2Eb",
        stakingRouter: "0xFdDf38947aFB03C621C71b06C9C70bce73f12999"
      }
    default:
      return {
        locator: "0x1eDf09b5023DC86737b59dE68a8130De878984f5",
        stakingRouter: "0xa3Dbd317E53D363176359E10948BA0b1c0A4c820"
      }
  }
}

extendEnvironment((hre) => {
  hre.lidoContracts = getLidoContracts(NETWORK_NAME);
});

export default config;
