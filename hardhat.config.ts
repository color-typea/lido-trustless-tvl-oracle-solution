import "@nomicfoundation/hardhat-toolbox";
import "@nomiclabs/hardhat-ethers";
import "hardhat-deploy";
import { HardhatUserConfig, extendEnvironment } from "hardhat/config";
import { config as dotEnvConfig } from "dotenv";
import { NetworksUserConfig } from "hardhat/types/config";

const dotenvConf = dotEnvConfig();

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
      url: `https://rpc.ankr.com/eth_goerli/${process.env.ANKR_API_ID}`
    },
  },
  goerli: {
    url: `https://rpc.ankr.com/eth_goerli/${process.env.ANKR_API_ID}`,
    accounts: [process.env.GOERLI_PRIVATE_KEY]
  },

  holesky: {
    url: `https://rpc.ankr.com/eth_holesky/${process.env.ANKR_API_ID}`,
    accounts: [process.env.HOLESKY_PRIVATE_KEY]
  },
}


const config: HardhatUserConfig = {
  defaultNetwork: DEFAULT_NETWORK,
  networks: networks,
  solidity: {
    version: "0.8.9",
    settings: {
      optimizer: {
        enabled: true,
        runs: 50,
      },
    },
  },
  namedAccounts: {
    deployer: 0,
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


type NilContracts = {
  verifier: string
}

type ExternalContracts = {
  lido: LidoContracts,
  nil: NilContracts
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



function getExternalContracts(networkName: string): ExternalContracts {
  let nilContracts: NilContracts;
  switch (networkName) {
    case 'goerli':
      nilContracts = { verifier: "0xC1bcE2291bd826d51a1e7f2FeB518d421D239cce" };
      break;
    case 'localhost':
      // this will 
      nilContracts = { verifier: "0x6646cf04c97d4159ba2B3a199a69b8a5C6aBFC7a" };
      break;
    case 'hardhat':
      nilContracts = { verifier: "0xC1bcE2291bd826d51a1e7f2FeB518d421D239cce" };
      break;
    default:
      throw new Error(`Verifier is not yet deployed on network ${networkName}`);
  }
  return {
    lido: getLidoContracts(NETWORK_NAME),
    nil: nilContracts,
  }
}

extendEnvironment((hre) => {
  hre.externalContracts = getExternalContracts(NETWORK_NAME);
});

export default config;
