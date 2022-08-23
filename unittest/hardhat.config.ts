import '@nomiclabs/hardhat-ethers';
import '@nomiclabs/hardhat-waffle';
import 'dotenv/config';

export default {
  solidity: {
    compilers: [
      {
        version: "0.5.16",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
      {
        version: "0.6.9",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
      {
        version: "0.7.5",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
      {
        version: "0.8.1",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
      {
        version: "0.8.9",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
      {
        version: "0.8.11",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
      {
        version: "0.6.12",
        settings: {
          optimizer: {
            enabled: true,
            runs: 200
          }
        }
      },
    ]
  },
  networks: {
    'eth': {
      url: "https://api.mycryptoapi.com/eth",
      accounts: {
        mnemonic: process.env.TEST_MN || '',
        count: 100,
      }
    },
    'bsc': {
      url: "https://bsc-dataseed1.ninicoin.io",
      accounts: {
        mnemonic: process.env.TEST_MN || '',
        count: 100,
      }
    },
  },
  watcher: {
    compilation: {
      tasks: ["compile"],
      files: ["./contracts"],
      verbose: true,
    }
  },
  mocha: {
    timeout: 2000000
  },
  paths: {
    sources: "./contracts",
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  gasReporter: {
      enabled: (process.env.REPORT_GAS) ? true : false
  }
};

