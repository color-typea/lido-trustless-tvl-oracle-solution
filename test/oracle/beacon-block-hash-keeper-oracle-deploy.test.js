const { ethers, artifacts, contract, web3 } = require('hardhat')
const { ZERO_ADDRESS } = require('../lido/helpers/constants')
const { assert } = require('../lido/helpers/assert')

const {
  INITIAL_EPOCH,
  SLOTS_PER_EPOCH,
  SECONDS_PER_SLOT,
  GENESIS_TIME,
  SECONDS_PER_EPOCH,
  EPOCHS_PER_FRAME,
  SLOTS_PER_FRAME,
  SECONDS_PER_FRAME,
  computeSlotAt,
  computeEpochAt,
  computeEpochFirstSlotAt,
  computeEpochFirstSlot,
  computeTimestampAtSlot,
  computeTimestampAtEpoch,
  ZERO_HASH,
  HASH_1,
  HASH_2,
  HASH_3,
  HASH_4,
  HASH_5,
  CONSENSUS_VERSION,
  deployHashConsensus,
} = require('../lido/0.8.9/oracle/hash-consensus-deploy.test')

const BeaconBlockHashKeeperOracle = artifacts.require('BeaconBlockHashKeeperOracleTimeTravellable')

async function deployBeaconBlockHashKeeperOracleSetup(
  admin,
  {
    initialEpoch = INITIAL_EPOCH,
    epochsPerFrame = EPOCHS_PER_FRAME,
    slotsPerEpoch = SLOTS_PER_EPOCH,
    secondsPerSlot = SECONDS_PER_SLOT,
    genesisTime = GENESIS_TIME,
  } = {}
) {
  const oracle = await BeaconBlockHashKeeperOracle.new(secondsPerSlot, genesisTime, { from: admin })

  const { consensus } = await deployHashConsensus(admin, {
    reportProcessor: oracle,
    epochsPerFrame,
    slotsPerEpoch,
    secondsPerSlot,
    genesisTime,
    initialEpoch,
  })

  return {
    oracle,
    consensus,
  }
}

async function initBeaconBlockHashKeeperOracle({
  admin,
  oracle,
  consensus,
  dataSubmitter = null,
  consensusVersion = CONSENSUS_VERSION,
  lastProcessingRefSlot = 0,
}) {
  let initTx = await oracle.initialize(admin, consensus.address, consensusVersion, lastProcessingRefSlot, {
    from: admin,
  })

  await oracle.grantRole(await oracle.MANAGE_CONSENSUS_CONTRACT_ROLE(), admin, { from: admin })
  await oracle.grantRole(await oracle.MANAGE_CONSENSUS_VERSION_ROLE(), admin, { from: admin })

  if (dataSubmitter != null) {
    await oracle.grantRole(await oracle.SUBMIT_DATA_ROLE(), dataSubmitter, { from: admin })
  }

  return initTx
}

async function configureBeaconBlockHashKeeperOracleSetup({
  admin,
  consensus,
  oracle,
  dataSubmitter = null,
  consensusVersion = CONSENSUS_VERSION,
  lastProcessingRefSlot = 0,
} = {}) {
  const initTx = await initBeaconBlockHashKeeperOracle({
    admin,
    oracle,
    consensus,
    dataSubmitter,
    consensusVersion,
    lastProcessingRefSlot,
  })

  return { initTx }
}

async function deployAndConfigureBeaconBlockHashKeeperOracle(admin) {
  /// this is done (far) before the protocol upgrade voting initiation:
  ///   1. deploy HashConsensus
  ///   2. deploy BeaconBlockHashKeeperOracle impl
  const deployed = await deployBeaconBlockHashKeeperOracleSetup(admin)

  const finalizeResult = await configureBeaconBlockHashKeeperOracleSetup({ admin, ...deployed })

  return { ...deployed, ...finalizeResult }
}

module.exports = {
  SLOTS_PER_EPOCH,
  SECONDS_PER_SLOT,
  GENESIS_TIME,
  SECONDS_PER_EPOCH,
  EPOCHS_PER_FRAME,
  SLOTS_PER_FRAME,
  SECONDS_PER_FRAME,
  ZERO_HASH,
  HASH_1,
  HASH_2,
  HASH_3,
  HASH_4,
  HASH_5,
  computeSlotAt,
  computeEpochAt,
  computeEpochFirstSlotAt,
  computeEpochFirstSlot,
  computeTimestampAtSlot,
  computeTimestampAtEpoch,
  CONSENSUS_VERSION,
  deployAndConfigureBeaconBlockHashKeeperOracle,
  deployBeaconBlockHashKeeperOracleSetup,
  initBeaconBlockHashKeeperOracle,
  configureBeaconBlockHashKeeperOracleSetup,
}

contract('BeaconBlockHashKeeperOracle', ([admin, member1]) => {
  context('Deployment and initial configuration', () => {
    it('reverts when slotsPerSecond is zero', async () => {
      await assert.reverts(
        deployBeaconBlockHashKeeperOracleSetup(admin, { secondsPerSlot: 0 }),
        'SecondsPerSlotCannotBeZero()'
      )
    })

    it('deployment and init finishes successfully (default setup)', async () => {
      const deployed = await deployAndConfigureBeaconBlockHashKeeperOracle(admin)
      // consensus = deployed.consensus
      // oracle = deployed.oracle
    })

    it('mock setup is correct', async () => {
      const { consensus, oracle } = await deployAndConfigureBeaconBlockHashKeeperOracle(admin)
      // check the mock time-travellable setup
      const time1 = +(await consensus.getTime())
      assert.equals(await oracle.getTime(), time1)

      await consensus.advanceTimeBy(SECONDS_PER_SLOT)

      const time2 = +(await consensus.getTime())
      assert.equal(time2, time1 + SECONDS_PER_SLOT)
      assert.equals(await oracle.getTime(), time2)
    })

    it('initial configuration is correct', async () => {
      const { consensus, oracle } = await deployAndConfigureBeaconBlockHashKeeperOracle(admin)

      assert.equal(await oracle.getConsensusContract(), consensus.address)
      assert.equals(await oracle.getConsensusVersion(), CONSENSUS_VERSION)
      assert.equals(await oracle.SECONDS_PER_SLOT(), SECONDS_PER_SLOT)
    })

    it('initialize reverts if admin address is zero', async () => {
      const deployed = await deployBeaconBlockHashKeeperOracleSetup(admin)

      await assert.reverts(
        deployed.oracle.initialize(ZERO_ADDRESS, deployed.consensus.address, CONSENSUS_VERSION, 0, {
          from: admin,
        }),
        'AdminCannotBeZero()'
      )
    })

    it('initialize succeeds', async () => {
      const deployed = await deployBeaconBlockHashKeeperOracleSetup(admin)

      await deployed.oracle.initialize(admin, deployed.consensus.address, CONSENSUS_VERSION, 0, {
        from: admin,
      })
    })
  })
})
