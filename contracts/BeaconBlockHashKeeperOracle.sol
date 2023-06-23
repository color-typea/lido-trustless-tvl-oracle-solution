// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

import '../interfaces/IBeaconBlockHashProvider.sol';
import '../interfaces/IBeaconBlockHashReceiver.sol';

import { BaseOracle, IConsensusContract } from './lido/0.8.9/oracle/BaseOracle.sol';

contract BeaconBlockHashKeeperOracle is IBeaconBlockHashProvider, BaseOracle {
    error AdminCannotBeZero();
    error SenderNotAllowed();
    error BlockHashCannotBeEmpty();

    event WarnExtraDataIncompleteProcessing(
        uint256 indexed refSlot,
        uint256 processedItemsCount,
        uint256 itemsCount
    );

    struct ExtraDataProcessingState {
        uint64 refSlot;
        uint16 dataFormat;
        bool submitted;
        uint64 itemsCount;
        uint64 itemsProcessed;
        uint256 lastSortingKey;
        bytes32 dataHash;
    }

    struct BeaconBlockHashRecord {
        uint256 slot;
        bytes32 blockHash;
    }

    /// @dev Storage slot: ExtraDataProcessingState state
    bytes32 internal constant EXTRA_DATA_PROCESSING_STATE_POSITION =
        keccak256('lido.BeaconBlockHashKeeper.extraDataProcessingState');

    /// @notice An ACL role granting the permission to submit the data for a committee report.
    bytes32 public constant SUBMIT_DATA_ROLE = keccak256('SUBMIT_DATA_ROLE');

    ///
    /// Initialization & admin functions
    ///

    constructor(uint256 secondsPerSlot, uint256 genesisTime) BaseOracle(secondsPerSlot, genesisTime) {}

    function initialize(
        address admin,
        address consensusContract,
        uint256 consensusVersion,
        uint256 lastProcessingRefSlot
    ) external {
        if (admin == address(0)) revert AdminCannotBeZero();

        _setupRole(DEFAULT_ADMIN_ROLE, admin);

        BaseOracle._initialize(consensusContract, consensusVersion, lastProcessingRefSlot);
    }

    ///
    /// Data provider interface
    ///
    struct ReportData {
        ///
        /// Oracle consensus info
        ///

        /// @dev Version of the oracle consensus rules. Current version expected
        /// by the oracle can be obtained by calling getConsensusVersion().
        uint256 consensusVersion;
        /// @dev Reference slot for which the report was calculated. If the slot
        /// contains a block, the state being reported should include all state
        /// changes resulting from that block. The epoch containing the slot
        /// should be finalized prior to calculating the report.
        uint256 refSlot;
        ///
        /// Oracle data
        ///

        // Becon block hashes
        BeaconBlockHashRecord[] beaconBlockHashRecords;
    }

    mapping(uint256 => bytes32) blockHashes;

    /// @notice Submits report data for processing.
    ///
    /// @param data The data. See the `ReportData` structure's docs for details.
    /// @param contractVersion Expected version of the oracle contract.
    ///
    /// Reverts if:
    /// - The caller is not a member of the oracle committee and doesn't possess the
    ///   SUBMIT_DATA_ROLE.
    /// - The provided contract version is different from the current one.
    /// - The provided consensus version is different from the expected one.
    /// - The provided reference slot differs from the current consensus frame's one.
    /// - The processing deadline for the current consensus frame is missed.
    /// - The keccak256 hash of the ABI-encoded data is different from the last hash
    ///   provided by the hash consensus contract.
    /// - The provided data doesn't meet safety checks.
    ///
    function submitReportData(ReportData calldata data, uint256 contractVersion) external {
        _checkMsgSenderIsAllowedToSubmitData();
        _checkContractVersion(contractVersion);
        _checkConsensusData(data.refSlot, data.consensusVersion, keccak256(abi.encode(data)));
        _checkBeaconBlockHashRecord(data.beaconBlockHashRecords);

        uint256 prevRefSlot = _startProcessing();

        // ToDo: Do we need to store those hashes at all?
        _setBeaconBlockHashes(data.beaconBlockHashRecords);
        _handleConsensusReportData(data, prevRefSlot);
    }

    function _handleConsensusReport(
        ConsensusReport memory /* report */,
        uint256 /* prevSubmittedRefSlot */,
        uint256 prevProcessingRefSlot
    ) internal override {
        ExtraDataProcessingState memory state = _storageExtraDataProcessingState().value;
        if (
            state.refSlot == prevProcessingRefSlot &&
            (!state.submitted || state.itemsProcessed < state.itemsCount)
        ) {
            emit WarnExtraDataIncompleteProcessing(
                prevProcessingRefSlot,
                state.itemsProcessed,
                state.itemsCount
            );
        }
    }

    function _checkMsgSenderIsAllowedToSubmitData() internal view {
        address sender = _msgSender();
        if (!hasRole(SUBMIT_DATA_ROLE, sender) && !_isConsensusMember(sender)) {
            revert SenderNotAllowed();
        }
    }

    function _handleConsensusReportData(ReportData calldata data, uint256 prevRefSlot) internal {
        //
        //uint256 slotsElapsed = data.refSlot - prevRefSlot;
        // ILido(LIDO).handleOracleReport(
        //     GENESIS_TIME + data.refSlot * SECONDS_PER_SLOT,
        //     slotsElapsed * SECONDS_PER_SLOT,
        //     data.numValidators,
        //     data.clBalanceGwei * 1e9,
        //     data.withdrawalVaultBalance,
        //     data.elRewardsVaultBalance,
        //     data.sharesRequestedToBurn,
        //     data.withdrawalFinalizationBatches,
        //     data.simulatedShareRate
        // );
    }

    struct StorageExtraDataProcessingState {
        ExtraDataProcessingState value;
    }

    function _storageExtraDataProcessingState()
        internal
        pure
        returns (StorageExtraDataProcessingState storage r)
    {
        bytes32 position = EXTRA_DATA_PROCESSING_STATE_POSITION;
        assembly {
            r.slot := position
        }
    }

    function getBeaconBlockHash(uint256 slot) external view returns (bytes32) {
        bytes32 value = blockHashes[slot];
        require(value != 0); // means that the hash was not set, ever
        return (value);
    }

    function _setBeaconBlockHashes(BeaconBlockHashRecord[] calldata blockRecords) internal {
        for (uint32 i = 0; i < blockRecords.length; i++) {
            BeaconBlockHashRecord memory record = blockRecords[i];

            blockHashes[record.slot] = record.blockHash;
        }
    }

    function _checkBeaconBlockHashRecord(BeaconBlockHashRecord[] calldata blockRecords) internal pure {
        for (uint32 i = 0; i < blockRecords.length; i++) {
            if (blockRecords[i].blockHash == bytes32(0)) {
                revert BlockHashCannotBeEmpty();
            }
        }
    }
}
