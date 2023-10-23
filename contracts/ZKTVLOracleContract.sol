// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8 <0.9;

import "@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol";
import "../interfaces/ILidoStakingRouter.sol";
import "../interfaces/ILidoLocator.sol";
import "../interfaces/IBeaconBlockHashProvider.sol";
import "./CircuitParams.sol";


contract ZKTVLOracleContract {
    struct OracleReport {
        uint256 slot;
        uint256 epoch;
        bytes32 lidoWithdrawalCredentials;
        uint256 allLidoValidators;
        uint256 exitedLidoValidators;
        uint256 clBalance;
    }

    struct OracleProof {
        bytes32 balancesHash;
        bytes32 validatorsHash;
        bytes32 beaconStateHash;
        bytes32 beaconBlockHash;
        bytes zkProof;
    }

    IVerifier zkllvmVerifier;
    address verificationGate;
    IBeaconBlockHashProvider beaconBlockHashProvider;
    ILidoLocator lidoLocator;
    uint public constant contractVersion = 1;

    mapping(uint256 => OracleReport) reports;

    error UnexpectedContractVersion(uint256 expected, uint256 received);
    error ReportRejected(OracleReport report, string reason);

    event ReportAccepted(
        uint256 slot,
        OracleReport report
    );


    constructor(
        address zkllvmVerifier_,
        address verificationGate_,
        address beaconBlockHashProvider_,
        address lidoLocator_
    ) {
        zkllvmVerifier = IVerifier(zkllvmVerifier_);
        verificationGate = verificationGate_;
        beaconBlockHashProvider = IBeaconBlockHashProvider(beaconBlockHashProvider_);
        lidoLocator = ILidoLocator(lidoLocator_);
    }

    function submitReportData(
        OracleReport calldata report,
        OracleProof calldata proof,
        uint version
    ) public {
        _checkContractVersion(version);
        _verifyReportSanity(report);

        bytes32 expectedBeaconBlockHash = getBeaconBlockHash(report.slot);
        bytes32 expectedWithdrawalAddress = getExpectedWithdrawalCredentials();

        _require(
            proof.beaconBlockHash == expectedBeaconBlockHash,
            report,
            "Beacon block hash didn't match actual one"
        );
        _require(
            report.lidoWithdrawalCredentials == expectedWithdrawalAddress,
            report,
            "Withdrawal credentials did not match actual ones"
        );
        _require(
            verifyZKLLVMProof(report, proof),
            report,
            "ZK proof did not verify"
        );

        _updateReport(report);
    }

    function getContractVersion() public pure returns (uint256) {
        return (contractVersion);
    }

    // Compatible with Versioned.sol, intended to be later replaced by complete versioning solution
    function _checkContractVersion(uint256 version) internal pure {
        if (version != contractVersion) {
            revert UnexpectedContractVersion(contractVersion, version);
        }
    }

    function getExpectedWithdrawalCredentials() internal view returns (bytes32) {
        address stakingRouter = lidoLocator.stakingRouter();
        ILidoStakingRouter lidoStakingRouter = ILidoStakingRouter(stakingRouter);
        return (lidoStakingRouter.getWithdrawalCredentials());
    }

    function getBeaconBlockHash(uint256 slot) internal view returns (bytes32) {
        return (beaconBlockHashProvider.getBeaconBlockHash(slot));
    }

    function _verifyReportSanity(OracleReport memory report) internal {
        // sanity checks for the report: e.g. number of validators does not change more than X% since last report
    }

    function constructPublicInput(OracleReport memory report, OracleProof memory proof) internal pure returns(uint256[] memory) {
        uint256[] memory public_input = new uint256[](6);
        public_input[0] = uint256(report.lidoWithdrawalCredentials);
        public_input[1] = uint256(report.slot);
        public_input[2] = uint256(report.epoch);
        public_input[3] = uint256(report.clBalance);
        public_input[4] = uint256(report.allLidoValidators);
        public_input[5] = uint256(report.exitedLidoValidators);
        public_input[6] = uint256(proof.beaconStateHash);
        public_input[7] = uint256(proof.beaconBlockHash);
        return (public_input);
    }

    function verifyZKLLVMProof(OracleReport memory report, OracleProof memory proof) internal view returns (bool) {
        return zkllvmVerifier.verify(
            proof.zkProof, 
            CircuitParams.get_init_params(), 
            CircuitParams.get_column_rotations(), 
            constructPublicInput(report, proof),
            verificationGate
        );
    }

    function getReport(uint256 slot) external view returns (
	    bool success,
	    uint256 clBalanceGwei,
	    uint256 numValidators
	) {
        OracleReport memory report = reports[slot];
        return (
            report.slot > 0,
            report.clBalance,
            report.allLidoValidators
        );
    }

    function _updateReport(OracleReport memory report) internal {
        reports[report.slot] = report;
        emit ReportAccepted(report.slot, report);
    }

    function _require(bool condition, OracleReport memory report, string memory reason) internal pure {
        if (!condition) {
            revert ReportRejected(report, reason);
        }
    }
}