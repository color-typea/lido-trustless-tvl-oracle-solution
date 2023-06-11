// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

import "../interfaces/IVerifier.sol";
import "../interfaces/ILidoStakingRouter.sol";
import "../interfaces/ILidoLocator.sol";
import "../interfaces/IBeaconBlockHashProvider.sol";


contract ZKTVLOracleContract {
    struct OracleReport {
        uint256 slot;
        uint256 epoch;
        bytes32 lidoWithdrawalCredentials;
        uint256 activeValidators;
        uint256 exitedValidators;
        uint256 totalValueLocked;
    }

    struct OracleProof {
        bytes32 beaconBlockHash;
        bytes zkProof;
    }

    event ReportAccepted(
        OracleReport report
    );
    event ReportRejected(
        OracleReport report,
        string reason
    );

    OracleReport latestReport;

    IVerifier zkllvmVerifier;
    address verificationGate;
    IBeaconBlockHashProvider beaconBlockHashProvider;
    ILidoLocator lidoLocator;
    uint public constant contractVersion = 1;

    error UnexpectedContractVersion(uint256 expected, uint256 received);

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
        _require(report.slot > latestReport.slot, report, "Report for a later slot already received");

        _verifyReportSanity(report);

        bytes32 expectedBeaconBlockHash = getBeaconBlockHash(report.slot);
        bytes32 expectedWithdrawalAddress = getExpectedWithdrawalCredentials();

        _require(proof.beaconBlockHash == expectedBeaconBlockHash, report, "Reported beacon block hash didn't match actual one");
        _require(
            report.lidoWithdrawalCredentials == expectedWithdrawalAddress,
            report,
            "Reported withdrawal credentials did not match actual ones"
        );
        _require(
            verifyZKLLVMProof(verificationGate, report, proof),
            report,
            "ZK proof did not verify"
        );

        latestReport = report;
    }

    // Compatible with Versioned.sol, intended to be later replaced by complete versioning solution
    function _checkContractVersion(uint256 version) internal view {
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

    function verifyZKLLVMProof(
        address gate, OracleReport memory report, OracleProof memory proof
    ) internal view returns (bool) {
        uint256[] memory init_params;
        int256[][] memory columns_rotations;
        return zkllvmVerifier.verify(proof.zkProof, init_params, columns_rotations, gate);
    }

    function getLastReport() public view returns (OracleReport memory result) {
        return (latestReport);
    }

    function _updateReport(OracleReport memory report) internal {
        latestReport = report;
        emit ReportAccepted(report);
    }

    function _require(bool condition, OracleReport memory report, string memory reason) internal {
        if (!condition) {
            emit ReportRejected(report, reason);
            require(false, reason);
        }
    }
}