// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.9;

import "@nilfoundation/evm-placeholder-verification/contracts/interfaces/verifier.sol";
import "../interfaces/ILidoStakingRouter.sol";
import "../interfaces/ILidoLocator.sol";
import "../interfaces/IBeaconBlockHashProvider.sol";
import "./CircuitParams.sol";


contract ZKTVLOracleContract {
    struct OracleReport {
        uint64 slot;
        uint64 epoch;
        uint64 allLidoValidators;
        uint64 exitedLidoValidators;
        uint256 clBalance;
        bytes32 lidoWithdrawalCredentials;
    }

    struct OracleProof {
        bytes32 balancesHash;
        bytes32 validatorsHash;
        bytes32 beaconStateHash;
        bytes32 beaconBlockHash;
        bytes zkProof;
    }

    IVerifier zkllvmVerifier;
    IBeaconBlockHashProvider beaconBlockHashProvider;
    address verificationGate;
    bytes32 lidoWithdrawalCredentials;
    mapping(uint256 => OracleReport) reports;

    error BeaconBlockHashMismatch(OracleReport report);
    error WithdrawalCredentialsMismatch(OracleReport report);
    error ZKPRoofVerificationFailed(OracleReport report);

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

        address stakingRouter = ILidoLocator(lidoLocator_).stakingRouter();
        lidoWithdrawalCredentials = ILidoStakingRouter(stakingRouter).getWithdrawalCredentials();
    }

    function submitReportData(
        OracleReport calldata report,
        OracleProof calldata proof
    ) external {
        if (proof.beaconBlockHash != _getBeaconBlockHash(report.slot)) {
            revert BeaconBlockHashMismatch(report);
        }

        if (report.lidoWithdrawalCredentials != lidoWithdrawalCredentials) {
            revert WithdrawalCredentialsMismatch(report);
        }

        if (!_verifyZKLLVMProof(report, proof)) {
            revert ZKPRoofVerificationFailed(report);
        }

        _updateReport(report);
    }

    function getReport(uint256 slot) external view returns (
	    bool success,
	    uint256 clBalanceGwei,
	    uint256 numValidators
	) {
        OracleReport storage report = reports[slot];
        return (
            report.slot > 0,
            report.clBalance,
            report.allLidoValidators
        );
    }

    function _getBeaconBlockHash(uint256 slot) internal view returns (bytes32) {
        return (beaconBlockHashProvider.getBeaconBlockHash(slot));
    }

    function _constructPublicInput(OracleReport memory report, OracleProof memory proof) internal pure returns(uint256[] memory) {
        uint256[] memory publicInput = new uint256[](8);
        publicInput[0] = uint256(report.lidoWithdrawalCredentials);
        publicInput[1] = uint256(report.slot);
        publicInput[2] = uint256(report.epoch);
        publicInput[3] = uint256(report.clBalance);
        publicInput[4] = uint256(report.allLidoValidators);
        publicInput[5] = uint256(report.exitedLidoValidators);
        publicInput[6] = uint256(proof.beaconStateHash);
        publicInput[7] = uint256(proof.beaconBlockHash);
        return (publicInput);
    }

    function _verifyZKLLVMProof(OracleReport memory report, OracleProof memory proof) internal view returns (bool) {
        return zkllvmVerifier.verify(
            proof.zkProof, 
            CircuitParams.getInitParams(),
            CircuitParams.getColumnRotations(),
            _constructPublicInput(report, proof),
            verificationGate
        );
    }



    function _updateReport(OracleReport memory report) internal {
        reports[report.slot] = report;
        emit ReportAccepted(report.slot, report);
    }
}