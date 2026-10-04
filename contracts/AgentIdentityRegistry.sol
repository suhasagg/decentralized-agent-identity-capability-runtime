// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal registry anchor. Production deployments should use audited
/// access control, upgrade policy, chain governance and event indexing.
contract AgentIdentityRegistry {
    struct Record { bytes32 documentHash; bool revoked; uint64 updatedAt; }
    mapping(bytes32 => Record) public records;
    mapping(bytes32 => address) public controllers;

    event Registered(bytes32 indexed didHash, address indexed controller, bytes32 documentHash);
    event Updated(bytes32 indexed didHash, bytes32 documentHash);
    event Revoked(bytes32 indexed didHash);

    function register(bytes32 didHash, bytes32 documentHash) external {
        require(controllers[didHash] == address(0), "exists");
        controllers[didHash] = msg.sender;
        records[didHash] = Record(documentHash, false, uint64(block.timestamp));
        emit Registered(didHash, msg.sender, documentHash);
    }
    function update(bytes32 didHash, bytes32 documentHash) external {
        require(controllers[didHash] == msg.sender, "not controller");
        require(!records[didHash].revoked, "revoked");
        records[didHash] = Record(documentHash, false, uint64(block.timestamp));
        emit Updated(didHash, documentHash);
    }
    function revoke(bytes32 didHash) external {
        require(controllers[didHash] == msg.sender, "not controller");
        records[didHash].revoked = true;
        records[didHash].updatedAt = uint64(block.timestamp);
        emit Revoked(didHash);
    }
}
