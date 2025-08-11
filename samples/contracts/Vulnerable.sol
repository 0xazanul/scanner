// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vulnerable {
    address public owner;
    event RandomUsed(uint256 v);

    constructor() {
        owner = msg.sender;
    }

    function dangerousAuth() external {
        // bad auth via tx.origin
        require(tx.origin == owner, "not owner");
    }

    function rng() external returns (uint256) {
        uint256 v = uint256(keccak256(abi.encode(block.timestamp, block.number)));
        emit RandomUsed(v);
        return v;
    }

    function nuke(address payable target) external {
        require(msg.sender == owner, "!owner");
        selfdestruct(target);
    }
}
