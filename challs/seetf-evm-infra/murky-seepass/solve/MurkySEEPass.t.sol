// SPDX-License-Identifier: Unlicense

pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "../src/Setup.sol";
import "../src/MerkleProof.sol";

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract MurkySEEPassTest is Test, IERC721Receiver {
    Setup setup;
    bytes32 root;

    function setUp() public {
        root = keccak256(abi.encodePacked("Welcome to SEETF 2023!"));
        setup = new Setup(root);

        console.log("Setup address: %s", address(setup));
        console.log("Setup isSolved: %s", setup.isSolved());
        console.logBytes32(root);
    }

    function testSolved() public {
        bytes32[] memory proof = new bytes32[](0);

        setup.pass().mintSeePass(proof, uint256(root));

        assertTrue(setup.isSolved());
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
    }
}
