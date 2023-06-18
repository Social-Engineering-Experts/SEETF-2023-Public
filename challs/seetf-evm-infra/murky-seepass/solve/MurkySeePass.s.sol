// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "../src/Setup.sol";

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";

contract MurkySEEPassScript is Script, IERC721Receiver {
    Setup setupContract;

    function setUp() public {
        setupContract = Setup(0x4b20Bb359E8281AB490000B5FCd3A99368b79a27);
    }

    function run() public {
        vm.startBroadcast();
        bytes32[] memory proof = new bytes32[](0);

        setupContract.pass().mintSeePass(
            proof, uint256(0xd158416f477eb6632dd0d44117c33220be333a420cd377fab5a00fdb72d27a10)
        );

        vm.stopBroadcast();
    }

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        return bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"));
    }
}
