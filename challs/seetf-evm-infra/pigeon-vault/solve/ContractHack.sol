// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {AppStorage} from "../src/libraries/LibAppStorage.sol";
import {LibDiamond} from "../src/libraries/LibDiamond.sol";

contract ContractHackFacet {
    AppStorage internal s;

    function initialize(address _owner) external {
        LibDiamond.setContractOwner(_owner);
    }
}
