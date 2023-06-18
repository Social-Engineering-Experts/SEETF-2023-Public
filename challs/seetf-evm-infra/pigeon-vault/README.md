# PigeonVault

**Author**: AtlanticBase

**Category**: Smart Contracts

Flag: `SEE{}`

## Description

rainbowpigeon has just received a massive payout from his **secret** business, and he now wants to create a secure vault to store his cryptocurrency assets. To achieve this, he developed PigeonVault, and being a smart guy, he made provisions for upgrading the contract in case he detects any vulnerability in the system.

Find out a way to steal his funds before he discovers any flaws in his implementation.

https://github.com/aavegotchi/aavegotchi-contracts
Implement a VaultFactory -> Deploy Vaults (Diamond Proxy)
Using Diamond Pattern
Have a DAOFacet where users can push proposals for the ecosystem -> flashLoan(?) to get huge gov token -> potentially malicious proposal where func sig will collide with another, potentially call the malicious func sig that matches a non-malicious function that was already deployed -> then call to change owner to solve or sth

```solidity
struct DiamondStorage {
        // function selector => facet address and selector position in selectors array
        mapping(bytes4 => FacetAddressAndSelectorPosition) facetAddressAndSelectorPosition;
        bytes4[] selectors;
        mapping(bytes4 => bool) supportedInterfaces;
        // owner of the contract
        address contractOwner;
    }
```


## Difficulty

Medium

## Solution

