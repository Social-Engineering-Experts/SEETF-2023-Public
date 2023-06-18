# Murky SEE Pass

**Author**: AtlanticBase

**Category**: Smart Contracts

Flag: `SEE{w3lc0me_t0_dA_NFT_w0rld_w1th_SE3pAs5_f3a794cf4f4dd14f9cc7f6a25f61e232}`

## Description

The SEE team has a list of special NFTs that are only allowed to be minted. Find out which one its allowed!

## Difficulty

Easy

## Solution

Misconfiguration and mistake by the Developers.

- A basic use of finding the private merkleRoot variable in the contract.
- Since we are using a custom MerkleRoot library, there might be a mistake.
- The MerkleRoot does not hash the leaf node correctly and thus we can find the merkleRoot and make sure that the leaf == merkleRoot. The user then can just claim the NFT.
