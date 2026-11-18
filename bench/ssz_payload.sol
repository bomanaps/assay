// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

library SSZ {
    /// @dev sha256 precompile address.
    uint8 constant SHA256 = 0x02;

    error BranchHasMissingItem();
    error BranchHasExtraItem();

    /// Withdrawal represents a validator withdrawal from the consensus layer.
    /// See EIP-4895: Beacon chain push withdrawals as operations.
    struct Withdrawal {
        uint64 index;
        uint64 validatorIndex;
        address _address;
        uint64 amount;
    }

    // As defined in phase0/beacon-chain.md:356
    struct Validator {
        bytes pubkey;
        bytes32 withdrawalCredentials;
        uint64 effectiveBalance;
        bool slashed;
        uint64 activationEligibilityEpoch;
        uint64 activationEpoch;
        uint64 exitEpoch;
        uint64 withdrawableEpoch;
    }

    // As defined in phase0/beacon-chain.md:436
    struct BeaconBlockHeader {
        uint64 slot;
        uint64 proposerIndex;
        bytes32 parentRoot;
        bytes32 stateRoot;
        bytes32 bodyRoot;
    }

    /// Inspired by https://github.com/succinctlabs/telepathy-contracts/blob/main/src/libraries/SimpleSerialize.sol#L59
    function withdrawalHashTreeRoot(Withdrawal memory withdrawal)
        internal
        pure
        returns (bytes32)
    {
        return sha256(
            bytes.concat(
                sha256(
                    bytes.concat(
                        toLittleEndian(withdrawal.index),
                        toLittleEndian(withdrawal.validatorIndex)
                    )
                ),
                sha256(
                    bytes.concat(
                        bytes20(withdrawal._address),
                        bytes12(0),
                        toLittleEndian(withdrawal.amount)
                    )
                )
            )
        );
    }

    function validatorHashTreeRoot(Validator memory validator)
        internal
        view
        returns (bytes32 root)
    {
        bytes32 pubkeyRoot;

        assembly {
            // Dynamic data types such as bytes are stored at the specified offset.
            let offset := mload(validator)
            // Call sha256 precompile with the pubkey pointer
            let result :=
                staticcall(gas(), SHA256, add(offset, 32), 0x40, 0x00, 0x20)
            // Precompile returns no data on OutOfGas error.
            if eq(result, 0) { revert(0, 0) }

            pubkeyRoot := mload(0x00)
        }

        bytes32[8] memory nodes = [
            pubkeyRoot,
            validator.withdrawalCredentials,
            toLittleEndian(validator.effectiveBalance),
            toLittleEndian(validator.slashed),
            toLittleEndian(validator.activationEligibilityEpoch),
            toLittleEndian(validator.activationEpoch),
            toLittleEndian(validator.exitEpoch),
            toLittleEndian(validator.withdrawableEpoch)
        ];

        // TODO: Extract to a function accepting a dynamic array of bytes32?
        /// @solidity memory-safe-assembly
        assembly {
            // Count of nodes to hash
            let count := 8

            // Loop over levels
            for { } 1 { } {
                // Loop over nodes at the given depth

                // Initialize `offset` to the offset of `proof` elements in memory.
                let target := nodes
                let source := nodes
                let end := add(source, shl(5, count))

                for { } 1 { } {
                    // Read next two hashes to hash
                    mstore(0x00, mload(source))
                    mstore(0x20, mload(add(source, 0x20)))

                    // Call sha256 precompile
                    let result :=
                        staticcall(gas(), SHA256, 0x00, 0x40, 0x00, 0x20)

                    if eq(result, 0) { revert(0, 0) }

                    // Store the resulting hash at the target location
                    mstore(target, mload(0x00))

                    // Advance the pointers
                    target := add(target, 0x20)
                    source := add(source, 0x40)

                    if iszero(lt(source, end)) { break }
                }

                count := shr(1, count)
                if eq(count, 1) {
                    root := mload(0x00)
                    break
                }
            }
        }
    }

    function beaconHeaderHashTreeRoot(BeaconBlockHeader memory header)
        internal
        view
        returns (bytes32 root)
    {
        bytes32[8] memory nodes = [
            toLittleEndian(header.slot),
            toLittleEndian(header.proposerIndex),
            header.parentRoot,
            header.stateRoot,
            header.bodyRoot,
            bytes32(0),
            bytes32(0),
            bytes32(0)
        ];

        /// @solidity memory-safe-assembly
        assembly {
            // Count of nodes to hash
            let count := 8

            // Loop over levels
            // prettier-ignore
            for { } 1 { } {
                // Loop over nodes at the given depth

                // Initialize `offset` to the offset of `proof` elements in memory.
                let target := nodes
                let source := nodes
                let end := add(source, shl(5, count))

                // prettier-ignore
                for { } 1 { } {
                    // TODO: Can be replaced with `mcopy` once it's available, see EIP-5656.
                    // Read next two hashes to hash
                    mstore(0x00, mload(source))
                    mstore(0x20, mload(add(source, 0x20)))

                    // Call sha256 precompile
                    let result :=
                        staticcall(gas(), 0x02, 0x00, 0x40, 0x00, 0x20)

                    if eq(result, 0) {
                        // Precompiles returns no data on OutOfGas error.
                        revert(0, 0)
                    }

                    // Store the resulting hash at the target location
                    mstore(target, mload(0x00))

                    // Advance the pointers
                    target := add(target, 0x20)
                    source := add(source, 0x40)

                    if iszero(lt(source, end)) { break }
                }

                count := shr(1, count)
                if eq(count, 1) {
                    root := mload(0x00)
                    break
                }
            }
        }
    }

    // forgefmt: disable-next-item
    function toLittleEndian(uint256 v) internal pure returns (bytes32) {
        v =
            ((v &
                0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >>
                8) |
            ((v &
                0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) <<
                8);
        v =
            ((v &
                0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >>
                16) |
            ((v &
                0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) <<
                16);
        v =
            ((v &
                0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >>
                32) |
            ((v &
                0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) <<
                32);
        v =
            ((v &
                0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >>
                64) |
            ((v &
                0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) <<
                64);
        v = (v >> 128) | (v << 128);
        return bytes32(v);
    }

    function toLittleEndian(bool v) internal pure returns (bytes32) {
        return bytes32(v ? 1 << 248 : 0);
    }

    /// @notice Modified version of `verify` from `MerkleProofLib` to support generalized indices and sha256 precompile.
    /// @dev Returns whether `leaf` exists in the Merkle tree with `root`, given `proof`.
    function verifyProof(
        bytes32[] calldata proof,
        bytes32 root,
        bytes32 leaf,
        uint256 index
    ) internal view returns (bool isValid) {
        /// @solidity memory-safe-assembly
        assembly {
            if proof.length {
                // Left shift by 5 is equivalent to multiplying by 0x20.
                let end := add(proof.offset, shl(5, proof.length))
                // Initialize `offset` to the offset of `proof` in the calldata.
                let offset := proof.offset
                // Iterate over proof elements to compute root hash.
                for { } 1 { } {
                    // Slot of `leaf` in scratch space.
                    // If the condition is true: 0x20, otherwise: 0x00.
                    let scratch := shl(5, and(index, 1))
                    index := shr(1, index)
                    if iszero(index) {
                        // revert BranchHasExtraItem()
                        mstore(0x00, 0x5849603f)
                        revert(0x1c, 0x04)
                    }
                    // Store elements to hash contiguously in scratch space.
                    // Scratch space is 64 bytes (0x00 - 0x3f) and both elements are 32 bytes.
                    mstore(scratch, leaf)
                    mstore(xor(scratch, 0x20), calldataload(offset))
                    // Call sha256 precompile
                    let result :=
                        staticcall(gas(), SHA256, 0x00, 0x40, 0x00, 0x20)

                    if eq(result, 0) { revert(0, 0) }

                    // Reuse `leaf` to store the hash to reduce stack operations.
                    leaf := mload(0x00)
                    offset := add(offset, 0x20)
                    if iszero(lt(offset, end)) { break }
                }
            }
            // index != 1
            if gt(sub(index, 1), 0) {
                // revert BranchHasMissingItem()
                mstore(0x00, 0x1b6661c3)
                revert(0x1c, 0x04)
            }
            isValid := eq(leaf, root)
        }
    }

    function concatGindices(uint64 a, uint64 b)
        internal
        pure
        returns (uint64)
    {
        uint64 stepBitLen = uint64(log2(b));
        return uint64(a << stepBitLen | b ^ (1 << stepBitLen));
    }

    /// @dev From solady FixedPointMath
    /// @dev Returns the log2 of `x`.
    /// Equivalent to computing the index of the most significant bit (MSB) of `x`.
    function log2(uint256 x) internal pure returns (uint256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(x) {
                // Store the function selector of `Log2Undefined()`.
                mstore(0x00, 0x5be3aa5c)
                // Revert with (offset, size).
                revert(0x1c, 0x04)
            }

            r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))

            // For the remaining 32 bits, use a De Bruijn lookup.
            // See: https://graphics.stanford.edu/~seander/bithacks.html
            x := shr(r, x)
            x := or(x, shr(1, x))
            x := or(x, shr(2, x))
            x := or(x, shr(4, x))
            x := or(x, shr(8, x))
            x := or(x, shr(16, x))

            // forgefmt: disable-next-item
            r := or(r, byte(shr(251, mul(x, shl(224, 0x07c4acdd))),
                0x0009010a0d15021d0b0e10121619031e080c141c0f111807131b17061a05041f))
        }
    }
}

contract AssayBench {
    function branchWords() internal pure returns (bytes32[] memory words) {
        words = abi.decode(hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000ca94d19abb415b322fea91ce84c433271edd23284458c4029bd5853b167283722dcd9ca31727b08e26f1169a117a180852598d3f1ca82a8d337d544eb49b383b970d95a8359bca2f1201367284b9793cee08549513ffaf273298c8e964ea1b3cd8a4beb85e993dd8cf5ed6cc325acd88bb7074e3bc939182e916ddb6f6495e7a35716755d9682678985a9a01e44a10bf34f7dea4e73a4f47e062ae5723189877d220729049d9d3ab8fe1a93bc0cc7f305d3f37ad2e5d61762736e5942f3e47f3003d740e4aa004ce07fb1324175f8ba9e5111b05d6474743c565dd152aee0b7cd6dd3b9955d892d92338b19976fd07084bfe88a76c3063482b7f30ee60feb2a58c658c73f8038edb270b682e8f6f9c27e1adb33a81fc0ed53140f367d593bb52a0000000000000000000000000000000000000000000000000000000000000000f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b98ce53144681e66d01cccdb788c3acb329e38c82cc6bf34319bc46f67f9b2b77", (bytes32[]));
    }

    function callVerify(bytes32[] calldata proof, bytes32 root, bytes32 leaf, uint256 gI)
        external
        view
        returns (bool)
    {
        return SSZ.verifyProof(proof, root, leaf, gI);
    }

    function callBaseline(bytes32[] calldata proof, bytes32 root, bytes32 leaf, uint256 gI)
        external
        pure
        returns (bool)
    {
        return (proof.length ^ uint256(root) ^ uint256(leaf) ^ gI) > 0;
    }

    function benchLeaf() internal pure returns (bytes32) {
        return bytes32(0x308f6853dc993c6a2bb2510f69bd63c4d3b6a61af3768b84173718b221ec1c02);
    }

    function verify() external view returns (uint256) {
        require(this.callVerify(branchWords(), bytes32(0xbff32708d86309510fce9e8845aec6ff2d30f0511c9d2f990c47cd586efe151a), benchLeaf(), 6434), "proof");
        return 1;
    }

    function baseline() external view returns (uint256) {
        require(this.callBaseline(branchWords(), bytes32(0xbff32708d86309510fce9e8845aec6ff2d30f0511c9d2f990c47cd586efe151a), benchLeaf(), 6434), "baseline");
        return 2;
    }
}
