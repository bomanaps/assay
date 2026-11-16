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
        words = abi.decode(hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000032dca2fc9664f41dcbfe69d31772beb7bd6ca700a8cdeb2948fc5a79916e39518bc076f93bcb709b3656b815a380b0d7b9b46c80d83b6bc9a0331eae2898d083cd536c37402191bdb5d11834ce765520568afc261d49b24babcec04ece5e0184513891bcccc5e6ae1badaf59db3b0753d1cc678efa6d16602d2bcbac38c91977eadb30585496dd249c5deaef4770921062546f49ecfc1568f46b97e00007236917b4a4f7a08f8144f3c1e59c9db7f42da417d26543d08e1b063f3b91a6fa03d337446a71816e93ee7900baf7eb5d4f9c6da7c809d53a29353589e5f4fdf132871ce002cf1116d8a636e8f2037e4b91503dbed55d95d2647d48ec070ee6a2dfd6f8b0a60e2564e370880c6349b47f556baca654fbaed8862c645490e45408cefbab5f8ed05bb11aacf2db64976e3b7c60d6b798ddb93bd1ac1cd2353e09e84b9eb3f139994839825564e6d213cbc6cdf11ec98ebb90fd5aa1f1236df9cc0d419c6e2fb6086f5b0e81295838efc9b59571f66a87fa3139cf6893c8d5602a7418a951d48be0c7794969b54c4558ebe7fd6480b9d52a5cb581c9393ae7ebe259eb2c3c021b3df7852422d99c7cd976551a4672bc52b03b6bb2d268e63ea41f74cdc8b013d8bb4d0051da5a4218d73b79292e0cd7de5c8f8b21ad96c240341c289de9017d8a92b267cf319e8c6662e7beb101ad9e280ae52125fc0de5f8df338f6ab894499f0e18d97c4b923dd1d80a98fe12105db0be740d376e3658fc0945e270707972cef623318153bad0a6236370c7e21b0b43191e67d93f533393d812e33536c78166304111bd486b01ab7ad3b1862b70b62d75cd7612b210bb94e4e74d9b8270f893e908917775b62bff23294dbbe3a1cd8e6cc1c35b4801887b646a6f81f17fcddba7b592e3133393c16194fac7431abf2f5485ed711db282183c819e08ebaaadc7b59bcf4ce97eafec8ac5aaeaa176d0b2e2bab5e18dc1eec143f9b1bf8033feb3c337d7a51a6fbf00b9e34c52e1c9195c969bd4e7a0bfd51d5c5bed9c1167e71f0aa83cc32edfbefa9f4d3e0174ca85182eec9f3a09f6a6c0df6377a510d731206fa80a50bb6abe29085058f16212212a60eec8f049fecb92d8c8e0a84bc021352bfecbeddde993839f614c3dac0a3ee37543f9b412b16199dc158e23b544619e312724bb6d7c3153ed9de791d764a366b389af13c58bf8a8d90481a467657cdd2986268250628d0c10e385c58c6191e6fbe05191bcc04f133f2cea72c1c4848930bd7ba8cac54661072113fb278869e07bb8587f91392933374d017bcbe18869ff2c22b28cc10510d9853292803328be4fb0e80495e8bb8d271f5b889636b5fe28e79f1b850f8658246ce9b6a1e7b49fc06db7143e8fe0b4f2b0c5523a5c985e929f70af28d0bdd1a90a808f977f597c7c778c489e98d3bd8910d31ac0f7c6f67e02e6e4e1bdefb994c6098953f34636ba2b6ca20a4721d2b26a886722ff1c9a7e5ff1cf48b4ad1582d3f4e4a1004f3b20d8c5a2b71387a4254ad933ebc52f075ae229646b6f6aed19a5e372cf295081401eb893ff599b3f9acc0c0d3e7d328921deb59612076801e8cd61592107b5c67c79b846595cc6320c395b46362cbfb909fdb236ad2411b4e4883810a074b840464689986c3f8a8091827e17c32755d8fb3687ba3ba49f342c77f5a1f89bec83d811446e1a467139213d640b6a74f7210d4f8e7e1039790e7bf4efa207555a10a6db1dd4b95da313aaa88b88fe76ad21b516cbc645ffe34ab5de1c8aef8cd4e7f8d2b51e8e1456adc7563cda206f76af240000000000000000000000000000000000000000000000000000000000c6341f00000000000000000000000000000000000000000000000000000000002c5f0e77ff4109cccbf29695da82d4d2a606554fa76ad530eb8f7b30ea63691c1b420fac31bde29f9ca09ca9ff1046363c71d603d5c77c75aa88e2af91ccfedb5527e9b78521c1ea742a5efc2dc77fd06fddad9bd81564bd3bbb2b3e7506ed8ed8ea29d967a379240ccdc25c3f6e5ec638a5d5a58d54aeb05204fbd8227bf26b1bec672660b586883283a1ae70435c7ff3f90391186dd8e5769459f36c1f4fe326eec1bbfa33400a3eae1bbaae40458e6312df6c90b568c77fcf690933c703e5548ae1cd500328193bca25d1102eb9580320c6cb4eed7c03706679aa5d8d9d1fba9612e7413c103a4ec477f11d8c3666614f5ebef678da44b41cc553e32f8af1", (bytes32[]));
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

    function benchLeaf() internal view returns (bytes32) {
        SSZ.Validator memory validator = SSZ.Validator({
            pubkey: hex"821a1c6d2115d652dd98aa6d8ffd01311778c73dc8a8087d2b97e3e3f314b1276af64eeb6513c249cccc21f3833b2469",
            withdrawalCredentials: bytes32(0x010000000000000000000000834beedcdb85bc51bff59c0b6a8c2414aa0818cc),
            effectiveBalance: 32000000000,
            slashed: false,
            activationEligibilityEpoch: 470673,
            activationEpoch: 470679,
            exitEpoch: 18446744073709551615,
            withdrawableEpoch: 18446744073709551615
        });
        return SSZ.validatorHashTreeRoot(validator);
    }

    function verify() external view returns (uint256) {
        require(this.callVerify(branchWords(), bytes32(0xfa1557e717b18cb9aaa9a4f35ebaa452ac5e1bfec1981adea68df917aa8c7a6c), benchLeaf(), 1572301630065358), "proof");
        return 1;
    }

    function baseline() external view returns (uint256) {
        require(this.callBaseline(branchWords(), bytes32(0xfa1557e717b18cb9aaa9a4f35ebaa452ac5e1bfec1981adea68df917aa8c7a6c), benchLeaf(), 1572301630065358), "baseline");
        return 2;
    }
}
