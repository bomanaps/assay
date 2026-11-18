// SPDX-License-Identifier: Apache-2.0
pragma solidity <0.9.0 >=0.5.10 ^0.8.20;

// src/trie/Memory.sol
// Copyright (C) Polytope Labs Ltd.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

library Memory {
    uint256 internal constant WORD_SIZE = 32;

    /*
     * Compares the 'len' bytes starting at address 'addr' in memory with the 'len'
     * bytes starting at 'addr2'.
     * Returns 'true' if the bytes are the same, otherwise 'false'.
     */
    function equals(
        uint256 addr,
        uint256 addr2,
        uint256 len
    ) internal pure returns (bool equal) {
        assembly {
            equal := eq(keccak256(addr, len), keccak256(addr2, len))
        }
    }

    /*
     * Compares the 'len' bytes starting at address 'addr' in memory with the bytes stored in
     * 'bts'. It is allowed to set 'len' to a lower value then 'bts.length', in which case only
     * the first 'len' bytes will be compared.
     * Requires that 'bts.length >= len'
     */

    function equals(
        uint256 addr,
        uint256 len,
        bytes memory bts
    ) internal pure returns (bool equal) {
        require(bts.length >= len);
        uint256 addr2;
        assembly {
            addr2 := add(bts, /*BYTES_HEADER_SIZE*/ 32)
        }
        return equals(addr, addr2, len);
    }
    // Returns a memory pointer to the data portion of the provided bytes array.

    function dataPtr(bytes memory bts) internal pure returns (uint256 addr) {
        assembly {
            addr := add(bts, /*BYTES_HEADER_SIZE*/ 32)
        }
    }

    /*
     * Creates a 'bytes memory' variable from the memory address 'addr', with the
     * length 'len'. The function will allocate new memory for the bytes array, and
     * the 'len bytes starting at 'addr' will be copied into that new memory.
     */
    function toBytes(
        uint256 addr,
        uint256 len
    ) internal pure returns (bytes memory bts) {
        bts = new bytes(len);
        uint256 btsptr;
        assembly {
            btsptr := add(bts, /*BYTES_HEADER_SIZE*/ 32)
        }
        copy(addr, btsptr, len);
    }

    /*
     * Copies 'self' into a new 'bytes memory'.
     * Returns the newly created 'bytes memory'
     * The returned bytes will be of length '32'.
     */
    function toBytes(bytes32 self) internal pure returns (bytes memory bts) {
        bts = new bytes(32);
        assembly {
            mstore(add(bts, /*BYTES_HEADER_SIZE*/ 32), self)
        }
    }

    /*
     * Copy 'len' bytes from memory address 'src', to address 'dest'.
     * This function does not check the or destination, it only copies
     * the bytes.
     */
    function copy(uint256 src, uint256 dest, uint256 len) internal pure {
        // Copy word-length chunks while possible
        for (; len >= WORD_SIZE; len -= WORD_SIZE) {
            assembly {
                mstore(dest, mload(src))
            }
            dest += WORD_SIZE;
            src += WORD_SIZE;
        }

        // Copy remaining bytes
        uint256 mask = len == 0
            ? 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            : 256 ** (WORD_SIZE - len) - 1;
        assembly {
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dest), mask)
            mstore(dest, or(destpart, srcpart))
        }
    }

    /*
     * This function does the same as 'dataPtr(bytes memory)', but will also return the
     * length of the provided bytes array.
     */
    function fromBytes(
        bytes memory bts
    ) internal pure returns (uint256 addr, uint256 len) {
        len = bts.length;
        assembly {
            addr := add(bts, /*BYTES_HEADER_SIZE*/ 32)
        }
    }
}

// src/trie/Node.sol
// Copyright (C) Polytope Labs Ltd.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

struct ByteSlice {
    bytes data;
    uint256 offset;
}

struct NibbleSlice {
    bytes data;
    uint256 offset;
}

// This is an enum for the different node types.
struct NodeKind {
    bool isEmpty;
    bool isLeaf;
    bool isHashedLeaf;
    bool isNibbledValueBranch;
    bool isNibbledHashedValueBranch;
    bool isNibbledBranch;
    bool isExtension;
    bool isBranch;
    uint256 nibbleSize;
    ByteSlice data;
}

struct NodeHandle {
    bool isHash;
    bytes32 hash;
    bool isInline;
    bytes inLine;
}

struct Extension {
    NibbleSlice key;
    NodeHandle node;
}

struct Branch {
    NodeHandleOption value;
    NodeHandleOption[16] children;
}

struct NibbledBranch {
    NibbleSlice key;
    NodeHandleOption value;
    NodeHandleOption[16] children;
}

struct ValueOption {
    bool isSome;
    bytes value;
}

struct NodeHandleOption {
    bool isSome;
    NodeHandle value;
}

struct Leaf {
    NibbleSlice key;
    NodeHandle value;
}

struct TrieNode {
    bytes32 hash;
    bytes node;
}

// Outcome of a successfully verified merkle-patricia proof.
struct StorageValue {
    // the storage key
    bytes key;
    // the encoded value
    bytes value;
}

// src/trie/ethereum/RLPReader.sol

/*
 * @author Hamdi Allam hamdi.allam97@gmail.com
 * Please reach out with any questions or concerns
 */

library RLPReader {
    uint8 constant STRING_SHORT_START = 0x80;
    uint8 constant STRING_LONG_START = 0xb8;
    uint8 constant LIST_SHORT_START = 0xc0;
    uint8 constant LIST_LONG_START = 0xf8;
    uint8 constant WORD_SIZE = 32;

    struct RLPItem {
        uint256 len;
        uint256 memPtr;
    }

    struct Iterator {
        RLPItem item; // Item that's being iterated over.
        uint256 nextPtr; // Position of the next item in the list.
    }

    /*
     * @dev Returns the next element in the iteration. Reverts if it has not next element.
     * @param self The iterator.
     * @return The next element in the iteration.
     */
    function next(Iterator memory self) internal pure returns (RLPItem memory) {
        require(hasNext(self));

        uint256 ptr = self.nextPtr;
        uint256 itemLength = _itemLength(ptr);
        self.nextPtr = ptr + itemLength;

        return RLPItem(itemLength, ptr);
    }

    /*
     * @dev Returns true if the iteration has more elements.
     * @param self The iterator.
     * @return true if the iteration has more elements.
     */
    function hasNext(Iterator memory self) internal pure returns (bool) {
        RLPItem memory item = self.item;
        return self.nextPtr < item.memPtr + item.len;
    }

    /*
     * @param item RLP encoded bytes
     */
    function toRlpItem(bytes memory item) internal pure returns (RLPItem memory) {
        uint256 memPtr;
        assembly {
            memPtr := add(item, 0x20)
        }

        return RLPItem(item.length, memPtr);
    }

    /*
     * @dev Create an iterator. Reverts if item is not a list.
     * @param self The RLP item.
     * @return An 'Iterator' over the item.
     */
    function iterator(RLPItem memory self) internal pure returns (Iterator memory) {
        require(isList(self));

        uint256 ptr = self.memPtr + _payloadOffset(self.memPtr);
        return Iterator(self, ptr);
    }

    /*
     * @param the RLP item.
     */
    function rlpLen(RLPItem memory item) internal pure returns (uint256) {
        return item.len;
    }

    /*
     * @param the RLP item.
     * @return (memPtr, len) pair: location of the item's payload in memory.
     */
    function payloadLocation(RLPItem memory item) internal pure returns (uint256, uint256) {
        uint256 offset = _payloadOffset(item.memPtr);
        uint256 memPtr = item.memPtr + offset;
        uint256 len = item.len - offset; // data length
        return (memPtr, len);
    }

    /*
     * @param the RLP item.
     */
    function payloadLen(RLPItem memory item) internal pure returns (uint256) {
        (, uint256 len) = payloadLocation(item);
        return len;
    }

    /*
     * @param the RLP item containing the encoded list.
     */
    function toList(RLPItem memory item) internal pure returns (RLPItem[] memory) {
        require(isList(item));

        uint256 items = numItems(item);
        RLPItem[] memory result = new RLPItem[](items);

        uint256 memPtr = item.memPtr + _payloadOffset(item.memPtr);
        uint256 dataLen;
        for (uint256 i = 0; i < items; i++) {
            dataLen = _itemLength(memPtr);
            result[i] = RLPItem(dataLen, memPtr);
            memPtr = memPtr + dataLen;
        }

        return result;
    }

    // @return indicator whether encoded payload is a list. negate this function call for isData.
    function isList(RLPItem memory item) internal pure returns (bool) {
        if (item.len == 0) return false;

        uint8 byte0;
        uint256 memPtr = item.memPtr;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < LIST_SHORT_START) return false;
        return true;
    }

    /*
     * @dev A cheaper version of keccak256(toRlpBytes(item)) that avoids copying memory.
     * @return keccak256 hash of RLP encoded bytes.
     */
    function rlpBytesKeccak256(RLPItem memory item) internal pure returns (bytes32) {
        uint256 ptr = item.memPtr;
        uint256 len = item.len;
        bytes32 result;
        assembly {
            result := keccak256(ptr, len)
        }
        return result;
    }

    /*
     * @dev A cheaper version of keccak256(toBytes(item)) that avoids copying memory.
     * @return keccak256 hash of the item payload.
     */
    function payloadKeccak256(RLPItem memory item) internal pure returns (bytes32) {
        (uint256 memPtr, uint256 len) = payloadLocation(item);
        bytes32 result;
        assembly {
            result := keccak256(memPtr, len)
        }
        return result;
    }

    /**
     * RLPItem conversions into data types *
     */

    // @returns raw rlp encoding in bytes
    function toRlpBytes(RLPItem memory item) internal pure returns (bytes memory) {
        bytes memory result = new bytes(item.len);
        if (result.length == 0) return result;

        uint256 ptr;
        assembly {
            ptr := add(0x20, result)
        }

        copy(item.memPtr, ptr, item.len);
        return result;
    }

    // any non-zero byte except "0x80" is considered true
    function toBoolean(RLPItem memory item) internal pure returns (bool) {
        require(item.len == 1);
        uint256 result;
        uint256 memPtr = item.memPtr;
        assembly {
            result := byte(0, mload(memPtr))
        }

        /*
         * SEE Github Issue #5.
         * Summary: Most commonly used RLP libraries (i.e Geth) will encode
         * "0" as "0x80" instead of as "0". We handle this edge case explicitly
         * here.
         */
        if (result == 0 || result == STRING_SHORT_START) {
            return false;
        } else {
            return true;
        }
    }

    function toAddress(RLPItem memory item) internal pure returns (address) {
        // 1 byte for the length prefix
        require(item.len == 21);

        return address(uint160(toUint(item)));
    }

    function toUint(RLPItem memory item) internal pure returns (uint256) {
        require(item.len > 0 && item.len <= 33);

        (uint256 memPtr, uint256 len) = payloadLocation(item);

        uint256 result;
        assembly {
            result := mload(memPtr)

            // shift to the correct location if neccesary
            if lt(len, 32) { result := div(result, exp(256, sub(32, len))) }
        }

        return result;
    }

    // enforces 32 byte length
    function toUintStrict(RLPItem memory item) internal pure returns (uint256) {
        // one byte prefix
        require(item.len == 33);

        uint256 result;
        uint256 memPtr = item.memPtr + 1;
        assembly {
            result := mload(memPtr)
        }

        return result;
    }

    function toBytes(RLPItem memory item) internal pure returns (bytes memory) {
        require(item.len > 0);

        (uint256 memPtr, uint256 len) = payloadLocation(item);
        bytes memory result = new bytes(len);

        uint256 destPtr;
        assembly {
            destPtr := add(0x20, result)
        }

        copy(memPtr, destPtr, len);
        return result;
    }

    /*
     * Private Helpers
     */

    // @return number of payload items inside an encoded list.
    function numItems(RLPItem memory item) private pure returns (uint256) {
        if (item.len == 0) return 0;

        uint256 count = 0;
        uint256 currPtr = item.memPtr + _payloadOffset(item.memPtr);
        uint256 endPtr = item.memPtr + item.len;
        while (currPtr < endPtr) {
            currPtr = currPtr + _itemLength(currPtr); // skip over an item
            count++;
        }

        return count;
    }

    // @return entire rlp item byte length
    function _itemLength(uint256 memPtr) private pure returns (uint256) {
        uint256 itemLen;
        uint256 byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START) {
            itemLen = 1;
        } else if (byte0 < STRING_LONG_START) {
            itemLen = byte0 - STRING_SHORT_START + 1;
        } else if (byte0 < LIST_SHORT_START) {
            assembly {
                let byteLen := sub(byte0, 0xb7) // # of bytes the actual length is
                memPtr := add(memPtr, 1) // skip over the first byte

                // 32 byte word size
                let dataLen := div(mload(memPtr), exp(256, sub(32, byteLen))) // right shifting to get the len
                itemLen := add(dataLen, add(byteLen, 1))
            }
        } else if (byte0 < LIST_LONG_START) {
            itemLen = byte0 - LIST_SHORT_START + 1;
        } else {
            assembly {
                let byteLen := sub(byte0, 0xf7)
                memPtr := add(memPtr, 1)

                let dataLen := div(mload(memPtr), exp(256, sub(32, byteLen))) // right shifting to the correct length
                itemLen := add(dataLen, add(byteLen, 1))
            }
        }

        return itemLen;
    }

    // @return number of bytes until the data
    function _payloadOffset(uint256 memPtr) private pure returns (uint256) {
        uint256 byte0;
        assembly {
            byte0 := byte(0, mload(memPtr))
        }

        if (byte0 < STRING_SHORT_START) {
            return 0;
        } else if (byte0 < STRING_LONG_START || (byte0 >= LIST_SHORT_START && byte0 < LIST_LONG_START)) {
            return 1;
        } else if (byte0 < LIST_SHORT_START) {
            // being explicit
            return byte0 - (STRING_LONG_START - 1) + 1;
        } else {
            return byte0 - (LIST_LONG_START - 1) + 1;
        }
    }

    /*
     * @param src Pointer to source
     * @param dest Pointer to destination
     * @param len Amount of memory to copy from the source
     */
    function copy(uint256 src, uint256 dest, uint256 len) private pure {
        if (len == 0) return;

        // copy as many word sizes as possible
        for (; len >= WORD_SIZE; len -= WORD_SIZE) {
            assembly {
                mstore(dest, mload(src))
            }

            src += WORD_SIZE;
            dest += WORD_SIZE;
        }

        if (len > 0) {
            // left over bytes. Mask is used to remove unwanted bytes from the word
            uint256 mask = 256 ** (WORD_SIZE - len) - 1;
            assembly {
                let srcpart := and(mload(src), not(mask)) // zero out src
                let destpart := and(mload(dest), mask) // retrieve the bytes
                mstore(dest, or(destpart, srcpart))
            }
        }
    }
}

// src/trie/NibbleSlice.sol
// Copyright (C) Polytope Labs Ltd.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

library NibbleSliceOps {
    uint256 internal constant NIBBLE_PER_BYTE = 2;
    uint256 internal constant BITS_PER_NIBBLE = 4;

    function len(NibbleSlice memory nibble) internal pure returns (uint256) {
        return nibble.data.length * NIBBLE_PER_BYTE - nibble.offset;
    }

    function mid(
        NibbleSlice memory self,
        uint256 i
    ) internal pure returns (NibbleSlice memory) {
        return NibbleSlice(self.data, self.offset + i);
    }

    function isEmpty(NibbleSlice memory self) internal pure returns (bool) {
        return len(self) == 0;
    }

    function eq(
        NibbleSlice memory self,
        NibbleSlice memory other
    ) internal pure returns (bool) {
        return len(self) == len(other) && startsWith(self, other);
    }

    function at(
        NibbleSlice memory self,
        uint256 i
    ) internal pure returns (uint256) {
        uint256 ix = (self.offset + i) / NIBBLE_PER_BYTE;
        uint256 pad = (self.offset + i) % NIBBLE_PER_BYTE;
        uint8 data = uint8(self.data[ix]);
        return (pad == 1) ? data & 0x0F : data >> BITS_PER_NIBBLE;
    }

    function startsWith(
        NibbleSlice memory self,
        NibbleSlice memory other
    ) internal pure returns (bool) {
        return commonPrefix(self, other) == len(other);
    }

    function commonPrefix(
        NibbleSlice memory self,
        NibbleSlice memory other
    ) internal pure returns (uint256) {
        uint256 self_align = self.offset % NIBBLE_PER_BYTE;
        uint256 other_align = other.offset % NIBBLE_PER_BYTE;

        if (self_align == other_align) {
            uint256 self_start = self.offset / NIBBLE_PER_BYTE;
            uint256 other_start = other.offset / NIBBLE_PER_BYTE;
            uint256 first = 0;

            if (self_align != 0) {
                if (
                    (self.data[self_start] & 0x0F) !=
                    (other.data[other_start] & 0x0F)
                ) {
                    return 0;
                }
                ++self_start;
                ++other_start;
                ++first;
            }
            bytes memory selfSlice = bytesSlice(self.data, self_start);
            bytes memory otherSlice = bytesSlice(other.data, other_start);
            return biggestDepth(selfSlice, otherSlice) + first;
        } else {
            uint256 s = min(len(self), len(other));
            uint256 i = 0;
            while (i < s) {
                if (at(self, i) != at(other, i)) {
                    break;
                }
                ++i;
            }
            return i;
        }
    }

    function biggestDepth(
        bytes memory a,
        bytes memory b
    ) internal pure returns (uint256) {
        uint256 upperBound = min(a.length, b.length);
        uint256 i = 0;
        while (i < upperBound) {
            if (a[i] != b[i]) {
                return i * NIBBLE_PER_BYTE + leftCommon(a[i], b[i]);
            }
            ++i;
        }
        return i * NIBBLE_PER_BYTE;
    }

    function leftCommon(bytes1 a, bytes1 b) internal pure returns (uint256) {
        if (a == b) {
            return 2;
        } else if (uint8(a) & 0xF0 == uint8(b) & 0xF0) {
            return 1;
        } else {
            return 0;
        }
    }

    function bytesSlice(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (bytes memory) {
        uint256 bytesLength = _bytes.length;
        uint256 _length = bytesLength - _start;
        require(bytesLength >= _start, "slice_outOfBounds");

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                tempBytes := mload(0x40) // load free memory pointer
                let lengthmod := and(_length, 31)

                let mc := add(
                    add(tempBytes, lengthmod),
                    mul(0x20, iszero(lengthmod))
                )
                let end := add(mc, _length)

                for {
                    let cc := add(
                        add(
                            add(_bytes, lengthmod),
                            mul(0x20, iszero(lengthmod))
                        ),
                        _start
                    )
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                mstore(0x40, and(add(mc, 31), not(31)))
            }
            default {
                tempBytes := mload(0x40)
                mstore(tempBytes, 0)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }
        return tempBytes;
    }

    function min(uint256 a, uint256 b) private pure returns (uint256) {
        return (a < b) ? a : b;
    }
}

// src/trie/Option.sol
// Copyright (C) Polytope Labs Ltd.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

library Option {
    function isSome(ValueOption memory val) internal pure returns (bool) {
        return val.isSome == true;
    }

    function isSome(NodeHandleOption memory val) internal pure returns (bool) {
        return val.isSome == true;
    }
}

// src/trie/TrieDB.sol
// Copyright (C) Polytope Labs Ltd.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

library TrieDB {
    function get(
        TrieNode[] memory nodes,
        bytes32 hash
    ) internal pure returns (bytes memory) {
        for (uint256 i = 0; i < nodes.length; i++) {
            if (nodes[i].hash == hash) {
                return nodes[i].node;
            }
        }
        revert("Incomplete Proof!");
    }

    function load(
        TrieNode[] memory nodes,
        NodeHandle memory node
    ) internal pure returns (bytes memory) {
        if (node.isInline) {
            return node.inLine;
        } else if (node.isHash) {
            return get(nodes, node.hash);
        }

        return bytes("");
    }

    function isNibbledBranch(
        NodeKind memory node
    ) internal pure returns (bool) {
        return (node.isNibbledBranch ||
            node.isNibbledHashedValueBranch ||
            node.isNibbledValueBranch);
    }

    function isExtension(NodeKind memory node) internal pure returns (bool) {
        return node.isExtension;
    }

    function isBranch(NodeKind memory node) internal pure returns (bool) {
        return node.isBranch;
    }

    function isLeaf(NodeKind memory node) internal pure returns (bool) {
        return (node.isLeaf || node.isHashedLeaf);
    }

    function isEmpty(NodeKind memory node) internal pure returns (bool) {
        return node.isEmpty;
    }

    function isHash(NodeHandle memory node) internal pure returns (bool) {
        return node.isHash;
    }

    function isInline(NodeHandle memory node) internal pure returns (bool) {
        return node.isInline;
    }
}

// src/trie/Bytes.sol
// Copyright (C) Polytope Labs Ltd.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

library Bytes {
    uint256 internal constant BYTES_HEADER_SIZE = 32;

    /*
     * Checks if two `bytes memory` variables are equal. This is done using hashing,
     * which is much more gas efficient then comparing each byte individually.
     * Equality means that:
     *  - 'self.length == other.length'
     *  - For 'n' in '[0, self.length)', 'self[n] == other[n]'
     */
    function equals(
        bytes memory self,
        bytes memory other
    ) internal pure returns (bool equal) {
        if (self.length != other.length) {
            return false;
        }
        uint256 addr;
        uint256 addr2;
        assembly {
            addr := add(self, /*BYTES_HEADER_SIZE*/ 32)
            addr2 := add(other, /*BYTES_HEADER_SIZE*/ 32)
        }
        equal = Memory.equals(addr, addr2, self.length);
    }

    function readByte(ByteSlice memory self) internal pure returns (uint8) {
        if (self.offset + 1 > self.data.length) {
            revert("Out of range");
        }

        uint8 b = uint8(self.data[self.offset]);
        self.offset += 1;

        return b;
    }

    /*
     * Copies 'len' bytes from 'self' into a new array, starting at the provided 'startIndex'.
     * Returns the new copy.
     * Requires that:
     *  - 'startIndex + len <= self.length'
     * The length of the substring is: 'len'
     */
    function read(
        ByteSlice memory self,
        uint256 len
    ) internal pure returns (bytes memory) {
        require(self.offset + len <= self.data.length);
        if (len == 0) {
            return "";
        }
        uint256 addr = Memory.dataPtr(self.data);
        bytes memory slice = Memory.toBytes(addr + self.offset, len);
        self.offset += len;
        return slice;
    }

    /*
     * Copies a section of 'self' into a new array, starting at the provided 'startIndex'.
     * Returns the new copy.
     * Requires that 'startIndex <= self.length'
     * The length of the substring is: 'self.length - startIndex'
     */
    function substr(
        bytes memory self,
        uint256 startIndex
    ) internal pure returns (bytes memory) {
        require(startIndex <= self.length);
        uint256 len = self.length - startIndex;
        uint256 addr = Memory.dataPtr(self);
        return Memory.toBytes(addr + startIndex, len);
    }

    /*
     * Copies 'len' bytes from 'self' into a new array, starting at the provided 'startIndex'.
     * Returns the new copy.
     * Requires that:
     *  - 'startIndex + len <= self.length'
     * The length of the substring is: 'len'
     */
    function substr(
        bytes memory self,
        uint256 startIndex,
        uint256 len
    ) internal pure returns (bytes memory) {
        require(startIndex + len <= self.length);
        if (len == 0) {
            return "";
        }
        uint256 addr = Memory.dataPtr(self);
        return Memory.toBytes(addr + startIndex, len);
    }

    /*
     * Combines 'self' and 'other' into a single array.
     * Returns the concatenated arrays:
     *  [self[0], self[1], ... , self[self.length - 1], other[0], other[1], ... , other[other.length - 1]]
     * The length of the new array is 'self.length + other.length'
     */
    function concat(
        bytes memory self,
        bytes memory other
    ) internal pure returns (bytes memory) {
        bytes memory ret = new bytes(self.length + other.length);
        uint256 src;
        uint256 srcLen;
        (src, srcLen) = Memory.fromBytes(self);
        uint256 src2;
        uint256 src2Len;
        (src2, src2Len) = Memory.fromBytes(other);
        uint256 dest;
        (dest, ) = Memory.fromBytes(ret);
        uint256 dest2 = dest + srcLen;
        Memory.copy(src, dest, srcLen);
        Memory.copy(src2, dest2, src2Len);
        return ret;
    }

    function toBytes32(bytes memory self) internal pure returns (bytes32 out) {
        require(self.length >= 32, "Bytes:: toBytes32: data is to short.");
        assembly {
            out := mload(add(self, 32))
        }
    }

    function toBytes16(
        bytes memory self,
        uint256 offset
    ) internal pure returns (bytes16 out) {
        for (uint256 i = 0; i < 16; i++) {
            out |= bytes16(bytes1(self[offset + i]) & 0xFF) >> (i * 8);
        }
    }

    function toBytes8(
        bytes memory self,
        uint256 offset
    ) internal pure returns (bytes8 out) {
        for (uint256 i = 0; i < 8; i++) {
            out |= bytes8(bytes1(self[offset + i]) & 0xFF) >> (i * 8);
        }
    }

    function toBytes4(
        bytes memory self,
        uint256 offset
    ) internal pure returns (bytes4) {
        bytes4 out;

        for (uint256 i = 0; i < 4; i++) {
            out |= bytes4(self[offset + i] & 0xFF) >> (i * 8);
        }
        return out;
    }

    function toBytes2(
        bytes memory self,
        uint256 offset
    ) internal pure returns (bytes2) {
        bytes2 out;

        for (uint256 i = 0; i < 2; i++) {
            out |= bytes2(self[offset + i] & 0xFF) >> (i * 8);
        }
        return out;
    }

    function removeLeadingZero(
        bytes memory data
    ) internal pure returns (bytes memory) {
        uint256 length = data.length;

        uint256 startIndex = 0;
        for (uint256 i = 0; i < length; i++) {
            if (data[i] != 0) {
                startIndex = i;
                break;
            }
        }

        return substr(data, startIndex);
    }

    function removeEndingZero(
        bytes memory data
    ) internal pure returns (bytes memory) {
        uint256 length = data.length;

        uint256 endIndex = 0;
        for (uint256 i = length - 1; i >= 0; i--) {
            if (data[i] != 0) {
                endIndex = i;
                break;
            }
        }

        return substr(data, 0, endIndex + 1);
    }

    function reverse(
        bytes memory inbytes
    ) internal pure returns (bytes memory) {
        uint256 inlength = inbytes.length;
        bytes memory outbytes = new bytes(inlength);

        for (uint256 i = 0; i <= inlength - 1; i++) {
            outbytes[i] = inbytes[inlength - i - 1];
        }

        return outbytes;
    }
}

// src/trie/ethereum/EthereumTrieDB.sol
/*
 * Copyright (C) Polytope Labs Ltd.

 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

library EthereumTrieDB {
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for RLPReader.Iterator;

    // keccak256(rlp("")) — root hash of an empty Ethereum trie.
    bytes32 constant HASHED_NULL_NODE =
        0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421;

    // Canonical RLP encoding of the empty trie node (an empty string).
    bytes constant EMPTY_NODE_ENCODING = hex"80";

    function decodeNodeKind(
        bytes memory encoded
    ) internal pure returns (NodeKind memory) {
        NodeKind memory node;
        ByteSlice memory input = ByteSlice(encoded, 0);
        if (Bytes.equals(encoded, EMPTY_NODE_ENCODING)) {
            node.isEmpty = true;
            return node;
        }
        RLPReader.RLPItem[] memory itemList = encoded.toRlpItem().toList();
        uint256 numItems = itemList.length;
        if (numItems == 0) {
            node.isEmpty = true;
            return node;
        } else if (numItems == 2) {
            // It may be a leaf or extension
            bytes memory key = itemList[0].toBytes();
            uint256 prefix;
            assembly {
                let first := shr(248, mload(add(key, 32)))
                prefix := shr(4, first)
            }
            if (prefix == 2 || prefix == 3) {
                node.isLeaf = true;
            } else {
                node.isExtension = true;
            }
        } else if (numItems == 17) {
            node.isBranch = true;
        } else {
            revert("Invalid data");
        }
        node.data = input;
        return node;
    }

    function decodeLeaf(
        NodeKind memory node
    ) internal pure returns (Leaf memory) {
        Leaf memory leaf;
        RLPReader.RLPItem[] memory decoded = node
            .data
            .data
            .toRlpItem()
            .toList();
        bytes memory data = decoded[1].toBytes();
        uint8 isOdd = uint8(decoded[0].toBytes()[0] >> 4) & 0x01;
        // For even: strip the full prefix byte (prefix nibble + padding nibble), offset 0.
        // For odd: keep the byte containing the first path nibble, offset 1 to skip the prefix nibble.
        leaf.key = NibbleSlice(
            Bytes.substr(decoded[0].toBytes(), (isOdd + 1) % 2),
            isOdd
        );
        leaf.value = NodeHandle(false, bytes32(0), true, data);

        return leaf;
    }

    function decodeExtension(
        NodeKind memory node
    ) internal pure returns (Extension memory) {
        Extension memory extension;
        RLPReader.RLPItem[] memory decoded = node
            .data
            .data
            .toRlpItem()
            .toList();
        uint8 isOdd = uint8(decoded[0].toBytes()[0] >> 4) & 0x01;
        // Remove the first byte, which is the prefix and not present in the user provided key
        extension.key = NibbleSlice(
            Bytes.substr(decoded[0].toBytes(), (isOdd + 1) % 2),
            isOdd
        );
        extension.node = decodeChildHandle(decoded[1]);
        return extension;
    }

    function decodeBranch(
        NodeKind memory node
    ) internal pure returns (Branch memory) {
        Branch memory branch;
        RLPReader.RLPItem[] memory decoded = node
            .data
            .data
            .toRlpItem()
            .toList();

        NodeHandleOption[16] memory childrens;

        for (uint256 i = 0; i < 16; i++) {
            childrens[i] = decodeChildOption(decoded[i]);
        }
        if (isEmpty(decoded[16].toBytes())) {
            branch.value = NodeHandleOption(
                false,
                NodeHandle(false, bytes32(0), false, new bytes(0))
            );
        } else {
            branch.value = NodeHandleOption(
                true,
                NodeHandle(false, bytes32(0), true, decoded[16].toBytes())
            );
        }
        branch.children = childrens;

        return branch;
    }

    function isEmpty(bytes memory item) internal pure returns (bool) {
        return item.length > 0 && (item[0] == 0xc0 || item[0] == 0x80);
    }

    // A branch child slot is one of: an empty string (absent), a 32-byte hash
    // reference, or an embedded RLP-encoded child node when its encoding is
    // shorter than 32 bytes. See https://ethereum.org/developers/docs/data-structures-and-encoding/patricia-merkle-trie/.
    function decodeChildOption(
        RLPReader.RLPItem memory item
    ) private pure returns (NodeHandleOption memory) {
        if (RLPReader.isList(item)) {
            return NodeHandleOption(
                true,
                NodeHandle(false, bytes32(0), true, RLPReader.toRlpBytes(item))
            );
        }
        bytes memory data = item.toBytes();
        if (data.length == 0) {
            return NodeHandleOption(
                false,
                NodeHandle(false, bytes32(0), false, new bytes(0))
            );
        }
        if (data.length == 32) {
            return NodeHandleOption(
                true,
                NodeHandle(true, Bytes.toBytes32(data), false, new bytes(0))
            );
        }
        revert("Invalid branch child reference");
    }

    // Extensions always reference a child (never absent). The reference is
    // either a 32-byte hash or an embedded RLP-encoded node.
    function decodeChildHandle(
        RLPReader.RLPItem memory item
    ) private pure returns (NodeHandle memory) {
        if (RLPReader.isList(item)) {
            return NodeHandle(false, bytes32(0), true, RLPReader.toRlpBytes(item));
        }
        bytes memory data = item.toBytes();
        require(data.length == 32, "Invalid extension child reference");
        return NodeHandle(true, Bytes.toBytes32(data), false, new bytes(0));
    }
}

// src/EthereumTrie.sol
// Copyright (C) Polytope Labs Ltd.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * @title Ethereum Merkle Patricia Trie verifier
 * @author Polytope Labs
 * @dev Verifies ethereum specific merkle patricia proofs as described by EIP-1186.
 * @dev refer to research for more info. https://research.polytope.technology/state-machine-proofs
 */
library EthereumTrie {
    using NibbleSliceOps for NibbleSlice;
    using EthereumTrieDB for NodeKind;

    /**
     * @notice Verifies ethereum specific merkle patricia proofs as described by EIP-1186.
     * @param root hash of the merkle patricia trie
     * @param proof a list of proof nodes
     * @param keys a list of keys to verify
     * @return bytes[] a list of values corresponding to the supplied keys.
     */
    function VerifyProof(
        bytes32 root,
        bytes[] memory proof,
        bytes[] memory keys
    ) internal pure returns (StorageValue[] memory) {
        StorageValue[] memory values = new StorageValue[](keys.length);

        // Empty trie root: every key is non-membership. The empty trie has no
        // proof nodes, so attempting to look up the root in `nodes` would
        // revert as "Incomplete Proof!" rather than returning a clean result.
        if (root == EthereumTrieDB.HASHED_NULL_NODE) {
            for (uint256 i = 0; i < keys.length; i++) {
                values[i].key = keys[i];
            }
            return values;
        }

        TrieNode[] memory nodes = new TrieNode[](proof.length);

        for (uint256 i = 0; i < proof.length; i++) {
            nodes[i] = TrieNode(keccak256(proof[i]), proof[i]);
        }

        for (uint256 i = 0; i < keys.length; i++) {
            values[i].key = keys[i];
            NibbleSlice memory keyNibbles = NibbleSlice(keys[i], 0);
            NodeKind memory node = EthereumTrieDB.decodeNodeKind(
                TrieDB.get(nodes, root)
            );

            /*
             * This loop is unbounded so that an adversary cannot insert a deeply nested key in the trie
             * and successfully convince us of it's non-existence, if we consume the block gas limit while
             * traversing the trie, then the transaction should revert.
             */
            for (uint256 j = 1; j > 0; j++) {
                NodeHandle memory nextNode;

                if (TrieDB.isLeaf(node)) {
                    Leaf memory leaf = node.decodeLeaf();
                    // Slice the remaining key to the current nibble offset,
                    // preserving nibble alignment (same approach as extensions).
                    keyNibbles = NibbleSlice(
                        NibbleSliceOps.bytesSlice(
                            keyNibbles.data,
                            keyNibbles.offset / 2
                        ),
                        keyNibbles.offset % 2
                    );
                    if (leaf.key.eq(keyNibbles)) {
                        values[i].value = TrieDB.load(nodes, leaf.value);
                    }
                    break;
                } else if (TrieDB.isExtension(node)) {
                    Extension memory extension = node.decodeExtension();
                    if (keyNibbles.startsWith(extension.key)) {
                        // Let's cut the key passed as input
                        uint256 cutNibble = keyNibbles.offset +
                            extension.key.len();
                        keyNibbles = NibbleSlice(
                            NibbleSliceOps.bytesSlice(
                                keyNibbles.data,
                                cutNibble / 2
                            ),
                            cutNibble % 2
                        );
                        nextNode = extension.node;
                    } else {
                        break;
                    }
                } else if (TrieDB.isBranch(node)) {
                    Branch memory branch = node.decodeBranch();
                    if (keyNibbles.isEmpty()) {
                        if (Option.isSome(branch.value)) {
                            values[i].value = TrieDB.load(
                                nodes,
                                branch.value.value
                            );
                        }
                        break;
                    } else {
                        NodeHandleOption memory handle = branch.children[
                            keyNibbles.at(0)
                        ];
                        if (Option.isSome(handle)) {
                            keyNibbles = keyNibbles.mid(1);
                            nextNode = handle.value;
                        } else {
                            break;
                        }
                    }
                } else if (TrieDB.isEmpty(node)) {
                    break;
                }

                node = EthereumTrieDB.decodeNodeKind(
                    TrieDB.load(nodes, nextNode)
                );
            }
        }

        return values;
    }
}

contract AssayBench {
    uint256 internal constant NODE_COUNT = 9;

    function benchProof() internal pure returns (bytes[] memory proof) {
        bytes[] memory nodes = new bytes[](NODE_COUNT);
        nodes[0] = hex"f90211a0024c052996f29184c0b69ff7e9badfb03fb794c731c13ca45cfc636f969f24e0a01feb7553e332b144ff1547edfa4b317daf5be9b0c896e3a62a1bc63169e1ecaaa0d5a923a074b79c4eb30826c0ad3afbbf749611e9e4e4ed97ce813ed1076df846a0f23987d693ef1c5ddfa3bb232e4f4d2ac1d35e13200cd571d559bbb575e4cde2a008cefe3fba22d8c13a85238919e36d358f7e7a4bf3c18915e4d15dd6abbc8b59a0dd56bd30e1652df8f768d6bf7f6bdb97aa7e9719d0dc31ad40389d715019ba4da0e4c8b88293addaf0faaa4b0551aac9c9ffbe1f34baa436751e86b1195537f178a0d0ded7a2faef5dfb5c4c63b7ae2ca3f26b42ae22115164c7a3b90053c48448ada0fc5a66ad37408508748d639069f78a8e651327d7e9e0cfa2e37b8475a3461acda05678c6c9d3fde9a770a463d39164d6dd963509294586586fb8f7ae8df13c27b3a03d9c2c604002c8aba3793d3ff90e9e443d45d45d3aac3118ba802435b53662baa07a81e9b55bab4e0baa248e8138db21b359212c984b134b08d412da983ce97355a0e0416097a562ce540523b7d03acc2b15d3295032fd88d6626d3f97bd533cc0fda0dff6d3c90f9f2f72c076ab7e27917db64d2c577bd5824568b8f68b74dc66aaa5a0894829a54c93cd5da18d9386551cc3d9a0f67a33aead97cb9d1e6914e4c53ae3a063b8c5b6eb3984a514e1853bc550cc033a0c29ada0ece44aa336ce8bb407aa4080";
        nodes[1] = hex"f90211a0d262841761a9cf1f0e6df810336a851c88c6458c96c4fef12d9db5c4ebd268eba03e3f71e70bc0673506898caba94869f1b5a7bb65a5fb8f79d994fa7e1f58c207a00bf3ab38f08707c1f7c1ca3644cad685021a96fa1299f1a3b6a41463a04bf304a0027da84ba9db29c25b5881988aee83e66acee35827e8941b7b33b08ac7823a50a0644173a84308646e10b4c53fc43c6c24e41eab5e046e74a0f5e608a9082fa1f3a024f807744ec5ecfba28bf16322806165a70997eb10b3460c151df58c14e80719a0fca8822baa40ed995dd3476378cdee4541977e4dff32931c2c211f394158a72ba0ad86421e1b15cd981fcf52fda848469d544ccd241113c81a78b4c4d81c31cd7ca06a6188c0223cac508cf0b1f2c9cb38882241e2d9aa444380a165b45359a37392a08c27e8f8a1179e4679c9af0301c0f7d8622f19d4a1cfe0cf9eb52f18b8c36a68a00d82915cd1dee8f71be91c5d1905b8b9139d3ee21d625005c3fafc167c828d61a099f515d8e93b97cb5363ac306f4167a6fabe1920877fb06e6e8fbd90c647d8e7a0262397bb49204e7bd4af1e758e44397f99291a8a822173e83275ed7e2a81003da03917b2aa7c843feca3d202fab315d6487f83029e8e50dae228af52f3b4256fcaa07c066ebbe524e18ba136f038abd84447cd5746ec142fd03a213d97943e16a8aaa09a5c3267f8262ab684608e5726652c0d17bbb3f670a88716009ed2dbcedb724380";
        nodes[2] = hex"f90211a03741b27663dbed54b229c429f8b7e0822cfa7e156c529300de106c8769d8082aa06af49227ba3a2d67f51f51eed67e43573e9e3fb1b1f491ddf9b192f1ec91e93aa0a6091d00ff66e773483786b10da1b7ccbe0cb7576db20a25305b3cbed418735aa06d922e0481dd9336f15a846ea863b1a224ba8bda45aeb922089f15409967f554a04cc437c4b77b936c6661bc2560278ba45860550e31716539a4093d58f6d97e72a0dbc8b7942fa22b6c163a9bcee9f0b11e6bd166b436c17173c9026d21113f1d63a0d8a99eaf8be2b6125559907d213fa91881480215e878e145b74392748976c503a0a35d693177462730e80686c01db449c1a3ef1da1a4cfae98c410e57731e55e59a017f433e9b09079ece259d2a644520dd827b81eb7f12ec48ba77c86c8dc613472a0c821692937e1639fbaef4cb810b88eb74580a7b5b7dfc838bd6b64063a25e733a0af48adf084ffa5761d0a9a291b32844f15ecd9d1b84688fa2603fd9a18b4cb17a04dffcc66ed170da0508c8e1a27c9e26d7b294d1dbe1ed2b42a3f0f02da0e8649a06ec67b428b135a7debde32f2b1ea0630e95d6bf391a5c077e671980711e5d473a03244a3aac5aca8f37b8a1e9e2ea3198e59412f48fdd95c9ae7d646f90dd69e57a0fed2f58788c616bb12277cb44db586c8bddc7d9c5b81e1b2d4056dddc2758c7ca02c4c82f1dc64c1ceacb9be5d5166daee6563ea6b940fafe4426b7e6607b6d4bc80";
        nodes[3] = hex"f90211a083206f5ba2edf8d4213244761980e18b79093250f43d8b038fd1a1b40fbb668ba0fd13f2f6b7a565e6cb34bf3be4af40f80e8f1bd422a15e0a62c309f34d29c5b7a08e7bc9f3fc6631e722157cfe813e5f7dbb9811409a3a15f1e96906d95727c57aa0cacc89064caf8856261c6a67e387293be426ea32d36c5eb31f64df5df3c01449a0a7749d077c504a2dfc8a1ee087f841a1720ba195a750a5e9bd5f5048b499ab12a0c6e3b20c4c81ca0d2d2575fc2e75721dfdd2d4a1c91bcb7ac0151f227fc79529a0c756c07282d8f0ce6b59ab2e25bd8f7bfb569a678d51564cca4ac3462b1b4dfea0fd7593e1d2811b66e06787f97a93d90cd111c7be93a839467b1987beffb95ce6a028aae79798663542e57937bb39022fd291e2325341d416576ff595c2f97b0805a031995e132e31e6e7765d311ab018a6418a7c79901304eb937b36e8a80c9d6e0ea0cafb30a20dd5af8fa781e16a5a55827ac01ed86cf7dd674e74b61762a045e20fa02654fb848a67a2056ff70e85d5df5ccb4149351b3e218738fbd28eaff61f23c1a073363790711ae0988fbf823512f75d692126a00b34133a690d6200b9fc1f9b79a0be5f57c498a7ec9e8767f8a54d5d04217dde594518461f68a729ea7257a7dfb7a0c2da0b1d829ad545428be39b156f7197c6e71239dccb76d4735bc71a7f16b29ba062ba1308c219c00a3a6ee09da622c53e587b46f802ff464c8c946c43fa05102980";
        nodes[4] = hex"f90211a0838e6ab6af8881e351432aaad656408c019d91aaa8ffe245eb98e32ebf2a765ca041c04329679a7cfd593af2a8caeb9b8aa0091d8f67e6519c6a683ada74114eb2a0e143d88cee4966167243801cbea359b6331b69d7919913a15b7297a38ec0ea3ea0fc5f51776daf9db39aef5d1dcec3c5c680d7fc38503c30e3c0a9208740ddcf5ba0ae61e61111a438fd111eab6db6811634cb9d2733e7fec4927ffa9e6e9d578abfa0ac67534fad16838a25060c2889f80bbde0ab4ef97f8c86d6f96714020100b330a0ae338141e1be8ee859a8947267e2112355b4f0ef7bacd1300f41429d3df31c18a0ab8b0a1070a42453da152e81fe326922bbaccbe630b55d91ebc6798a0161458fa0408fed788d9dc4ad644e829bf920d7c9e8f7b9f687ecd49058ce02e7711679bfa00a2aa03a2ede6416f53abb00bedfc636d6bbfa5c64828c274beba5009af4780aa0a91768a9b23adc2f16ef7de79ae76e7661dfa547b4b3e6582dd3c16e358f2ba4a063007338e036c86c5ecee5bde8e4c08d2ce06b1603f74d8354d5c05f15e00feea0dc54a1cee9e5128d23cf9db4c49b975a60c52e1f516759cc2998554ef0e66cf7a09ea0775529afdcf0afdc0937066ed25aedbb5c6efbbd6e6394a5b95914fc8a5ba06e18581a16571a1c575c7310050b5637744a4ef51d4b1ca1d920f2124a4bccc2a0d28871e6722e43434b45d0b64e48885cc60758adf316eb7f1d4b5cd2eb37616f80";
        nodes[5] = hex"f90211a0ae461911752230ea57c3ee9f15a9ac3003b21c5208dc5c8eec6a4ed33ab48543a025c641d902319646a6100d437164ec2481ab0cc7bfea8ad44a7c89a46aeb42b4a019ec6ae2d7dcb844c071a1f3353c1b16d26277c275e05940b40263e49d1b0221a081df9d31ae051c1496f6be50a8bf0329719789748e66c9195d754dd21ee4dd03a0a5956ac6d4f04bdf816e78df527415631aead08aa8b2adb584c0cb5dbbfec22da01a7c5bb3ff6afdcfcf736c488c1058b8dd82360c42917d16b3abdd58058750aba0d5ccdc89778f710bfb944a1b4de705e8f822e3e09125494fec9ac3e64ac271f8a09d2d5e0f523b15145b7ecd71a450c77537e481b9983542ff4db726a88d08664aa01d41233512423c9bd9c11f90a7d993d9f6541a6e721a5586b6496a30b9b2fc7fa0dffca34dd0447c74102c6d8bf20d54471f69067cae880528973a67c96937fa46a01bf06e368a453da103a278dac5fd45e276a0a20f9f0d6002c3ef9c362cf55bd0a0ef515ba44ebe2c2b37c981e7b2ac4f93936750948155216a56dd0ca433862a79a0d1e0a00d71b956f6d3d84d718fe14d044d073b183707a3fef9c638b48f4cdffda07dac049227bd6a4bae4b4032a0e4b5198152c84061bc0a18f7550ba81ba1282ca0c46b4c8cff4baf32ddcf3d607b8e3d5019593f367d859418ae6fce1093002e04a08f4b1ece466dcf09c1ab00f336aec03c36dca920a483f3c378e283675c89a13180";
        nodes[6] = hex"f901b1a05061d000c2a2f1f5fd018a1dc465c1afd087c2b010d2a68629a8d5467e58666da03f98e9ce6af172ec08481a6bcffb89a264933f90ee288a82144c0eab968e42ffa00fb582920a2d3ecba2d56df62fe8e8000dadddf48b388d24634b652954d687a68080a0c9015959346af2881b4e3fe38f673105acbe25ba4472a514954311e545ffa5e0a0b7ac5434d71571fe4266508ba452377e0d629ef1a96913f298ba391c2dc32d50a02f5c33d3378a8e36caf8f8a70a726f4a0fa817a1d36935df69605b77e7d45d5ca091e8c2c9aa6b25b19d0a7131aac1895da72419e9f88ec47d05b1d13ab37fbabba0b5d6ae1c2e3bf5ab5b4aa2f3e8d6fbd0a8aa2066147d2ed9c1960a37e1391543a04858e149a5a2072ea380b93d54f2e553abf02fb43e095da4f4a28ab57b747317a0b0d1bf84ef8e92470ebf5dd330a2269f0dcfe5ed0356e2e05954d63a9d35f1b3a0c329d67971ead7da9f1d222990d9aa6c0f448bd161c0981ef504b1d7292b666180a0804cc6a6f087cd13f92574e0d02b1db807aa5043e45891a06764918938c0a203a0b5d933002fb8f44d57f0a6aa57bc335341491f9e1c55202185a12bbda5103d2580";
        nodes[7] = hex"f87180a0568a3548f0c468bec66c6d91b1d72f84e44373c03c6e118d7edc6ba8fe9b4d0c80808080808080a0ec26e129a6fc11a5dcc748bd22ca4e41a0ace63cbf1cb2de018e2b9585a06fc680a019f400381c08f9aa173dc9534ed63146d5882cd1c84072235b2241341bf191d08080808080";
        nodes[8] = hex"f8669d2092cd7f3f78137497df02f6ccb9badda93d9782e0f230c807ba728be0b846f8440180a026b73e61996eefbbfada25f2b90c1ed1345522c4d5d310189434ffffdaa6fac5a0d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505";
        proof = nodes;
    }

    function benchChecksum() internal pure returns (uint256 total) {
        bytes[] memory proof = benchProof();
        for (uint256 i = 0; i < proof.length; i++) {
            total += proof[i].length;
        }
        total += proof.length;
    }

    function verify() external pure returns (uint256) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(keccak256(hex"a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        StorageValue[] memory values = EthereumTrie.VerifyProof(
            bytes32(0x308f6853dc993c6a2bb2510f69bd63c4d3b6a61af3768b84173718b221ec1c02),
            benchProof(),
            keys
        );
        require(values.length == 1, "count");
        require(keccak256(values[0].value) == bytes32(0xe10e34bdd279b2de01c786b5de7857009bfb6e4e325cadfdfba2a70a7897a279), "value");
        return values[0].value.length + 1;
    }

    function baseline() external pure returns (uint256) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(keccak256(hex"a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        return benchChecksum() + keys[0].length;
    }
}
