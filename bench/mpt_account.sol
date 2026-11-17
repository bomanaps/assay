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
        nodes[0] = hex"f90211a08cbd688c6cfa0dcb778b54113c19417799ab1e94c14d6661dc5baf2622f8dee6a05572ceb42982f7b2f3c40c6de71e97b88329797a7b9d85dbfce22fe47bec7e40a082b874f6bd7e3bca4f2f5e57e0143c167cb462a184796c416ec679af7c97e04ba0c5dcc89b8295c6548f4819d1f9e9f47a72dd63dbff329e62e5bc9b2beb3b09fda09a6599c1daecda189b9b2b1aedb29896266e453c840f829c61ac9f35c04fa885a0a6d07c84f752f540a44dae74cf37acbf4977ef453ac71915fb6b650f3b5b3908a0e95f3ac3423b372b23f16b0d727f9f016d51bc78f6c5fc7b47ffe11e929f55d9a0a543f289f23510802c7b474d10e14ee1183ba83b24d5bf077d7fb8c4959d088ba02decd3ba3855ad95f72cde9e6fea06a31ac45be4b2cc7ded5226831734c9f487a097b34c9c8f4f230aa42272240bb4d0e233f4be485665e89722e1293750d73f26a0ba561e5fbfe5536866a8d61648bdf8c66935579c88ad57b6c93b11d28676e284a03e1f577e93100aeae3783960af351a4ff9e9b2e4d66983390eb64118b0571165a0fa8072f146e00279cf00fc001e557e69282f94f709b5c662e34e168a84f1f93ea0a55eebeae203db2d1aca9e3cc5559b01a16f2e043796e45060a9ea56044f9483a027c7367b684741626bda4ff53e0c51d48801f1d9d6ddc407c7a3d87e57e1e491a070c5d821ffb4ba32ed81e8701a16b16e04487defd4366e5049185591ef4a83b180";
        nodes[1] = hex"f90211a001fe8ffe20e38ad1ffdc3ad423e8a404b9f78bc693212206d1b5ffef41ad0704a042b8cf691655ced6dd27e7293533ace3af2b93108619af9666b446870b2e3cafa059d7fe895b24bd373853b0da450e5d7126b4ae14aed15be8620a0ff404f93843a0452d8a138bf4d88a922af94b4de371b67d5cc72c9f7d99e500abe53b9bf38b1ba04bec508ece0fba9e9d6869bbcb29f125c8ed621de5716c78b4fbdb5a63236c26a00a0d3ca9ac348a30f9f8b0a0bc707ff9803ef24de5a94d11a51f5f8cd292f489a0471e6dcf5d0ec4fce6e3e22aeabd19dc72e6cff4423bb5c9ba8d685d583a0adaa0836ce38e7505230845b0eb359181148168535c098f48c8161e6f6b1b76a899c7a0a7fe9385b94a799df92236db0468e0d4f03e09671e468cc113810d886608afaea0cdca479798db2782129c5d948f33de5e60fbb93d0f36f924db5a66f1b1b7eb47a01fdc2cc7ef975eb7c2d0a6beeec08facf91aa0c5e6ae74efc39aef73d052e9eaa0e0c6241de4b8f30c268cf7cb45a544903ee19ac00a948d59e6ea2083ae087d00a09741fd27dc3f409130e7d1adb93157d5205ace7f66a0dbdd927af86565080fe4a058990e91ebbcbac526549332b89d7d970cc04165cd01a2632442e3da2dee0d0ca06b82ae8dbe7681f924ee2b7f0e716484acdeab5e7b7d91d441c4ccd47c4779c4a009ab13075e1bb1b880cdba45d99999d15cc9b652c072b28b59939cb23a467f5780";
        nodes[2] = hex"f90211a05020965921413bfacd5c9c1e91d45d5734bd70fe5aa7f01ff4c9a3ab3c1097d8a0da2c014ca186a81d44cad04335b1056a32cd1ec5b45c177d06b7693db24256b7a0e184055048f35b15db56a14f3305b69128641f4dd0ba32d4aa09f1b8bf0620c9a05eb6bfceebeb98b8b5c9b7f57f041671405342faa492d4838573d592df1d8751a0737306544029469806e7b5e78d37d526e382615d9c7d211bf6d553275b3e2ed0a032d0ca9780eb1b1c70467b8b4de676762917d5aa75108c7bbf10dee938f87a88a0af76185fe279ccb541ec4c40043fae5dbaca6cac5af6279c68c97f092c1b0b87a06fdb801c0dbe29854595c01c7ed0df89335766fd88c02a6546e1f9b64d119ec9a0b10f994bc0e60868f0537e87e91e65f32932ba96e9c34332ef96281b2392e239a0b79771298fd7b138e06a8726fe01a26b3012974700edb9aea8410a61e356df38a09821193ec8f8c82692627f6803b7f4040215320c46ee07b89f75596a1991e9fda0d53d30f0512ea92c3f3095403dc12ac11b3826b5d22c3ed64dd0df40451a2159a008bd8911019e976ad969ac5374701721d18d224457ae4a523d694103bb80601ea09ecb41301bf6704f2dbd37eef9b713ba86fc5a108e028ebcdcb9082203cc734ca0ff36d4201c6d89793b9953e7606e7aa32c4e46e740aecb1674d5bbb5b1daa8a5a0f044bdb56314161aa7dbe3dc605bb417ca36f910a93d3bcc59e6fda8ce55130d80";
        nodes[3] = hex"f90211a059e65c6cfa45213e05a2d3584ee2dabbcf5c3dc87e2fcf962422c6b6b6367bb3a098bd46614d03476684e337153e5930811b67be14acb0e0faca3e03ac8c507784a00ce28305c378ef00b82f7317edadea37fea9e4abffcc3e908feafc11294d1ae5a02d575de652be19613ea3d11263c2e893d48baed86f81d1d2ab3e65fe77ebfed5a09d84a003570ab1fa25f0c9622025f14879190d5505b40f2ff5a650703caa2f5da074bafd06cb1780878611004e57016aa6853d6ea73b1ef53d2b4632e871584c3ba07d357871eeaa3a517f7f3efca790669b290b7b30bec4bf5acd809fc173e19b88a00f162463e8d14d08456e87ee6fae5f2a62ad9c2ed39de38168f11032a0040b45a01aca32879801f9d69395ef0d0fc436484d88a2c8f3788eeb21ab50f025762b8da0be501637cc0a56c7da773ce2ac5768be6309b2b328b72803fdcc6883b5db13b2a0b48ca814124ec385a55d2a0b84f008e792e835c2656e6f6604bd208f48bee161a09f62422361b50696e951fffcc95361df3841d7ae8d1f12b8fba61dc574a1d2efa09d527e6ce7f935f6eca70c3dfd009d1705d90c1767eca524972a1375c0c4ebd2a0f02bee93fb1ba559cfcb89c28be0f1520ca16c3e90e656936d6f51ebb97acb16a0b0bc3633012b9b75e261ace59ab7a5688d0e4556250d1555402dfad5cb69de54a05c4dfc8dc5e178c4d96c0ecc023943cecc759ca2241d53b36865ec1dacb2601c80";
        nodes[4] = hex"f90211a0838e6ab6af8881e351432aaad656408c019d91aaa8ffe245eb98e32ebf2a765ca041c04329679a7cfd593af2a8caeb9b8aa0091d8f67e6519c6a683ada74114eb2a0ebed1204729c84dfa12e0bcbda0c2b379daf22796d27bdca2cff002395a4e00da0fc5f51776daf9db39aef5d1dcec3c5c680d7fc38503c30e3c0a9208740ddcf5ba0ae61e61111a438fd111eab6db6811634cb9d2733e7fec4927ffa9e6e9d578abfa0884e66fbac8a6e7db263d1f6530cd20dcb896f386b618ee86610d7da7f8922d0a03a2ffb16deaeee6a486f86009ea062dd49f561a35723aa3d0aca5ee3c5436ba5a0bc5d43cf60f4afa793d9fba980528983bd3f1c4c5523ff21f0f0b85c76a465d9a0408fed788d9dc4ad644e829bf920d7c9e8f7b9f687ecd49058ce02e7711679bfa00a2aa03a2ede6416f53abb00bedfc636d6bbfa5c64828c274beba5009af4780aa0fd15fd27a62bd23b91ed921027b72e4b00ecdb0375185f4a227779d0d05edde9a063007338e036c86c5ecee5bde8e4c08d2ce06b1603f74d8354d5c05f15e00feea0b789363872ffd294079b52df97ea01d6b2a63f44fe0b55bc3c02552ce85f98a5a0d264564736575f64c67b7cd236fd4e0a495a79a9e7adf485dfcc1bf5b2514a77a05b19c39b01bad21467b692377502cd909767af800ea1807c2015a72d1b1be289a0d28871e6722e43434b45d0b64e48885cc60758adf316eb7f1d4b5cd2eb37616f80";
        nodes[5] = hex"f90211a0ae461911752230ea57c3ee9f15a9ac3003b21c5208dc5c8eec6a4ed33ab48543a00d21dc62030b53a31fabf541ab7544648ce70a20dbc40d38e2e5647528b782fba019ec6ae2d7dcb844c071a1f3353c1b16d26277c275e05940b40263e49d1b0221a081df9d31ae051c1496f6be50a8bf0329719789748e66c9195d754dd21ee4dd03a0a5956ac6d4f04bdf816e78df527415631aead08aa8b2adb584c0cb5dbbfec22da03d907f1b3fc8d60957b8603abac995dfc38eb2cb8a9d8ea99d98eabe00c61ae6a0d5ccdc89778f710bfb944a1b4de705e8f822e3e09125494fec9ac3e64ac271f8a09d2d5e0f523b15145b7ecd71a450c77537e481b9983542ff4db726a88d08664aa01d41233512423c9bd9c11f90a7d993d9f6541a6e721a5586b6496a30b9b2fc7fa0dffca34dd0447c74102c6d8bf20d54471f69067cae880528973a67c96937fa46a01bf06e368a453da103a278dac5fd45e276a0a20f9f0d6002c3ef9c362cf55bd0a0ef515ba44ebe2c2b37c981e7b2ac4f93936750948155216a56dd0ca433862a79a0d1e0a00d71b956f6d3d84d718fe14d044d073b183707a3fef9c638b48f4cdffda07dac049227bd6a4bae4b4032a0e4b5198152c84061bc0a18f7550ba81ba1282ca0c46b4c8cff4baf32ddcf3d607b8e3d5019593f367d859418ae6fce1093002e04a08f4b1ece466dcf09c1ab00f336aec03c36dca920a483f3c378e283675c89a13180";
        nodes[6] = hex"f901b1a05061d000c2a2f1f5fd018a1dc465c1afd087c2b010d2a68629a8d5467e58666da03f98e9ce6af172ec08481a6bcffb89a264933f90ee288a82144c0eab968e42ffa00fb582920a2d3ecba2d56df62fe8e8000dadddf48b388d24634b652954d687a68080a0c9015959346af2881b4e3fe38f673105acbe25ba4472a514954311e545ffa5e0a0b7ac5434d71571fe4266508ba452377e0d629ef1a96913f298ba391c2dc32d50a02f5c33d3378a8e36caf8f8a70a726f4a0fa817a1d36935df69605b77e7d45d5ca091e8c2c9aa6b25b19d0a7131aac1895da72419e9f88ec47d05b1d13ab37fbabba0b5d6ae1c2e3bf5ab5b4aa2f3e8d6fbd0a8aa2066147d2ed9c1960a37e1391543a04858e149a5a2072ea380b93d54f2e553abf02fb43e095da4f4a28ab57b747317a030ac5df8674b6215bd8e2308ffc351153a3aa0e7e3473b3be1fb4925712069aaa0c329d67971ead7da9f1d222990d9aa6c0f448bd161c0981ef504b1d7292b666180a0804cc6a6f087cd13f92574e0d02b1db807aa5043e45891a06764918938c0a203a0b5d933002fb8f44d57f0a6aa57bc335341491f9e1c55202185a12bbda5103d2580";
        nodes[7] = hex"f87180a0568a3548f0c468bec66c6d91b1d72f84e44373c03c6e118d7edc6ba8fe9b4d0c80808080808080a0ec26e129a6fc11a5dcc748bd22ca4e41a0ace63cbf1cb2de018e2b9585a06fc680a00508c282d942fd5e48619d4a5850fc19fb8b81271f5bf709d831c53e71658d638080808080";
        nodes[8] = hex"f8669d2092cd7f3f78137497df02f6ccb9badda93d9782e0f230c807ba728be0b846f8440180a0a8487dceb7103428eaf28c3fbb363a67c53a9216aa0a1ad8c591d293449237c5a0d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505";
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
            bytes32(0xbaf378b9cb94e38ca206f463940157354e5c9306175d6eb0376c44fa7150a8e7),
            benchProof(),
            keys
        );
        require(values.length == 1, "count");
        require(keccak256(values[0].value) == bytes32(0x64810104de4b7bdb87a94534a0e93780faab1a5b68e799ca1fda7ee8993d631b), "value");
        return values[0].value.length + 1;
    }

    function baseline() external pure returns (uint256) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(keccak256(hex"a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        return benchChecksum() + keys[0].length;
    }
}
