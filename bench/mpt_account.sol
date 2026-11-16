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
        nodes[0] = hex"f90211a0565a5df8e1e154385ad62a31c1ada1fb520dafc6cd36e92c681d7ecaf134416ea04adf6d49de5a33e6c6474dd7e389e3094e810248d776dd2fbf4f386a775174c3a07ea77ae00e61ff6be3b39ef32fbc12e965c5d5b15f9c897c8b997e1e519aa67ca0e4976e1f8f445fd148eeca9b49b2382b278dba1887b92740c1cbbe7cdbe0278ca0a494ac8391a38306a019bce83753ab2dfdaea7c9006aae3f3f0aeb0fd4d39165a041e7d03a250b82ccbe69320eb3db42317588ad3ba591fdfcba9408c21c6828fba067501dde3ed0019fb0ced4c91df5022641ac5c6b4a4d35d56e430a7e2e96549da09ff41be6b465ba503c1ae9a7ca9606a518542da384586756834eb6b43bcd2005a022797bbdeebeb83f513170531c1ac715e6c3152494aa3202adcca66a21fd0980a0f23d2a4456a611d6337c54d08c4f4c2e6c326763500188d3c2f5f3102ba81d8da0939c804fab188a113882d95e87c75c02ae2b080bdd9ffdd35af21af1eec095e7a0c021a873e7a60f0330d38cda0afeae0f4c747be1332203a7d5a6772feea23ce9a0d86cda423db2c5342eca34379b8e2a999227d399ed3bad5c2a52843ec9bdf5faa09b82e6242b4d339ab5e7121288871a88c15f888cd59f67a39e67733695cb627aa0bbde856925cc73adb678659c94f423b3e88c55fe3e58c69f9a8d036e5a859f8fa0e705aac16f4bfa684ca6ec39f5230f55d989915699c655ae92dbb69f9b31b6f680";
        nodes[1] = hex"f90211a0c46703dfc032cf8f2a1bf8ff91edb201c4a24f0ff6db1ef376670f903a05c2b1a0b8956a92b86beb6a273880bfa37846b440531d4412aa2ea3584b94f9243aaaf8a03361ca4583cc4020b1c93547d21e6bdc65950453e669174327152b0a45a5b6d7a0c0348c760a96cb3eafb486e318c62cb5acfc76f75fab3016fcdafaa2fc7eca2ba0fa24ef2affcd86664c27c368d96840563534bc5343811515255dc9b781f1a696a06993e4f809aeeff62000a7e98987408ec0c7407eb58df7989c38193b1ba2a1b5a01732e9ca649c55a0c0455e3687d8a422bd8d4fd1a382b55193410c3a2672eecfa04701ec3d0041f6c0c058c5833bb967b9a302d3ccbbb74f70910cfabbfa2f055da0615d19d3cc48dba4c5df75ff308045b4d42ce4f87bdcfc491f81326c7f780042a0ba5c796af477d56f294f879c59e3e194c82268ceb3ac37a3ed58e11e322126afa0fedc580b5e846db7e419d1de499c03d44cb62db2969832cbaa7b8e5ac1cadd98a006c6caeed18f9da2378f7183342ad226a5a28ea09ed51eb358ce29ac05bdad57a0eaea3f9eade6311893f3253127750f5b1843e5054a51476fb59802589f759e00a07c24a7c10a8162ddb7380dfd7618fea04b864aadb1399c6fa4e0ff875aeefbfba04288344d2469e538280cded8babbe44e9d09a9f8c834af3ec53994ab3b1d468ca0e749f24974d8f54a8a943f5de84333c85f98ac4fb4153054ef6976970decf20a80";
        nodes[2] = hex"f90211a0479eb113685bd03c8404efdaa3abb6a6bd4a40eddb36691a016d70c5b54c305aa0c6d77c50fb8853ed91aae741a696749d5347ebee9562b2bfc4e08c5cf7b04727a06cafefb8bf72c57757b467d336ae060b845459cf32078c0a5e3cf7ea6044277ca06d726b9c46b7e05e21670f0acccabb356dfc72244a4a6d131e814b355f19860ba0f0c4b51a46990e8921b87f7a36540d72f9e6caa7d7ee32ba04fd333c1a26f0fba0ce1761e635b542845d171359e661a0509fe48316d9a9e79adf04acf92fdedff5a03bd9a5cdb36e6297986da396e461740da977a914b479ad9c3d6d480b1bb59ea6a05689eac2fa44d7e3bf6bb74539895114f11edb5a65927d0bd49a3325cb70ab34a0e5ea97bec760a0617a9656cee92ea6a2f6a1fc08ddf3f56f89bc064317423874a0466b20e6623da6104be0d746a18a20cdbfb239073c8114af78e778dc554e9484a0c8d3315e16ddbf458f9056fc10bddaa5c5ebaf2063a1955f0de9d7d86abb463aa0f14cf9c794f80640c20c7364cd29cd3b79f04a31a5a7d39031292a1ea3f4b75ea037c2a962110b7cd430cc075934d4e38201e39fc806fee5329be6af3724d09410a09e9ab1b94d7076d9e12f698e70c52448fec4a76edcb508b079c457b5082d60d8a09ab7ddb0a5673c838d63670cbabcb7ad1f04d3a099848b125182184554db48e4a0ca1f8db91365a647386ea19ecb153d30acb928a014c1136567c987e7a1193cd780";
        nodes[3] = hex"f90211a07f5c9a0919e5ad0269ca12423e630759465f57a5d1bb7c9dee07bc0a3b415611a088df6301980036f41927670a617921be2edd9c091b14a9b02b14f7d1763247ada062151f7f3125179581d3e224da6e1e51425c72bb53046718df4e6603083e713ea0902f0e93923e0ead752f7f3caf0ff41694a9ef864acf862e26f5cca8c2b39103a0d853e6b62ff0cb86f890aaa9d92592e2cc78e43c982423696c97f325129627d5a09dac1987e022b8813d1e57667bcc6e2028e8055c1e995b9775409e7bfa9f68afa08121a4a58c56ecd873cf3ea24cfeef1b9d80fe6e76d2a77c8af28117697c0c7aa0b1f6a637e650f4008487ec14aa11239b3c1d643f9661e4bdf9590e5289e6393fa0b62add5b60db5898c8ce92880abc0937aab9083d4dc452cd7a93bdcb6c288665a036a20ca1f023a34cd3dd85c7af83b84349f067ff0b3185ad1316611a25f0022ba0c1d8cbbb203817684213b24e0e81ba3dfdeddc8628852af3027ab4a48d195115a0e16efda5f55e2104ae0f1abfb5b86e259d07d3ef585c427240e8578a83816286a07ae5e2cdbbead211b57912e6722aff2b0961f1075486e7ee08ced7cedd222ba8a0485feb85ee9d7eb8a7646a3d10c10051b9e45663d5df50c68b9b6fb052fe5160a0a85a048ae508fed3713abc3bc00deb19ca9a777085bd28beb9d9a0e866586dafa047fed5e00987364aa2350a919469571421702a534fce0cfca62670f466426a1e80";
        nodes[4] = hex"f90211a0e3d094f2c07f8aaecbf41b906913621d41c4d7df140d8efd565f02f8d767ee30a0f7ab5980c5d2d100cabaf4acf055372122f9af0370c5cf1d92bfdb0943118295a0c44fac4050607ec8b742b022787d185bd5fb6a99489dbcc171d33712f1bb68c9a0f87e2ce834799fee8d97e46ce92410a78a5dad558f144add3207f56bcdeb0be0a0b8f3292524b559e015118ad0e3a5152d95901243fada6f724d8d335983b5f01aa0536475e5b393cc97f12606a0cd4477ec91032e2f2b942ba30cb0648967695cfba042e3c2a6120380d950b9544f0b4cd5436166d167de5bf8183ac51567b445982fa0aa8a1e4e23bf8743a7c6763c93ed5a83dec07eff70a952d721937b84768b404fa0804721718b718d67f07de6d54423ba7f0f3c1f83bf43901206577cd034795186a078b070ca04c80e04362b4a7eeafbe9bc2004a9bc233f4bf4f95644cbcfb362c3a08620fc826c1283fde2868b45773e6044580aae10663855ca9ce0515d71e0f301a09067983caa2ecd1d3f4c26060c7454dad245b13a83e0e2dd99087a033c2b2325a0a25eee42f32dacc05c98137fedc5ecd721375761a766e3c52a640d5976133508a0162bf366a698dd191142d3272d05000e80d0d855c3ade122ccb9fc85a463f8e5a08b74dc1387a80afc334efdda3f1a112e0f577efe8c2f9cfb4364e5498e441a5ca0ff36498c8046cad7affe9e6dcfb60aadfb90f9be19f2b0f6d0b021031de1689c80";
        nodes[5] = hex"f90211a00a9852c3c11c553c18ffd5cd06a4637f70f5f96b6d47c8f13b6d5f70f8c7fae1a00d21dc62030b53a31fabf541ab7544648ce70a20dbc40d38e2e5647528b782fba06e6baa6bc115f6817c44f2fcca51419273c62f538b0723dfe346d77db300e700a088f7e96ad2308bd4c0179a2e59fd2f563b66c56d7ae67dc546c58387a53495daa0a5956ac6d4f04bdf816e78df527415631aead08aa8b2adb584c0cb5dbbfec22da0938ed706e465009cb9d893464d6a109829bed05d414fa78ef2691446f13a966da0d5ccdc89778f710bfb944a1b4de705e8f822e3e09125494fec9ac3e64ac271f8a09d2d5e0f523b15145b7ecd71a450c77537e481b9983542ff4db726a88d08664aa01d41233512423c9bd9c11f90a7d993d9f6541a6e721a5586b6496a30b9b2fc7fa0dffca34dd0447c74102c6d8bf20d54471f69067cae880528973a67c96937fa46a01bf06e368a453da103a278dac5fd45e276a0a20f9f0d6002c3ef9c362cf55bd0a0ef515ba44ebe2c2b37c981e7b2ac4f93936750948155216a56dd0ca433862a79a0d1e0a00d71b956f6d3d84d718fe14d044d073b183707a3fef9c638b48f4cdffda07dac049227bd6a4bae4b4032a0e4b5198152c84061bc0a18f7550ba81ba1282ca0c46b4c8cff4baf32ddcf3d607b8e3d5019593f367d859418ae6fce1093002e04a018a42f537ff2eade95000e34b0da8d34fed4d802ddb72e21121d2510232b004e80";
        nodes[6] = hex"f901b1a01cc70c879480631f86b95371e8ed3cb4a683b1444268eea2753b147fb9255517a03f98e9ce6af172ec08481a6bcffb89a264933f90ee288a82144c0eab968e42ffa00fb582920a2d3ecba2d56df62fe8e8000dadddf48b388d24634b652954d687a68080a0c9015959346af2881b4e3fe38f673105acbe25ba4472a514954311e545ffa5e0a0b7ac5434d71571fe4266508ba452377e0d629ef1a96913f298ba391c2dc32d50a02f5c33d3378a8e36caf8f8a70a726f4a0fa817a1d36935df69605b77e7d45d5ca0d36e8a2e15ed6a549ec8dc0c0e4bb7b827a4f9c70345e9aaeee5c720e4d0640aa0b5d6ae1c2e3bf5ab5b4aa2f3e8d6fbd0a8aa2066147d2ed9c1960a37e1391543a04858e149a5a2072ea380b93d54f2e553abf02fb43e095da4f4a28ab57b747317a0c86bda738884dc8983b03ba189e53a473419c282c28595ab0bfd2e1e55921e9aa0c329d67971ead7da9f1d222990d9aa6c0f448bd161c0981ef504b1d7292b666180a0804cc6a6f087cd13f92574e0d02b1db807aa5043e45891a06764918938c0a203a0b5d933002fb8f44d57f0a6aa57bc335341491f9e1c55202185a12bbda5103d2580";
        nodes[7] = hex"f87180a0568a3548f0c468bec66c6d91b1d72f84e44373c03c6e118d7edc6ba8fe9b4d0c80808080808080a0ec26e129a6fc11a5dcc748bd22ca4e41a0ace63cbf1cb2de018e2b9585a06fc680a0007e67d24204fae01f14c197bd91781f7df629973dd833a0ff3763c8508478878080808080";
        nodes[8] = hex"f8669d2092cd7f3f78137497df02f6ccb9badda93d9782e0f230c807ba728be0b846f8440180a009ce8ac83a38fa5d8bd302e273c53afaf3105c9a45e066feb85c29f538920eaaa0d80d4b7c890cb9d6a4893e6b52bc34b56b25335cb13716e0d1d31383e6b41505";
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
            bytes32(0x51502b02719e78d7daec6ec98b6ddea37da89578d0081aedca12263be6e2c312),
            benchProof(),
            keys
        );
        require(values.length == 1, "count");
        require(keccak256(values[0].value) == bytes32(0x8979cd10deb1d0d7a1d3757968e4ed8b67b0e65ceb8e33b54657c75c5e25892b), "value");
        return values[0].value.length + 1;
    }

    function baseline() external pure returns (uint256) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(keccak256(hex"a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"));
        return benchChecksum() + keys[0].length;
    }
}
