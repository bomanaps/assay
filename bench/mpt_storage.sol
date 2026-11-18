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
    uint256 internal constant NODE_COUNT = 7;

    function benchProof() internal pure returns (bytes[] memory proof) {
        bytes[] memory nodes = new bytes[](NODE_COUNT);
        nodes[0] = hex"f90211a0b8d9cfcc60f2481d18501049f23b8a4aa18f30d0f880e0c7d67ded6cad118c68a008c778f13e1323da3f0179aa2c5dcc33af7d6de331ea4ee623087262cdc11f15a0b0a728cd727046b9b5299abc62499b06cacabdae184a04dbb190eb739f03b834a0645a50b5d8537d82db19d7be597280c43c3b3733502b4240818de0f1da65269fa04677a16c185bf90674df3811e661a2746b7215fc89a7c9c4571244fffcb7a880a08e20b3870d4057ccc3558dc3a0f529953feddc5ed1667e641461de1ebe638f6ba0a50d4a465066887294208a040618974e7fb8d4374d6916677854e1c3969f49d1a0afb0bc3b36b50a6584aedebc2d414b97fef300f2496ffb977788a8ae34e1c19aa0bfbd34ab081bd3e83a921c852e1c40b8dbef858ea07ca040953b991b62c5f2fca085348040e6accfc078f30eb724c3467fe443ba35dbc1a77c4a02a43c9f4deeb5a0d0d6f68f287b823e9f8f6bb358d36adddad601059e200f5cf81c5a960e68f749a04022622e88e4a3bffc2c079582d12113d8b83eac84a15e35a6e19603a4170ee5a0f8a3a203e008f3fe05693e8cddd32566a3e7507965f0cca14230a5673bb4c90ba0fd5afdca0ac5c8c4ab430dbba60d29865c1c3d1103fccfd631f9ef4722e624f8a0382d7fb3b7506daa06a72614344735e39f96dcfb322f095b07dab014da806271a0844d47ed8fed1f9b06a96312afd1f3f598ab603a41b22ba46e66eea993e31ff580";
        nodes[1] = hex"f90211a02ca164328c8386db36d3dd76dacda69675a68cf6c67036c1c27ebec752b72d92a096d1bf8397045e947f57af4406f176e66893806a64fe8eeb65dbc49ad2c0c750a01d6cee17bb49e769bd953b81fae69f48e3adde12d7fd9eecc8e445978754e2cda0b1f424cb5653abd2d1e1ce995a5b8a52054ce3242097e55e5f60fb77cbe15411a0827eef0e85dce6435033af2be1ff0c27a4a4d7fa429c47a0b98810a40e44ebf8a0fa5e37dbb924392cb97c87bf65936e0f7934ca9ed045d7e2017728d1dbc75d8ca044aea524b393fe266e4fc345de19705e10c7bb7d82d688412b0596142bb8bcc0a0b65064bb699c2bc8c0eec51bc81317bd0bd423a31d78ccd5db74a005df17b8f4a01823d99cb176941fc46a8305a59b2669715dbaed53e47af818c6bf31fe3b36dca08baf6dec4ee36b5aaed6b3a4e5fdc2186f6c7e1c954dd97308c3002f550a12d8a016e7298ee334e3225292096726a465a0845dca9969db41cb6afb22f7b4cbd3f5a074d0b17ee766df1ba30ea31415e88f8618789b7948de2058021e5e0e9bd25e5ea03fde9151288d5dc62d272954b09191c4fa9c6abc05396fe7d8efd62f922bac5aa05c9808121b2717165799aa3eb1f15fd0dfde433fed2d040ac6823a7211e55125a02ce9094997808bcab7b4ca8b0dcb16aed46ecf24ab73ef9bbdd386d3325be5e3a0c0b4a999e856593a660aa31be9401adb6505626206363699aae05d86d62efed380";
        nodes[2] = hex"f90211a06e15fb14a17f27ae59cd2c33fac28500ec99d68c727e036c46cd95fcc583b51ba010f5221b5dfecd9380fdecf50749bcbae8015006433f8253388611d6fb2ec7f7a0a8f56940df78eaed6f1e18df6e3a46fc0f352573fa304c082cab839fcda0fdb7a0e3254e6fd3f1d6dedf64dee552f92db0344b5d1f662506a442f176ed29c75a98a0085fa2c54e8b7aa7ec7349cecaeb99f28cb5848c78d142f16b5daf7ca0bfff8fa0eccef0ac4c5ca66516ab38576abfabe75454984450090ccbebf56dfc2667715fa0271709147389451e05020d8ee88d42993905a5d1bc02ef02f98d17b3d7005743a03ecd6821fd9187f0bcc42c6abf258340ad93625838f8577ebb5cd6849cec5fd9a0ae87931b458f477f3f312d4206614a47f031e30793fb9d2dd995f73e2cbfdd38a09ab96a8cb980372e9de593eca0bd43b3e90cdceade3d8e3ad8881df8b9a5314da08b15094b9efc4d9ce30a920641a160737d09e6c0d24c038310da6112ef9e274fa0f9a93bf34778e5d843c8aa2e0f5ff5ebf67e46da5af65cd94828087f1f4f52cea0061fd7f40817f72964fa652cef1300985088ec9f7182e791f5de6ab6b8767685a035dd6e54f5f0b9726bff7e4a4c9a4c54907b0d25b1f7c20bd026b8098cfa8566a035b2b0c47d20f835fd93a5d5250462fe5415b70b237d8792908338ab447cc472a07e7c5ee8811cd97bd0f3eebc41f5f4fd9399afcf095b3a19c45febbe5106a30580";
        nodes[3] = hex"f90211a02d699cb57211ca22e08acfb2fdd80aa8edc1117f7438dc0534d301115c3b12aba0844dc4cf96a7138e061aab59f206c4c4d28b3589320a95a83d28877d95d3bbdea0abe63b48bf81c2e79436e36b0aebb9957937daa90e1a47d6aec68bb6294f9d24a0c7db366d4d85fe2e91f1a7e186231b07c57463d24c5cc6fd8df70b1d3c7fe924a0d0180a4ceb5fc58cb672542ed2211211b56856693161050fb06473bd233902daa0eef97af22b5028226a197f1d3eec184d78e6931f9e2a631ee5b5037f4c2cac3aa0faa13d53e412b19c52cb6d2d678700462ba3329b9353f2b61ded55899cc22a72a00eb7be7b6fdd0b0b1bca89408fbf898dee7548c3a5f794c38b96ff7ef8696514a01afe6dc886e9ad0e80c5ed08572e8fab9f62256af63b2275463ced6afbcc5d00a0909fdeb1264d6f2e76b47901aaec494a8d8d06512299cde3294890f2acdc1431a0e553867989a9fbf37f6434549d7968d6a193cf6342b362fc35d12487e4c5ee8ba083b6218864a12dbc8105798b884ed625bb056729bcd8af160527b037e0172122a0b52da7668df395238bb0ba69720f692dc94b64559db1ac3d6c3d9e33608706f2a085bb625375bc4e7ee9516299600cf890c9111cadd2467b7f6a7ecd6c8885b6c4a08f0f10f64b8a1b9aaf06d144756e1c5a81c45442f78d17534933231cf45d8059a0a2f866b0237072a309e1f5b7e513be8f0ede8b18126fae012d5932517fdb73ce80";
        nodes[4] = hex"f90211a0d045097ab06ef6a3ee9209f8fd24eaee567e605fcf96c4093145489f519b197fa026c38e13c75b44240d45314c81e730c8f3b3027c78ef88fb2471bfaffaa5546aa00789812259096a6bf564e90bda438fc096f509a95458662cb3f988f70467e335a0e754f498b222a780d8561fe6df5c6ad55785987594d3978a5c67a52aea67d0fea018549e67048784ce2707e691b87c7bf68afe6e094ccfbc1d747d8e4bdc1cb826a09c5fd8a3bf66cb85d432859666e95370f713ad9a4bf00ca24675387a90e1e080a012a41547bb55f95aa15dab6011532c4c9d83453e7492ce59e7036dd294eef287a0ef3b278ac10799550ef5a7434e242970c4cf1135485ff93b17c7c8534152d9f3a04ecdd3f54348af6d4d114f603b742631a8e8335c38a62f93a22b5623372c7ee7a00986446b4834f98c77174b8d69b388e1aae361b478537b26c5fb8b352bd949b3a0b6b3f4bcde8bbec4a1b1292a146b9897cd6df1ac2fac180f97639ff25b22efe5a0f9fc31f0e7f1fd6f3b1897c9c3c2507eda1035601b582fddf1c36403f059a238a07f28f9f634f61d28ec82cb70c56b264804a21e9c94dc657488652cd890d9fc1ca0bc354778ae54b8218ac8889c27bdb4725c2aec0397f92bf8af07f469216c59e0a0fb12c8e1d888884bf60656e7444bf9b6ef5f66ef4730aa6504ba5ca01e2518cda064e38326d06b0da085ee2767e17d936df9c48e9a3c0e3013db05ea5135039e7380";
        nodes[5] = hex"f8d1a04051c185c76297d0754e01c94a37286d61c5a5a6558b2e435a7aeaa2b0bb330d80a0dc3a75080ba3dd845460371d8f9f5dd87687818083351e46f5d77a4d59d5bf28808080a051e55005d844eaf99de8eed6680edfa6aaab6bdb91973d08171fd6df90d7b5d980a02138935ff30cefcdde3aa0ef58bfcf654341aa9ea36509a13207dd26b93acd36808080a0ac5007707c6f26dd2a3a19424132871f7ad21d2f0c0ae39dacc34ca7a3f36b68a04feccfd2cf7dfe272a0e33ee90f451a97ed4fc1e9bbbb5ea59d4447317a34d7f808080";
        nodes[6] = hex"f8419e20d9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563a1a0577261707065642045746865720000000000000000000000000000000000001a";
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
        keys[0] = abi.encodePacked(keccak256(hex"0000000000000000000000000000000000000000000000000000000000000000"));
        StorageValue[] memory values = EthereumTrie.VerifyProof(
            bytes32(0xc75902d12b8d8e5e4527dfe8e4c0835352faf9b69808d0549960f864f7a92879),
            benchProof(),
            keys
        );
        require(values.length == 1, "count");
        require(keccak256(values[0].value) == bytes32(0x13510057a2b881c77e1c9cddef8c7142f161eecb714b28fde6f1184fde105c92), "value");
        return values[0].value.length + 1;
    }

    function baseline() external pure returns (uint256) {
        bytes[] memory keys = new bytes[](1);
        keys[0] = abi.encodePacked(keccak256(hex"0000000000000000000000000000000000000000000000000000000000000000"));
        return benchChecksum() + keys[0].length;
    }
}
