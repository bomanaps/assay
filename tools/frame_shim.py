"""Assemble the EIP-8141 pay-frame shim around a FrameGate address.

usage:

    python3 -I tools/frame_shim.py <gate-address>

The shim is the target of a `pay` frame (VERIFY mode, flags APPROVE_PAYMENT).
It forwards the frame's calldata to the Fe FrameGate with STATICCALL, reverts
with the gate's own revert data when the proof fails, and executes
APPROVE(APPROVE_PAYMENT) when the gate accepts. It exists because Fe v26.6.0
cannot emit the APPROVE opcode (0xaa), which only exists in the EIP-8141
draft. Every byte of verification logic stays in Fe; the shim holds only the
call, the branch, and the one opcode the compiler cannot know about.

A call with empty calldata stops immediately so the shim can receive the
devnet funds it pays gas from. Inside a frame transaction an empty frame
would therefore exit without APPROVE, which the protocol treats as an
invalid pay frame; it approves nothing.

The GAS opcode is legal in the validation prefix only immediately before a
call, which is exactly how the shim uses it. The tool prints the runtime
code, the deployment initcode, and a byte-by-byte listing, and it verifies
its own output: jump targets must land on JUMPDEST, the APPROVE operands
must sit in the required stack order, and the assembled bytes must round
trip through the listing.
"""

import sys

APPROVE = 0xAA
APPROVE_PAYMENT = 0x01


def assemble(gate):
    if len(gate) != 20:
        raise SystemExit("error: the gate address must be 20 bytes")

    code = bytearray()
    listing = []

    def emit(data, note):
        listing.append((len(code), bytes(data), note))
        code.extend(data)

    emit([0x36], "CALLDATASIZE, zero when the shim is only receiving funds")
    fund_jump_at = len(code)
    emit([0x60, 0x00], "PUSH1 body, patched once the body offset is known")
    emit([0x57], "JUMPI, proof calldata continues below")
    emit([0x00], "STOP, accept a plain transfer")
    body = len(code)
    emit([0x5B], "JUMPDEST, start of the proof path")
    emit([0x36], "CALLDATASIZE")
    emit([0x5F], "PUSH0")
    emit([0x5F], "PUSH0")
    emit([0x37], "CALLDATACOPY, frame data to memory")
    emit([0x5F], "PUSH0, return size")
    emit([0x5F], "PUSH0, return offset")
    emit([0x36], "CALLDATASIZE, argument size")
    emit([0x5F], "PUSH0, argument offset")
    emit([0x73] + list(gate), "PUSH20 FrameGate")
    emit([0x5A], "GAS, legal in the prefix only directly before a call")
    emit([0xFA], "STATICCALL into the Fe verifier")
    approve_jump_at = len(code)
    emit([0x60, 0x00], "PUSH1 approve, patched once the approve offset is known")
    emit([0x57], "JUMPI on gate success")
    emit([0x3D], "RETURNDATASIZE")
    emit([0x5F], "PUSH0")
    emit([0x5F], "PUSH0")
    emit([0x3E], "RETURNDATACOPY, bubble the gate's revert data")
    emit([0x3D], "RETURNDATASIZE")
    emit([0x5F], "PUSH0")
    emit([0xFD], "REVERT with the gate's reason")
    approve = len(code)
    emit([0x5B], "JUMPDEST, the proof held")
    emit([0x60, APPROVE_PAYMENT], "PUSH1 APPROVE_PAYMENT scope")
    emit([0x5F], "PUSH0, return length")
    emit([0x5F], "PUSH0, return offset")
    emit([APPROVE], "APPROVE, the shim pays the transaction")

    if body > 0xFF or approve > 0xFF:
        raise SystemExit("error: jump targets no longer fit PUSH1")
    code[fund_jump_at + 1] = body
    code[approve_jump_at + 1] = approve
    listing = [
        (offset, bytes(code[offset : offset + len(data)]), note.split(",")[0] if "patched" in note else note)
        for offset, data, note in listing
    ]

    if code[body] != 0x5B or code[approve] != 0x5B:
        raise SystemExit("error: a jump target does not land on JUMPDEST")
    if bytes(code[approve:]) != bytes([0x5B, 0x60, APPROVE_PAYMENT, 0x5F, 0x5F, APPROVE]):
        raise SystemExit("error: the APPROVE tail is not scope, length, offset, APPROVE")
    rebuilt = b"".join(data for _, data, _ in listing)
    if rebuilt != bytes(code):
        raise SystemExit("error: the listing does not round trip to the code")
    return bytes(code), listing


def initcode(runtime):
    if len(runtime) > 0xFF:
        raise SystemExit("error: runtime no longer fits the PUSH1 initcode")
    return bytes([0x60, len(runtime), 0x80, 0x60, 0x09, 0x5F, 0x39, 0x5F, 0xF3]) + runtime


def main(argv):
    if len(argv) != 2:
        raise SystemExit(__doc__)
    text = argv[1].lower().removeprefix("0x")
    if len(text) != 40 or any(c not in "0123456789abcdef" for c in text):
        raise SystemExit("error: the gate address must be 20 hex bytes")
    gate = bytes.fromhex(text)

    runtime, listing = assemble(gate)
    print(f"runtime ({len(runtime)} bytes): 0x{runtime.hex()}")
    print(f"initcode: 0x{initcode(runtime).hex()}")
    print()
    for offset, data, note in listing:
        print(f"  {offset:3d}  {data.hex():<44} {note}")


if __name__ == "__main__":
    main(sys.argv)
