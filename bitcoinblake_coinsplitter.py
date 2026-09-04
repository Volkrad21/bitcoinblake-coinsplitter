"""Construct a Bitcoin PSBT with a mandatory BIP-110-incompatible marker.

This program never handles private keys and never signs or broadcasts.
"""

from __future__ import annotations

import base64
import hashlib
import struct
from decimal import Decimal, InvalidOperation, ROUND_CEILING
from pathlib import Path


TOOL_NAME = "bitcoinblake-coinsplitter"
# Project-specific binary marker with no human-readable identifying text.
MARKER_HEX = (
    "8f3cc2e8b7a3a683ca9959fa0377fb7d0ea11548fb3e3084cb4fc3eeba2e4231"
    "6037bb27a17074849007bc61bfafc74a6dc23bf3bcf188a5f21a932dd7454b55"
    "f5f8f9143014550cffa4590e8fb7083cbc7925aea95ed85dfb33f5d21dca4104"
)
MARKER = bytes.fromhex(MARKER_HEX)

MAX_STANDARD_TX_WEIGHT = 400_000
CORE_DEFAULT_DUST_RATE_SAT_PER_KVB = 3_000
P2WPKH_WITNESS_WEIGHT = 111
SEQUENCE_RBF = 0xFFFFFFFD

if len(MARKER) != 96:
    raise RuntimeError("The chain-split marker must remain exactly 96 bytes.")


def compact_size(value: int) -> bytes:
    if value < 0:
        raise ValueError("CompactSize cannot encode a negative value.")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return b"\xff" + struct.pack("<Q", value)
    raise ValueError("CompactSize value is too large.")


def read_compact_size(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of transaction.")
    first = data[offset]
    offset += 1
    sizes = {0xFD: (2, "<H", 0xFD), 0xFE: (4, "<I", 0x10000), 0xFF: (8, "<Q", 0x100000000)}
    if first < 0xFD:
        return first, offset
    size, fmt, minimum = sizes[first]
    if offset + size > len(data):
        raise ValueError("Truncated CompactSize value.")
    value = struct.unpack_from(fmt, data, offset)[0]
    if value < minimum:
        raise ValueError("Non-canonical CompactSize value.")
    return value, offset + size


def take(data: bytes, offset: int, size: int, label: str) -> tuple[bytes, int]:
    end = offset + size
    if size < 0 or end > len(data):
        raise ValueError(f"Transaction ends inside {label}.")
    return data[offset:end], end


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def serialize_output(amount: int, script: bytes) -> bytes:
    if not 0 <= amount <= 21_000_000 * 100_000_000:
        raise ValueError("Output amount is outside Bitcoin's money range.")
    return struct.pack("<Q", amount) + compact_size(len(script)) + script


def parse_transaction(raw_hex: str) -> dict:
    try:
        data = bytes.fromhex("".join(raw_hex.split()))
    except ValueError as exc:
        raise ValueError("Parent transaction is not valid hexadecimal.") from exc
    if len(data) < 10:
        raise ValueError("Parent transaction is too short.")

    offset = 0
    version_bytes, offset = take(data, offset, 4, "version")
    version = struct.unpack("<I", version_bytes)[0]
    segwit = data[offset:offset + 2] == b"\x00\x01"
    if segwit:
        offset += 2

    input_count_start = offset
    input_count, offset = read_compact_size(data, offset)
    if input_count == 0:
        raise ValueError("Parent transaction has no inputs.")
    base = bytearray(version_bytes + data[input_count_start:offset])

    inputs = []
    for _ in range(input_count):
        start = offset
        txid_le, offset = take(data, offset, 32, "input txid")
        vout_bytes, offset = take(data, offset, 4, "input vout")
        script_length, offset = read_compact_size(data, offset)
        _, offset = take(data, offset, script_length, "scriptSig")
        _, offset = take(data, offset, 4, "sequence")
        base.extend(data[start:offset])
        inputs.append({"txid": txid_le[::-1].hex(), "vout": struct.unpack("<I", vout_bytes)[0]})

    output_count_start = offset
    output_count, offset = read_compact_size(data, offset)
    base.extend(data[output_count_start:offset])
    outputs = []
    for _ in range(output_count):
        start = offset
        amount_bytes, offset = take(data, offset, 8, "output amount")
        script_length, offset = read_compact_size(data, offset)
        script, offset = take(data, offset, script_length, "scriptPubKey")
        base.extend(data[start:offset])
        outputs.append({"amount": struct.unpack("<Q", amount_bytes)[0], "script": script})

    if segwit:
        for _ in range(input_count):
            item_count, offset = read_compact_size(data, offset)
            for _ in range(item_count):
                item_length, offset = read_compact_size(data, offset)
                _, offset = take(data, offset, item_length, "witness item")

    locktime, offset = take(data, offset, 4, "locktime")
    base.extend(locktime)
    if offset != len(data):
        raise ValueError("Unexpected bytes remain after parent transaction.")

    return {
        "raw": data,
        "version": version,
        "segwit": segwit,
        "inputs": inputs,
        "outputs": outputs,
        "txid": double_sha256(bytes(base))[::-1].hex(),
    }


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def convert_bits(data: list[int], from_bits: int, to_bits: int, pad: bool) -> list[int]:
    accumulator = 0
    bits = 0
    result = []
    max_value = (1 << to_bits) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise ValueError("Invalid Bech32 data value.")
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            result.append((accumulator >> bits) & max_value)
    if pad and bits:
        result.append((accumulator << (to_bits - bits)) & max_value)
    elif not pad and (bits >= from_bits or ((accumulator << (to_bits - bits)) & max_value)):
        raise ValueError("Invalid Bech32 padding.")
    return result


def decode_standard_segwit_address(address: str) -> tuple[str, int, bytes]:
    address = address.strip()
    if not 8 <= len(address) <= 90:
        raise ValueError("Bech32 address length is invalid.")
    if address.lower() != address and address.upper() != address:
        raise ValueError("Bech32 address contains mixed case.")
    address = address.lower()
    separator = address.rfind("1")
    if separator < 1 or separator + 7 > len(address):
        raise ValueError("Bech32 separator or checksum is invalid.")
    hrp = address[:separator]
    if hrp not in {"bc", "tb", "bcrt"}:
        raise ValueError("Only Bitcoin mainnet, testnet/testnet4, and regtest are supported.")
    try:
        values = [BECH32_CHARSET.index(char) for char in address[separator + 1:]]
    except ValueError as exc:
        raise ValueError("Address contains an invalid Bech32 character.") from exc
    checksum = bech32_polymod([ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp] + values)
    encoding = "bech32" if checksum == 1 else "bech32m" if checksum == 0x2BC830A3 else None
    if encoding is None:
        raise ValueError("Bech32 checksum is invalid.")
    payload = values[:-6]
    if not payload:
        raise ValueError("Witness version is missing.")
    version = payload[0]
    program = bytes(convert_bits(payload[1:], 5, 8, False))
    allowed = {(0, 20, "bech32"), (0, 32, "bech32"), (1, 32, "bech32m")}
    if (version, len(program), encoding) not in allowed:
        raise ValueError("Destination must be standard P2WPKH, P2WSH, or P2TR.")
    return hrp, version, program


def address_to_scriptpubkey(address: str) -> tuple[bytes, str]:
    hrp, version, program = decode_standard_segwit_address(address)
    opcode = b"\x00" if version == 0 else bytes([0x50 + version])
    return opcode + bytes([len(program)]) + program, hrp


def make_split_marker_script() -> bytes:
    # 96 bytes requires OP_PUSHDATA1. Total script size: 1 + 2 + 96 = 99.
    script = b"\x6a\x4c" + bytes([len(MARKER)]) + MARKER
    if len(script) != 99:
        raise RuntimeError("Unexpected chain-split marker script size.")
    return script


def build_unsigned_transaction(parent_txid: str, vout: int, outputs: list[tuple[int, bytes]]) -> bytes:
    if len(parent_txid) != 64:
        raise ValueError("Parent TXID must contain 32 bytes.")
    transaction = bytearray(struct.pack("<I", 2))
    transaction.extend(compact_size(1))
    transaction.extend(bytes.fromhex(parent_txid)[::-1])
    transaction.extend(struct.pack("<I", vout))
    transaction.extend(b"\x00")
    transaction.extend(struct.pack("<I", SEQUENCE_RBF))
    transaction.extend(compact_size(len(outputs)))
    for amount, script in outputs:
        transaction.extend(serialize_output(amount, script))
    transaction.extend(struct.pack("<I", 0))
    return bytes(transaction)


def signed_p2wpkh_vsize(unsigned_transaction: bytes) -> tuple[int, int]:
    weight = len(unsigned_transaction) * 4 + P2WPKH_WITNESS_WEIGHT
    return weight, (weight + 3) // 4


def fee_for_rate(fee_rate: Decimal, vsize: int) -> int:
    return int((fee_rate * Decimal(vsize)).to_integral_value(rounding=ROUND_CEILING))


def dust_threshold(script: bytes, rate_sat_per_kvb: int = CORE_DEFAULT_DUST_RATE_SAT_PER_KVB) -> int:
    # Core estimates a witness output's future spending input as 67 vbytes.
    return ((len(serialize_output(0, script)) + 67) * rate_sat_per_kvb) // 1_000


def create_psbt(unsigned_transaction: bytes, input_amount: int, input_script: bytes, output_count: int) -> bytes:
    psbt = bytearray(b"psbt\xff")
    psbt.extend(b"\x01\x00")
    psbt.extend(compact_size(len(unsigned_transaction)))
    psbt.extend(unsigned_transaction)
    psbt.extend(b"\x00")
    witness_utxo = serialize_output(input_amount, input_script)
    psbt.extend(b"\x01\x01")
    psbt.extend(compact_size(len(witness_utxo)))
    psbt.extend(witness_utxo)
    psbt.extend(b"\x00")
    psbt.extend(b"\x00" * output_count)
    return bytes(psbt)


def ask_yes_no(prompt: str) -> bool:
    return input(prompt).strip().lower() in {"y", "yes"}


def main() -> None:
    print(f"\n{'=' * 72}\n{TOOL_NAME}\n{'=' * 72}")
    print("\nEXPERIMENTAL: constructs an unsigned PSBT; never signs or broadcasts.")
    print("The mandatory 96-byte OP_RETURN is intended to violate BIP-110's")
    print("83-byte OP_RETURN script limit. Verify both chains before use.\n")

    parent = parse_transaction(input("Paste the complete raw parent transaction:\n> ").strip())
    print(f"\nParent TXID: {parent['txid']}")
    vout = int(input("Output to split (vout):\n> ").strip())
    if not 0 <= vout < len(parent["outputs"]):
        raise ValueError("Selected vout does not exist.")
    utxo = parent["outputs"][vout]
    if len(utxo["script"]) != 22 or not utxo["script"].startswith(b"\x00\x14"):
        raise ValueError("This version supports only native P2WPKH inputs.")

    destination = input("Fresh Bitcoin destination address (never reuse the source address):\n> ").strip()
    destination_script, network = address_to_scriptpubkey(destination)
    marker_script = make_split_marker_script()

    try:
        fee_rate = Decimal(input("Fee rate in sat/vB:\n> ").strip())
    except InvalidOperation as exc:
        raise ValueError("Fee rate is not a valid decimal number.") from exc
    if fee_rate < Decimal("0.1"):
        raise ValueError("Fee rate is below Bitcoin Core 30/31's default 0.1 sat/vB minimum.")
    warnings = []
    if fee_rate < 1:
        warnings.append("Fee rate is below 1 sat/vB; propagation through older or busy nodes may be limited.")
    if fee_rate > 10:
        warnings.append("Fee rate is unusually high; confirm the units carefully.")

    template = build_unsigned_transaction(parent["txid"], vout, [(0, destination_script), (0, marker_script)])
    weight, vsize = signed_p2wpkh_vsize(template)
    if weight > MAX_STANDARD_TX_WEIGHT:
        raise ValueError("Transaction exceeds the standard transaction weight limit.")
    fee = fee_for_rate(fee_rate, vsize)
    destination_amount = utxo["amount"] - fee
    minimum = dust_threshold(destination_script)
    if destination_amount < minimum:
        raise ValueError(f"Destination output would be below the Core-default dust threshold ({minimum} sats).")
    if fee * 20 > utxo["amount"]:
        warnings.append("The fee exceeds 5% of the selected input.")

    unsigned_transaction = build_unsigned_transaction(
        parent["txid"], vout, [(destination_amount, destination_script), (0, marker_script)]
    )
    psbt = create_psbt(unsigned_transaction, utxo["amount"], utxo["script"], 2)

    print(f"\n{'=' * 72}\nREVIEW BEFORE WRITING FILES\n{'=' * 72}")
    print(f"Network HRP:          {network}")
    print(f"Input:                {parent['txid']}:{vout}")
    print(f"Input amount:         {utxo['amount']} sats")
    print(f"Destination:          {destination}")
    print(f"Destination amount:   {destination_amount} sats")
    print(f"Fee:                  {fee} sats ({fee_rate} sat/vB requested)")
    print(f"Estimated signed size:{vsize:>8} vB")
    print(f"Marker bytes:         {len(MARKER)}")
    print(f"Marker script bytes:  {len(marker_script)}")
    print(f"Marker (hex):         {MARKER_HEX}")
    print("RBF:                  enabled (sequence 0xfffffffd)")
    for warning in warnings:
        print(f"WARNING: {warning}")
    print("WARNING: Confirm actual Bitcoin and Bitcoin Blake rules at broadcast time.")
    print("WARNING: Do not spend the other chain's coins until the split is confirmed.")

    if input("\nType SPLIT to create the unsigned files:\n> ").strip() != "SPLIT":
        print("Cancelled; no files written.")
        return

    Path("unsigned_transaction.txt").write_text(unsigned_transaction.hex(), encoding="ascii")
    Path("transaction.psbt").write_bytes(psbt)
    Path("transaction_psbt_base64.txt").write_text(base64.b64encode(psbt).decode("ascii"), encoding="ascii")
    print("\nCreated unsigned_transaction.txt, transaction.psbt, and transaction_psbt_base64.txt")
    print("Inspect the PSBT in a trusted signer. After signing, run testmempoolaccept on Bitcoin.")


if __name__ == "__main__":
    main()
