"""Structural validation of GGUF files, before the runtime parses them.

A crafted GGUF aimed at the loader is usually malformed somewhere: a count or length that runs past
the end of the file, sizes that overflow when multiplied, a tensor whose data lies outside the file
or on top of another tensor, a type the loader indexes a table with. This module parses the whole
header (metadata and tensor descriptors) with bounds on everything, and checks every tensor's
extent against the file, so a file that would only be well-formed to a lenient parser is refused at
intake rather than handed to llama-server.

It reads the header only; tensor data is not inspected (the manifest hashes it). Passing this check
does not make a file benign: a well-formed GGUF can still carry a hostile chat template or hit a
bug this check does not anticipate. That is what the sandbox is for.

Format: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import BinaryIO

# ggml tensor types: id -> (elements per block, bytes per block). From llama.cpp's
# gguf-py/gguf/constants.py (GGML_QUANT_SIZES), fetched 2026-11-26. Ids absent here were removed
# upstream or are newer than this table; files using them are reported as unknown.
QK_K = 256
TENSOR_TYPES: dict[int, tuple[str, int, int]] = {
    0: ("F32", 1, 4), 1: ("F16", 1, 2), 2: ("Q4_0", 32, 18), 3: ("Q4_1", 32, 20), 6: ("Q5_0", 32, 22),
    7: ("Q5_1", 32, 24), 8: ("Q8_0", 32, 34), 9: ("Q8_1", 32, 36),
    10: ("Q2_K", 256, 4 + QK_K // 16 + QK_K // 4), 11: ("Q3_K", 256, 2 + QK_K // 4 + QK_K // 8 + 12),
    12: ("Q4_K", 256, 4 + QK_K // 2 + 12), 13: ("Q5_K", 256, 4 + QK_K // 2 + QK_K // 8 + 12),
    14: ("Q6_K", 256, 2 + QK_K // 2 + QK_K // 4 + QK_K // 16), 15: ("Q8_K", 256, 4 + QK_K + QK_K // 8),
    16: ("IQ2_XXS", 256, 2 + QK_K // 4), 17: ("IQ2_XS", 256, 2 + QK_K // 4 + QK_K // 32),
    18: ("IQ3_XXS", 256, 2 + QK_K // 4 + QK_K // 8), 19: ("IQ1_S", 256, 2 + QK_K // 8 + QK_K // 16),
    20: ("IQ4_NL", 32, 18), 21: ("IQ3_S", 256, 2 + QK_K // 4 + QK_K // 8 + QK_K // 32 + 4),
    22: ("IQ2_S", 256, 2 + QK_K // 4 + QK_K // 16), 23: ("IQ4_XS", 256, 4 + QK_K // 2 + QK_K // 64),
    24: ("I8", 1, 1), 25: ("I16", 1, 2), 26: ("I32", 1, 4), 27: ("I64", 1, 8), 28: ("F64", 1, 8),
    29: ("IQ1_M", 256, QK_K // 8 + QK_K // 16 + QK_K // 32), 30: ("BF16", 1, 2),
    34: ("TQ1_0", 256, 2 + 4 * 13), 35: ("TQ2_0", 256, 2 + 64), 39: ("MXFP4", 32, 17),
    40: ("NVFP4", 64, 36), 41: ("Q1_0", 128, 18), 42: ("Q2_0", 64, 18), 43: ("F8_E4M3", 1, 1),
}

# Metadata value types: id -> struct format (STRING = 8 and ARRAY = 9 are handled separately).
SCALARS = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}
STRING, ARRAY = 8, 9

MAX_DIMS = 4                # GGML_MAX_DIMS
MAX_TENSOR_NAME = 63        # GGML_MAX_NAME is 64 including the terminating NUL
MAX_KEY = 65535             # the GGUF spec's limit on key length
MAX_KV = 1 << 16
MAX_TENSORS = 1 << 20
MAX_ARRAY = 1 << 26         # elements; the largest vocabularies are a few hundred thousand
MAX_STRING = 1 << 26        # bytes; chat templates and merges are well below this
INT64_MAX = (1 << 63) - 1
DEFAULT_ALIGNMENT = 32


class GGUFError(ValueError):
    pass


class UnknownTensorType(GGUFError):
    pass


@dataclass
class GGUFInfo:
    version: int
    tensors: int
    metadata: int
    alignment: int
    data_offset: int
    types: dict[str, int] = field(default_factory=dict)
    chat_template_bytes: int = 0

    def summary(self) -> str:
        types = ", ".join(f"{name}x{count}" for name, count in sorted(self.types.items()))
        parts = [f"GGUF v{self.version}", f"{self.tensors} tensors", f"{self.metadata} keys"]
        if self.chat_template_bytes:
            parts.append(f"chat template {self.chat_template_bytes} B")
        return ", ".join(parts) + (f" ({types})" if types else "")


class _Reader:
    def __init__(self, fh: BinaryIO, size: int):
        self.fh, self.size, self.pos = fh, size, 0

    def take(self, n: int, what: str) -> bytes:
        if n < 0 or self.pos + n > self.size:
            raise GGUFError(f"{what} runs past the end of the file (offset {self.pos}, {n} bytes)")
        data = self.fh.read(n)
        if len(data) != n:
            raise GGUFError(f"short read in {what}")
        self.pos += n
        return data

    def skip(self, n: int, what: str) -> None:
        if n < 0 or self.pos + n > self.size:
            raise GGUFError(f"{what} runs past the end of the file (offset {self.pos}, {n} bytes)")
        self.pos += n
        self.fh.seek(self.pos)

    def unpack(self, fmt: str, what: str):
        return struct.unpack(fmt, self.take(struct.calcsize(fmt), what))[0]

    def string(self, what: str, limit: int = MAX_STRING) -> str:
        length = self.unpack("<Q", f"{what} length")
        if length > limit:
            raise GGUFError(f"{what} is {length} bytes (limit {limit})")
        try:
            return self.take(length, what).decode("utf-8")
        except UnicodeDecodeError:
            raise GGUFError(f"{what} is not valid UTF-8") from None


def _value(r: _Reader, vtype: int, key: str, top: bool = True):
    if vtype in SCALARS:
        return r.unpack(SCALARS[vtype], f"value of {key!r}")
    if vtype == STRING:
        return r.string(f"value of {key!r}")
    if vtype == ARRAY and top:
        etype = r.unpack("<I", f"array type of {key!r}")
        count = r.unpack("<Q", f"array length of {key!r}")
        if count > MAX_ARRAY:
            raise GGUFError(f"array {key!r} has {count} elements (limit {MAX_ARRAY})")
        if etype in SCALARS:
            r.skip(count * struct.calcsize(SCALARS[etype]), f"array {key!r}")
            return None
        if etype == STRING:
            for _ in range(count):
                r.string(f"element of {key!r}")
            return None
        if etype == ARRAY:
            raise GGUFError(f"array {key!r} contains arrays (nested arrays are not supported)")
        raise GGUFError(f"array {key!r} has unknown element type {etype}")
    raise GGUFError(f"key {key!r} has unknown value type {vtype}")


def validate(fh: BinaryIO, size: int) -> GGUFInfo:
    """Parse and check a GGUF header; raise GGUFError on anything malformed."""
    r = _Reader(fh, size)
    if r.take(4, "magic") != b"GGUF":
        raise GGUFError("missing GGUF magic")
    version = r.unpack("<I", "version")
    if version not in (2, 3):
        raise GGUFError(f"unsupported GGUF version {version}")
    n_tensors = r.unpack("<Q", "tensor count")
    n_kv = r.unpack("<Q", "metadata count")
    if n_tensors > MAX_TENSORS or n_kv > MAX_KV:
        raise GGUFError(f"implausible counts: {n_tensors} tensors, {n_kv} metadata keys")

    keys: set[str] = set()
    alignment, template_bytes = DEFAULT_ALIGNMENT, 0
    for _ in range(n_kv):
        key = r.string("metadata key", MAX_KEY)
        if not key:
            raise GGUFError("empty metadata key")
        if key in keys:
            raise GGUFError(f"duplicate metadata key {key!r}")
        keys.add(key)
        vtype = r.unpack("<I", f"type of {key!r}")
        start = r.pos
        value = _value(r, vtype, key)
        if key == "general.alignment":
            if vtype != 4 or not value or value & (value - 1):
                raise GGUFError("general.alignment must be a power-of-two UINT32")
            alignment = value
        elif key == "tokenizer.chat_template":
            if vtype != STRING:
                raise GGUFError("tokenizer.chat_template must be a string")
            template_bytes = r.pos - start - 8

    names: set[str] = set()
    extents: list[tuple[int, int, str]] = []
    types: dict[str, int] = {}
    unknown: set[int] = set()
    for _ in range(n_tensors):
        name = r.string("tensor name", MAX_TENSOR_NAME)
        if name in names:
            raise GGUFError(f"duplicate tensor name {name!r}")
        names.add(name)
        n_dims = r.unpack("<I", f"dimension count of {name!r}")
        if not 1 <= n_dims <= MAX_DIMS:
            raise GGUFError(f"tensor {name!r} has {n_dims} dimensions (1-{MAX_DIMS} allowed)")
        dims = [r.unpack("<Q", f"dimensions of {name!r}") for _ in range(n_dims)]
        elements = 1
        for d in dims:
            if d < 1 or d > INT64_MAX:
                raise GGUFError(f"tensor {name!r} has dimension {d}")
            elements *= d
            if elements > INT64_MAX:
                raise GGUFError(f"tensor {name!r} has more elements than fit in int64")
        ttype = r.unpack("<I", f"type of {name!r}")
        offset = r.unpack("<Q", f"offset of {name!r}")
        if offset % alignment:
            raise GGUFError(f"tensor {name!r} offset {offset} is not aligned to {alignment}")
        if ttype not in TENSOR_TYPES:
            unknown.add(ttype)
            continue
        type_name, block, block_bytes = TENSOR_TYPES[ttype]
        if dims[0] % block:
            raise GGUFError(f"tensor {name!r}: first dimension {dims[0]} is not a multiple of {type_name}'s block of {block}")
        nbytes = elements // block * block_bytes
        types[type_name] = types.get(type_name, 0) + 1
        extents.append((offset, offset + nbytes, name))

    data_offset = -(-r.pos // alignment) * alignment
    data_size = size - data_offset
    if data_size < 0:
        raise GGUFError("file ends inside the header padding")
    extents.sort()
    previous_end, previous = 0, None
    for start, end, name in extents:
        if end > data_size:
            raise GGUFError(f"tensor {name!r} data ({start}-{end}) lies past the end of the file ({data_size} bytes of data)")
        if start < previous_end:
            raise GGUFError(f"tensor {name!r} overlaps tensor {previous!r}")
        previous_end, previous = end, name
    if unknown:
        raise UnknownTensorType(f"unknown tensor type(s) {sorted(unknown)}: newer than silo's table, or not a ggml type")
    return GGUFInfo(version, n_tensors, n_kv, alignment, data_offset, types, template_bytes)
