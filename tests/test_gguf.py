import io
import struct
import unittest

from silo import gguf


def s(text: str | bytes) -> bytes:
    raw = text.encode() if isinstance(text, str) else text
    return struct.pack("<Q", len(raw)) + raw


def kv(key: str, vtype: int, payload: bytes) -> bytes:
    return s(key) + struct.pack("<I", vtype) + payload


def tensor(name: str, dims, ttype: int, offset: int) -> bytes:
    return s(name) + struct.pack("<I", len(dims)) + b"".join(struct.pack("<Q", d) for d in dims) + \
        struct.pack("<IQ", ttype, offset)


def build(kvs=(), tensors=(), data=b"", version=3, alignment=32, n_tensors=None, n_kv=None) -> bytes:
    header = b"GGUF" + struct.pack("<IQQ", version, len(tensors) if n_tensors is None else n_tensors,
                                   len(kvs) if n_kv is None else n_kv)
    header += b"".join(kvs) + b"".join(tensors)
    header += b"\0" * (-len(header) % alignment)
    return header + data


F32, Q8_0 = 0, 8
GOOD_KVS = (
    kv("general.architecture", 8, s("llama")),
    kv("llama.context_length", 4, struct.pack("<I", 4096)),
    kv("tokenizer.ggml.tokens", 9, struct.pack("<IQ", 8, 3) + s("a") + s("b") + s("c")),
    kv("tokenizer.ggml.scores", 9, struct.pack("<IQ", 6, 3) + struct.pack("<3f", 0, 0, 0)),
    kv("tokenizer.chat_template", 8, s("{{ messages }}")),
)
# a 2x32 F32 tensor (256 bytes) at 0, and a 32-element Q8_0 tensor (34 bytes) at 256
GOOD_TENSORS = (tensor("a.weight", [32, 2], F32, 0), tensor("b.weight", [32], Q8_0, 256))
GOOD_DATA = b"\0" * (256 + 34)


def check(data: bytes) -> gguf.GGUFInfo:
    return gguf.validate(io.BytesIO(data), len(data))


class GGUFTests(unittest.TestCase):
    def assert_bad(self, data: bytes, fragment: str, exc=gguf.GGUFError):
        with self.assertRaises(exc) as cm:
            check(data)
        self.assertIn(fragment, str(cm.exception))

    def test_valid(self):
        info = check(build(GOOD_KVS, GOOD_TENSORS, GOOD_DATA))
        self.assertEqual((info.version, info.tensors, info.metadata), (3, 2, 5))
        self.assertEqual(info.types, {"F32": 1, "Q8_0": 1})
        self.assertEqual(info.chat_template_bytes, len("{{ messages }}"))
        self.assertIn("chat template", info.summary())

    def test_empty_model_header(self):
        self.assertEqual(check(build()).tensors, 0)

    def test_custom_alignment(self):
        kvs = GOOD_KVS + (kv("general.alignment", 4, struct.pack("<I", 64)),)
        check(build(kvs, (tensor("a.weight", [32, 2], F32, 0), tensor("b.weight", [32], Q8_0, 256)),
                    GOOD_DATA, alignment=64))
        for bad in (struct.pack("<I", 0), struct.pack("<I", 48)):
            with self.subTest(alignment=bad):
                self.assert_bad(build(GOOD_KVS + (kv("general.alignment", 4, bad),)), "power-of-two")
        self.assert_bad(build((kv("general.alignment", 10, struct.pack("<Q", 64)),)), "power-of-two")
        self.assert_bad(build(GOOD_KVS + (kv("general.alignment", 4, struct.pack("<I", 64)),),
                              (tensor("a.weight", [32], F32, 32),), b"\0" * 256, alignment=64), "not aligned")

    def test_header_fields(self):
        self.assert_bad(b"GGUL" + build()[4:], "magic")
        self.assert_bad(build(version=1), "version")
        self.assert_bad(build(n_kv=1 << 40), "implausible")
        self.assert_bad(build(n_tensors=gguf.MAX_TENSORS + 1), "implausible")
        self.assert_bad(build()[:12], "past the end")

    def test_counts_that_overrun(self):
        # claims more keys or tensors than the file holds
        self.assert_bad(build(GOOD_KVS, n_kv=len(GOOD_KVS) + 1), "")  # padding read as a key: refused either way
        self.assert_bad(build(GOOD_KVS, GOOD_TENSORS, GOOD_DATA, n_tensors=3), "")

    def test_strings(self):
        self.assert_bad(build((kv("k", 8, struct.pack("<Q", 1 << 62)),)), "limit")
        self.assert_bad(build((kv("k", 8, struct.pack("<Q", 1000) + b"x"),)), "past the end")
        self.assert_bad(build((kv("k", 8, s(b"\xff\xfe")),)), "UTF-8")
        self.assert_bad(build((s("") + struct.pack("<I", 4) + struct.pack("<I", 1),)), "empty")

    def test_metadata(self):
        self.assert_bad(build((kv("k", 4, struct.pack("<I", 1)), kv("k", 4, struct.pack("<I", 2)))), "duplicate")
        self.assert_bad(build((kv("k", 13, b""),)), "unknown value type")
        self.assert_bad(build((kv("k", 9, struct.pack("<IQ", 9, 1) + struct.pack("<IQ", 4, 0)),)), "nested")
        self.assert_bad(build((kv("k", 9, struct.pack("<IQ", 99, 1)),)), "unknown element type")
        self.assert_bad(build((kv("k", 9, struct.pack("<IQ", 4, 1 << 40)),)), "limit")
        self.assert_bad(build((kv("k", 9, struct.pack("<IQ", 4, 1000) + b"\0" * 8),)), "past the end")
        self.assert_bad(build((kv("tokenizer.chat_template", 4, struct.pack("<I", 1)),)), "must be a string")

    def test_tensor_descriptors(self):
        def one(t, data=GOOD_DATA):
            return build(GOOD_KVS, (t,), data)
        self.assert_bad(build(GOOD_KVS, (tensor("a", [32], F32, 0), tensor("a", [32], F32, 128)), GOOD_DATA),
                        "duplicate tensor")
        self.assert_bad(one(tensor("x" * 64, [32], F32, 0)), "limit")
        self.assert_bad(one(tensor("a", [], F32, 0)), "dimensions")
        self.assert_bad(one(tensor("a", [1, 1, 1, 1, 1], F32, 0)), "dimensions")
        self.assert_bad(one(tensor("a", [32, 0], F32, 0)), "dimension 0")
        self.assert_bad(one(tensor("a", [1 << 62, 4], F32, 0)), "int64")
        self.assert_bad(one(tensor("a", [33], Q8_0, 0)), "block")
        self.assert_bad(one(tensor("a", [32], F32, 3)), "not aligned")

    def test_tensor_extents(self):
        self.assert_bad(build(GOOD_KVS, GOOD_TENSORS, GOOD_DATA[:-1]), "past the end of the file")
        self.assert_bad(build(GOOD_KVS, (tensor("a", [32, 2], F32, 0), tensor("b", [32], Q8_0, 128)), GOOD_DATA),
                        "overlaps")
        self.assert_bad(build(GOOD_KVS, (tensor("a", [32], F32, 1 << 62),), GOOD_DATA), "past the end of the file")
        # data larger than the tensors need (padding, unused space) is fine
        check(build(GOOD_KVS, GOOD_TENSORS, GOOD_DATA + b"\0" * 64))

    def test_unknown_type_is_its_own_error(self):
        data = build(GOOD_KVS, (tensor("a", [32], 4, 0),), GOOD_DATA)  # 4: a removed type
        self.assert_bad(data, "unknown tensor type", gguf.UnknownTensorType)

    def test_type_table(self):
        for ttype, (name, block, size) in gguf.TENSOR_TYPES.items():
            with self.subTest(name=name):
                self.assertGreater(block, 0)
                self.assertGreater(size, 0)
        # spot checks against ggml's block structs
        self.assertEqual(gguf.TENSOR_TYPES[12][1:], (256, 144))  # Q4_K
        self.assertEqual(gguf.TENSOR_TYPES[14][1:], (256, 210))  # Q6_K
        self.assertEqual(gguf.TENSOR_TYPES[8][1:], (32, 34))     # Q8_0


if __name__ == "__main__":
    unittest.main()
