import unittest

from silo import cli
from silo.util import safe_text


class SafeTextTests(unittest.TestCase):
    def test_control_sequences_are_escaped(self):
        self.assertEqual(safe_text("\x1b]0;owned\x07"), "\\x1b]0;owned\\x07")
        self.assertEqual(safe_text("\x1b[2J"), "\\x1b[2J")
        self.assertEqual(safe_text("progress\rOVERWRITTEN"), "progress\\x0dOVERWRITTEN")
        self.assertEqual(safe_text("a\x9b31mb"), "a\\x9b31mb")
        self.assertEqual(safe_text("abc\u202edef"), "abc\\u202edef")
        self.assertEqual(safe_text("\x00\x7f"), "\\x00\\x7f")

    def test_ordinary_text_is_untouched(self):
        for text in ("plain", "tab\tand\nnewline", "é ñ 日本語 👨‍👩‍👧", "path/with spaces/model-Q4_K_M.gguf", ""):
            self.assertEqual(safe_text(text), text)

    def test_result_never_contains_a_raw_escape(self):
        hostile = "".join(chr(c) for c in range(0, 0x100)) + "\u2028\u2029\u202a\u2066"
        cleaned = safe_text(hostile)
        self.assertFalse(any(ord(ch) < 0x20 and ch not in "\t\n" for ch in cleaned))
        self.assertFalse(any(0x7f <= ord(ch) <= 0x9f for ch in cleaned))


class CliTests(unittest.TestCase):
    def test_every_subcommand_has_a_handler(self):
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if a.dest == "command")
        self.assertEqual(set(sub.choices), set(cli.COMMANDS))

    def test_config_errors_exit_2_without_a_traceback(self):
        self.assertEqual(cli.main(["--config", "/nonexistent/silo.toml", "status"]), 2)


if __name__ == "__main__":
    unittest.main()
