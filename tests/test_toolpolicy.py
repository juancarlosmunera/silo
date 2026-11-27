import unittest

from silo.toolpolicy import CallChecker, ToolPolicyError, callable_tools, offered_tools


def fn(name):
    return {"type": "function", "function": {"name": name}}


def chunk(call, choice=0):
    return {"choices": [{"index": choice, "delta": {"tool_calls": [call]}}]}


class OfferedToolsTests(unittest.TestCase):
    def test_no_tool_keys(self):
        self.assertEqual(offered_tools({"messages": []}, allow=False, allowlist=[]), [])

    def test_disabled(self):
        with self.assertRaises(ToolPolicyError) as cm:
            offered_tools({"tools": []}, allow=False, allowlist=[])
        self.assertEqual(cm.exception.status, 403)

    def test_any_tool_without_allowlist(self):
        self.assertEqual(offered_tools({"tools": [fn("a"), fn("b")]}, allow=True, allowlist=[]), ["a", "b"])

    def test_allowlist(self):
        self.assertEqual(offered_tools({"tools": [fn("a")]}, allow=True, allowlist=["a", "b"]), ["a"])
        with self.assertRaises(ToolPolicyError) as cm:
            offered_tools({"tools": [fn("a"), fn("c")]}, allow=True, allowlist=["a"])
        self.assertEqual(cm.exception.status, 403)
        self.assertIn("c", cm.exception.message)

    def test_names_from_both_styles_share_one_namespace(self):
        with self.assertRaises(ToolPolicyError):
            offered_tools({"tools": [fn("a")], "functions": [{"name": "a"}]}, allow=True, allowlist=[])
        self.assertEqual(offered_tools({"tools": [fn("a")], "functions": [{"name": "b"}]}, allow=True,
                                       allowlist=[]), ["a", "b"])

    def test_names_are_strings(self):
        for name in (None, 1, ["a"], "a" * 65, "a.b", "a b", ""):
            with self.subTest(name=name), self.assertRaises(ToolPolicyError):
                offered_tools({"tools": [fn(name)]}, allow=True, allowlist=[])


class CallCheckerTests(unittest.TestCase):
    def test_text_only(self):
        CallChecker([], 10).check({"choices": [{"message": {"content": "hi", "tool_calls": []}}]})
        CallChecker([], 10).check({"error": {"message": "no choices at all"}})

    def test_parallel_calls_tracked_separately(self):
        c = CallChecker(["a", "b"], 10)
        c.check(chunk({"index": 0, "function": {"name": "a", "arguments": "12345"}}))
        c.check(chunk({"index": 1, "function": {"name": "b", "arguments": "12345"}}))
        c.check(chunk({"index": 0, "function": {"arguments": "12345"}}))
        with self.assertRaises(ToolPolicyError):
            c.check(chunk({"index": 1, "function": {"arguments": "123456"}}))

    def test_choices_tracked_separately(self):
        c = CallChecker(["a"], 100)
        c.check(chunk({"index": 0, "function": {"name": "a"}}, choice=0))
        with self.assertRaises(ToolPolicyError):  # choice 1's call 0 was never named
            c.check(chunk({"index": 0, "function": {"arguments": "{}"}}, choice=1))

    def test_argument_size_counts_bytes(self):
        c = CallChecker(["a"], 4)
        with self.assertRaises(ToolPolicyError):
            c.check(chunk({"index": 0, "function": {"name": "a", "arguments": "ééé"}}))

    def test_malformed(self):
        for payload in ({"choices": [{"message": {"tool_calls": "shell"}}]},
                        {"choices": [{"message": {"tool_calls": ["shell"]}}]},
                        {"choices": [{"message": {"tool_calls": [{"function": "shell"}]}}]},
                        {"choices": [{"message": {"tool_calls": [{"function": {"name": 7}}]}}]},
                        {"choices": [{"message": {"tool_calls": [{"function": {"name": "a", "arguments": {}}}]}}]}):
            with self.subTest(payload=payload), self.assertRaises(ToolPolicyError) as cm:
                CallChecker(["a"], 100).check(payload)
            self.assertEqual(cm.exception.status, 502)

    def test_shapes_other_clients_would_still_read_are_refused(self):
        call = {"function": {"name": "shell", "arguments": "{}"}}
        for payload in ({"choices": {"0": {"message": {"tool_calls": [call]}}}},   # JS: choices[0] works
                        {"choices": "garbage"},
                        {"choices": [["not", "a", "choice"]]},
                        {"choices": [{"message": "text"}]},
                        {"choices": [{"index": "0", "message": {"content": "x"}}]},
                        {"choices": [{"message": {"tool_calls": [dict(call, index=False)]}}]}):
            with self.subTest(payload=payload), self.assertRaises(ToolPolicyError):
                CallChecker([], 100).check(payload)

    def test_call_index_spelled_another_way_is_refused(self):
        for index in (False, True, 0.0, "0", [0], -1):
            c = CallChecker(["a"], 100)
            c.check(chunk({"index": 0, "function": {"name": "a", "arguments": "x"}}))
            with self.subTest(index=index), self.assertRaises(ToolPolicyError):
                c.check(chunk({"index": index, "function": {"name": "a", "arguments": "x"}}))

    def test_argument_cap_holds_across_choices(self):
        # a client that ignores the choice index joins call 0 of every choice into one call
        c = CallChecker(["a"], 100)
        with self.assertRaises(ToolPolicyError):
            for choice in range(12):
                c.check(chunk({"index": 0, "function": {"name": "a", "arguments": "x" * 90}}, choice=choice))

    def test_the_request_constraints_bind_the_answer(self):
        tools = {"tools": [fn("a"), fn("b")]}
        for extra, allowed, limit in (({"tool_choice": "none"}, [], None),
                                      ({"tool_choice": "auto"}, ["a", "b"], None),
                                      ({"tool_choice": {"type": "function", "function": {"name": "b"}}}, ["b"], None),
                                      ({"parallel_tool_calls": False}, ["a", "b"], 1)):
            with self.subTest(extra=extra):
                request = dict(tools, **extra)
                self.assertEqual(callable_tools(request, offered_tools(request, True, [])), (allowed, limit))
        c = CallChecker(["a", "b"], 100, max_calls=1)
        c.check(chunk({"index": 0, "function": {"name": "a"}}))
        c.check(chunk({"index": 0, "function": {"arguments": "{}"}}))
        with self.assertRaises(ToolPolicyError):
            c.check(chunk({"index": 1, "function": {"name": "b"}}))

    def test_names_with_a_trailing_newline(self):
        with self.assertRaises(ToolPolicyError):
            offered_tools({"tools": [fn("shell\n")]}, allow=True, allowlist=[])

    def test_tool_keys_hidden_in_template_arguments(self):
        request = {"messages": [], "chat_template_kwargs": {"tools": [fn("shell")]}}
        for allow in (False, True):
            with self.subTest(allow=allow), self.assertRaises(ToolPolicyError):
                offered_tools(request, allow=allow, allowlist=[])
        self.assertEqual(offered_tools({"chat_template_kwargs": {"enable_thinking": False}}, False, []), [])


if __name__ == "__main__":
    unittest.main()
