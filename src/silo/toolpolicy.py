"""Tool-call policy: which tools a client may offer, and which calls a model may make.

With `gateway.allow_tools = false` (the default) the gateway refuses every request that carries a
tool key, and cuts off any tool call the runtime emits anyway. With it on, whatever executes the
calls sits outside the silo, so the gateway narrows what can reach that executor:

  * request side: only function tools, with well-formed, unique names, and, when `gateway.tools` is
    set, only names on that list. `tool_choice` / `function_call` may only force an offered tool;
  * response side: the model may only call a tool the request offered. A tool call that names
    anything else, changes its name mid-stream or sends arguments before naming a tool is refused,
    and each call's arguments are capped at `gateway.max_tool_arguments_bytes`.

The arguments themselves are not interpreted: they are scanned by the output tripwire with the
rest of the completion, and recorded in the audit log by tool name.
"""

from __future__ import annotations

import re
from collections.abc import Collection

TOOL_KEYS = ("tools", "tool_choice", "functions", "function_call", "parallel_tool_calls")
# The OpenAI API's constraint on function names; also what config.gateway.tools must match.
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
CHOICE_MODES = frozenset({"none", "auto", "required"})


class ToolPolicyError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def _bad(message: str) -> ToolPolicyError:
    return ToolPolicyError(400, message)


def _function_names(request: dict) -> list:
    names = []
    tools = request.get("tools", [])
    if not isinstance(tools, list):
        raise _bad("tools must be a list")
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") != "function" or not isinstance(tool.get("function"), dict):
            raise _bad("only tools of type 'function' are supported")
        names.append(tool["function"].get("name"))
    functions = request.get("functions", [])
    if not isinstance(functions, list):
        raise _bad("functions must be a list")
    for fn in functions:
        if not isinstance(fn, dict):
            raise _bad("functions must be a list of objects")
        names.append(fn.get("name"))
    return names


def _check_choice(choice, offered: list[str], key: str) -> None:
    if isinstance(choice, str):
        if choice not in CHOICE_MODES:
            raise _bad(f"{key} must be one of {', '.join(sorted(CHOICE_MODES))} or name an offered tool")
        return
    if not isinstance(choice, dict):
        raise _bad(f"{key} must be a string or an object")
    if key == "tool_choice":
        if choice.get("type") != "function" or not isinstance(choice.get("function"), dict):
            raise _bad("tool_choice objects must be {\"type\": \"function\", \"function\": {\"name\": ...}}")
        name = choice["function"].get("name")
    else:
        name = choice.get("name")
    if name not in offered:
        raise _bad(f"{key} names a tool the request does not offer")


def offered_tools(request: dict, allow: bool, allowlist: Collection[str]) -> list[str]:
    """Check a request's tool keys against the policy; return the tool names it offers."""
    present = [k for k in TOOL_KEYS if k in request]
    if not present:
        return []
    if not allow:
        raise ToolPolicyError(403, f"tool calling is disabled (gateway.allow_tools = false): {', '.join(present)}")
    names = _function_names(request)
    for name in names:
        if not isinstance(name, str) or not NAME_RE.match(name):
            raise _bad("tool names must match [A-Za-z0-9_-]{1,64}")
    if len(set(names)) != len(names):
        raise _bad("tool names must be unique")
    if allowlist:
        refused = sorted(set(names) - set(allowlist))
        if refused:
            raise ToolPolicyError(403, f"tool(s) not allowed by gateway.tools: {', '.join(refused)}")
    if "tool_choice" in request:
        _check_choice(request["tool_choice"], names, "tool_choice")
    if "function_call" in request:
        _check_choice(request["function_call"], names, "function_call")
    if "parallel_tool_calls" in request and not isinstance(request["parallel_tool_calls"], bool):
        raise _bad("parallel_tool_calls must be a boolean")
    return names


class CallChecker:
    """Checks the tool calls in one response, or across every chunk of one stream.

    Streamed calls arrive in pieces: the first delta for a call carries its name, later ones carry
    argument fragments for the same (choice, call) index. Names are therefore tracked per slot and
    argument sizes summed per slot.
    """

    def __init__(self, offered: Collection[str], max_argument_bytes: int):
        self.offered = frozenset(offered)
        self.max_argument_bytes = max_argument_bytes
        self._names: dict[tuple, str] = {}
        self._sizes: dict[tuple, int] = {}

    def check(self, payload: dict) -> None:
        choices = payload.get("choices") or []
        if not isinstance(choices, list):
            return
        for pos, choice in enumerate(choices):
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", pos)
            for key in ("message", "delta"):
                msg = choice.get(key)
                if not isinstance(msg, dict):
                    continue
                calls = msg.get("tool_calls")
                if calls:
                    if not isinstance(calls, list):
                        raise self._refuse("malformed tool_calls")
                    for call_pos, call in enumerate(calls):
                        if not isinstance(call, dict):
                            raise self._refuse("malformed tool call")
                        self._call((repr(index), "tool", repr(call.get("index", call_pos))), call.get("function"))
                legacy = msg.get("function_call")
                if legacy:
                    self._call((repr(index), "function"), legacy)

    @staticmethod
    def _refuse(message: str) -> ToolPolicyError:
        return ToolPolicyError(502, f"model tool call refused: {message}")

    def _call(self, slot: tuple, fn) -> None:
        if fn is None:
            return
        if not isinstance(fn, dict):
            raise self._refuse("malformed function")
        name, arguments = fn.get("name"), fn.get("arguments")
        if name not in (None, ""):
            if not isinstance(name, str):
                raise self._refuse("malformed name")
            known = self._names.get(slot)
            if known is not None and known != name:
                raise self._refuse("tool name changed mid-stream")
            if name not in self.offered:
                raise self._refuse(f"{name[:64]!r} was not offered by the request")
            self._names[slot] = name
        if arguments in (None, ""):
            return
        if not isinstance(arguments, str):
            raise self._refuse("arguments must be a string")
        if slot not in self._names:
            raise self._refuse("arguments sent before the tool was named")
        size = self._sizes.get(slot, 0) + len(arguments.encode("utf-8", "surrogatepass"))
        if size > self.max_argument_bytes:
            raise self._refuse(f"arguments exceed {self.max_argument_bytes} bytes (gateway.max_tool_arguments_bytes)")
        self._sizes[slot] = size
