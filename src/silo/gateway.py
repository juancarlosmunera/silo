"""Host-side gateway: the only path between clients and the sandboxed model.

    client --HTTP/127.0.0.1--> gateway --HTTP over AF_UNIX--> llama-server (network=none)

The model process cannot initiate anything: it has no network interface and can only answer on its
UNIX socket. The gateway treats both sides as untrusted and terminates the protocol rather than
piping bytes:

  * route allowlist (OpenAI-compatible inference endpoints + /health), matched verbatim; no admin,
    slots, props, metrics, web UI, LoRA control or static files;
  * every request and response body is parsed as JSON and re-serialised, so what was inspected is
    byte-for-byte what is forwarded (no parser differentials between the gateway and either side);
  * the gateway chooses the response Content-Type (JSON or SSE, never the upstream's) and adds
    nosniff + a deny-all CSP, so a compromised runtime cannot serve HTML or script to a browser that
    happens to open the gateway URL;
  * no client headers reach the model, no upstream headers reach the client;
  * loopback Host check (DNS rebinding) and no browser-originated requests (Origin);
  * tool calling is refused unless gateway.allow_tools is set: by default the model can only emit text;
  * size caps both ways, one total deadline per request, bounded concurrency;
  * output tripwire (silo.scanner) on every completion; in enforce mode streams are held until they
    finish clean, so a blocked completion is never partially delivered;
  * JSONL audit log with request/response hashes, findings and tool-call names, written before
    delivery wherever that is possible.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import socket
import stat
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from silo import scanner
from silo.config import Config, ConfigError

ROUTES: dict[str, set[str]] = {
    "/health": {"GET"},
    "/v1/models": {"GET"},
    "/v1/chat/completions": {"POST"},
    "/v1/completions": {"POST"},
    "/v1/embeddings": {"POST"},
}
JSON_TYPE = "application/json"
SSE_TYPE = "text/event-stream"
TOOL_KEYS = ("tools", "tool_choice", "functions", "function_call", "parallel_tool_calls")
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
RESPONSE_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; sandbox"),
    ("Cache-Control", "no-store"),
    ("Referrer-Policy", "no-referrer"),
)
CLIENT_IO_TIMEOUT = 30  # seconds a client may stall on a single read or write


class Reject(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class ClientGone(Exception):
    pass


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._unix_path = path

    def connect(self) -> None:
        # lstat, not stat: the path must itself be a socket, never a symlink to some other host socket.
        try:
            mode = os.lstat(self._unix_path).st_mode
        except OSError as exc:
            raise FileNotFoundError(self._unix_path) from exc
        if not stat.S_ISSOCK(mode):
            raise ConnectionRefusedError(f"{self._unix_path} is not a socket")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._unix_path)
        except OSError:
            sock.close()
            raise
        self.sock = sock


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    def write(self, entry: dict) -> None:
        line = (json.dumps(entry, separators=(",", ":")) + "\n").encode()
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line)
            finally:
                os.close(fd)


def _no_constants(name: str):
    raise ValueError(f"non-standard JSON constant {name}")


def canonical(data: bytes) -> tuple[object, bytes]:
    """Parse JSON strictly and return (value, canonical ASCII serialisation).

    Raises ValueError for anything that is not standard JSON (NaN/Infinity, bad UTF-8, numbers that
    overflow to infinity) and RecursionError for pathological nesting; callers treat both as invalid.
    """
    value = json.loads(data, parse_constant=_no_constants)
    return value, json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")


def _route(target: str) -> str:
    # The request target is matched verbatim (minus the query string). No URL parsing or
    # normalisation: "//x", "/v1/../slots" and percent-encodings simply fail to match.
    return target.split("?", 1)[0]


def _hostname(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("["):
        return host[: host.find("]") + 1]
    return host.split(":", 1)[0]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


class Gateway:
    def __init__(self, cfg: Config, socket_path: Path | None = None, audit: AuditLog | None = None):
        self.cfg = cfg
        self.gw = cfg.gateway
        self.socket_path = str(socket_path or cfg.socket_path)
        self.audit = audit or AuditLog(cfg.audit_log)
        self.slots = threading.BoundedSemaphore(self.gw.max_concurrency)
        self.loopback_only = ipaddress.ip_address(self.gw.listen).is_loopback
        self.api_key = os.environ.get(self.gw.api_key_env) if self.gw.api_key_env else None
        if self.gw.api_key_env and not self.api_key:
            raise ConfigError(f"gateway.api_key_env={self.gw.api_key_env} is set but the variable is empty")

    def server(self) -> ThreadingHTTPServer:
        family = socket.AF_INET6 if ":" in self.gw.listen else socket.AF_INET
        cls = type("SiloGatewayServer", (_Server,), {"address_family": family})
        return cls((self.gw.listen, self.gw.port), _make_handler(self))


def _make_handler(gw: Gateway):
    cfg = gw.gw

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"  # one request per connection; streamed bodies end at close
        timeout = CLIENT_IO_TIMEOUT
        _t0 = 0.0
        _started = False
        _audited = False
        _sse = False

        def version_string(self) -> str:
            return "silo"

        def log_message(self, fmt, *args):  # the audit log replaces access logging
            pass

        def _modernise(self) -> bool:
            # http.server answers HTTP/0.9-looking requests (one- or two-word request lines) with a bare
            # body: no status line, no headers. Every silo response carries its headers.
            if getattr(self, "request_version", "HTTP/0.9") != "HTTP/0.9":
                return False
            self.request_version = "HTTP/1.0"
            return True

        def _dispatch(self):
            if self._modernise():
                # Python versions disagree on whether such a request has headers; refuse it on all of them.
                return self.send_error(400)
            self._handle(self.command)

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = do_TRACE = _dispatch

        def send_error(self, code, message=None, explain=None):
            # Malformed request lines, oversized headers, unknown methods: answered by http.server
            # before _handle runs. Keep them JSON, headered and audited like everything else.
            self._modernise()
            self._t0 = self._t0 or time.monotonic()
            entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "silo": gw.cfg.name,
                     "client": self.client_address[0]}
            self.close_connection = True
            self._fail(int(code), "malformed or unsupported request", entry)

        # ------------------------------------------------------------------------------ client side

        def _write(self, data: bytes) -> None:
            try:
                self.wfile.write(data)
                self.wfile.flush()
            except OSError as exc:
                raise ClientGone from exc

        def _send(self, status: int, ctype: str, body: bytes | None) -> None:
            self._started = True
            self._sse = ctype == SSE_TYPE
            try:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                for name, value in RESPONSE_HEADERS:
                    self.send_header(name, value)
                if body is not None:
                    self.send_header("Content-Length", str(len(body)))
                self.end_headers()
            except OSError as exc:
                raise ClientGone from exc
            if body:
                self._write(body)

        def _audit(self, entry: dict) -> None:
            if self._audited:
                return
            self._audited = True
            entry["ms"] = int((time.monotonic() - self._t0) * 1000)
            gw.audit.write(entry)
            if entry.get("findings"):
                rules = ", ".join(sorted({f"{f['rule']}({f['severity']})" for f in entry["findings"]}))
                print(f"silo[{gw.cfg.name}] ALERT request {entry.get('id', '-')}: {rules}",
                      file=sys.stderr, flush=True)

        def _fail(self, status: int, message: str, entry: dict) -> None:
            error = {"error": {"message": message, "type": "silo_gateway"}}
            if self._started:  # headers already sent (live stream): record it, tell the client in-band
                entry.update(error=message)
                self._audit(entry)
                if self._sse:
                    try:
                        self._write(b"data: " + json.dumps(error).encode() + b"\n\n")
                    except ClientGone:
                        pass
                return
            entry.update(status=status, rejected=message)
            self._audit(entry)  # audit before delivery, always
            try:
                self._send(status, JSON_TYPE, json.dumps(error).encode())
            except ClientGone:
                pass

        # ---------------------------------------------------------------------------------- request

        def _handle(self, method: str) -> None:
            self._t0, self._started, self._audited, self._sse = time.monotonic(), False, False, False
            path = _route(self.path)
            entry = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "id": uuid.uuid4().hex[:16],
                "silo": gw.cfg.name,
                "client": self.client_address[0],
                "method": method,
                "path": path[:200],
            }
            held = False
            try:
                body, stream = self._admit(method, path, entry)
                if not gw.slots.acquire(timeout=5):
                    raise Reject(429, "too many concurrent requests")
                held = True
                self._proxy(method, path, body, stream, entry)
            except Reject as reject:
                self._fail(reject.status, reject.message, entry)
            except ClientGone:
                entry.update(status=499, error="client disconnected")
                self._audit(entry)
            except (ConnectionRefusedError, FileNotFoundError):
                self._fail(503, "model sandbox is not running", entry)
            except TimeoutError:
                self._fail(504, "model sandbox timed out", entry)
            except (http.client.HTTPException, OSError) as exc:
                self._fail(502, f"model sandbox connection failed ({type(exc).__name__})", entry)
            except Exception as exc:  # noqa: BLE001 - the trust boundary fails closed, never with a traceback
                print(f"silo[{gw.cfg.name}] internal error on request {entry['id']}: {type(exc).__name__}: {exc}",
                      file=sys.stderr, flush=True)
                self._fail(500, "internal gateway error", entry)
            finally:
                if held:
                    gw.slots.release()

        def _admit(self, method: str, path: str, entry: dict) -> tuple[bytes, bool]:
            """Every check a request must pass before anything is sent to the model."""
            if gw.loopback_only and _hostname(self.headers.get("Host", "")) not in LOOPBACK_HOSTS:
                raise Reject(403, "Host header is not a loopback name (DNS-rebinding protection)")
            if self.headers.get("Origin") is not None:
                raise Reject(403, "browser-originated requests are not accepted")
            if path not in ROUTES:
                raise Reject(404, "route not allowed by silo")
            if method not in ROUTES[path]:
                raise Reject(405, "method not allowed")
            if gw.api_key is not None:
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied.encode(), f"Bearer {gw.api_key}".encode()):
                    raise Reject(401, "missing or invalid API key")
            if method != "POST":
                return b"", False

            if self.headers.get("Content-Type", "").split(";")[0].strip().lower() != JSON_TYPE:
                raise Reject(415, "Content-Type must be application/json")
            if self.headers.get("Transfer-Encoding"):
                raise Reject(411, "chunked request bodies are not accepted")
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                raise Reject(411, "Content-Length required") from None
            if length < 0 or length > cfg.max_request_bytes:
                raise Reject(413, f"request exceeds {cfg.max_request_bytes} bytes")
            try:
                raw = self.rfile.read(length)
            except OSError as exc:
                raise ClientGone from exc
            if len(raw) != length:
                raise ClientGone
            try:
                request, body = canonical(raw)
            except (ValueError, RecursionError):
                raise Reject(400, "body must be standard JSON") from None
            if not isinstance(request, dict):
                raise Reject(400, "body must be a JSON object")
            model = request.get("model")
            stream = request.get("stream") is True
            entry.update(req_bytes=len(body), req_sha256=_sha256(body), stream=stream,
                         model=model[:200] if isinstance(model, str) else None)
            if cfg.log_content:
                entry["request"] = request
            tool_keys = [k for k in TOOL_KEYS if k in request]
            if tool_keys and not cfg.allow_tools:
                raise Reject(403, f"tool calling is disabled (gateway.allow_tools = false): {', '.join(tool_keys)}")
            return body, stream

        # --------------------------------------------------------------------------------- upstream

        def _proxy(self, method: str, path: str, body: bytes, stream: bool, entry: dict) -> None:
            deadline = self._t0 + cfg.timeout
            conn = UnixHTTPConnection(gw.socket_path, timeout=cfg.timeout)
            try:
                headers = {"Accept": JSON_TYPE}
                if method == "POST":
                    headers["Content-Type"] = JSON_TYPE
                conn.request(method, path, body=body if method == "POST" else None, headers=headers)
                sock = conn.sock  # http.client drops its reference once the response is flagged close
                resp = conn.getresponse()
                status = resp.status
                ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
                if status != 200 and not 400 <= status <= 599:
                    raise Reject(502, f"unexpected status {status} from model sandbox")
                if ctype == SSE_TYPE:
                    if not stream or status != 200:
                        raise Reject(502, "unexpected event stream from model sandbox")
                    self._relay_stream(resp, sock, deadline, entry)
                elif ctype == JSON_TYPE:
                    self._relay_json(resp, sock, status, deadline, entry)
                else:
                    raise Reject(502, "unexpected content type from model sandbox")
            finally:
                conn.close()

        def _read_some(self, resp: http.client.HTTPResponse, sock: socket.socket, deadline: float) -> bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("request deadline exceeded")
            try:
                sock.settimeout(remaining)
            except OSError:
                pass
            return resp.read1(65536)

        def _relay_json(self, resp, sock, status: int, deadline: float, entry: dict) -> None:
            data = bytearray()
            while chunk := self._read_some(resp, sock, deadline):
                data += chunk
                if len(data) > cfg.max_response_bytes:
                    raise Reject(502, "model response exceeded size cap")
            try:
                payload, out = canonical(bytes(data))
            except (ValueError, RecursionError):
                raise Reject(502, "model sandbox returned invalid JSON") from None
            if not isinstance(payload, dict):
                raise Reject(502, "model sandbox returned a non-object JSON body")
            text = scanner.extract_text(payload)
            findings = scanner.scan(text) if cfg.scanner != "off" else []
            entry.update(resp_bytes=len(out), resp_sha256=_sha256(out),
                         findings=[f.as_dict() for f in findings], tool_calls=scanner.tool_call_names(payload))
            if cfg.log_content:
                entry["response_text"] = text
            if scanner.has_tool_calls(payload) and not cfg.allow_tools:
                raise Reject(502, "model emitted tool calls while gateway.allow_tools = false")
            if cfg.scanner == "enforce" and scanner.blocking(findings):
                raise Reject(502, "completion blocked by silo output policy")
            entry["status"] = status
            self._audit(entry)  # the record exists before the client can act on the output
            self._send(status, JSON_TYPE, out)

        def _relay_stream(self, resp, sock, deadline: float, entry: dict) -> None:
            hold = cfg.scanner == "enforce"  # deliver nothing until the whole completion is known clean
            stream_scan = scanner.StreamScanner()
            digest = hashlib.sha256()
            held: list[bytes] = []
            tools: list[str] = []
            text: list[str] = []
            total, dropped, pending, done = 0, 0, b"", False

            def emit(event: bytes) -> None:
                nonlocal total
                total += len(event)
                digest.update(event)
                if hold:
                    held.append(event)
                else:
                    self._write(event)

            if not hold:
                self._send(200, SSE_TYPE, None)
            try:
                while not done:
                    chunk = self._read_some(resp, sock, deadline)
                    if not chunk:
                        break
                    pending += chunk
                    if total + len(pending) > cfg.max_response_bytes:
                        raise Reject(502, "model response exceeded size cap")
                    *lines, pending = pending.split(b"\n")
                    for line in lines:
                        line = line.strip()
                        if not line.startswith(b"data:"):
                            dropped += bool(line)  # comments, event:/id:/retry: fields are not forwarded
                            continue
                        data = line[5:].strip()
                        if data == b"[DONE]":
                            emit(b"data: [DONE]\n\n")
                            done = True
                            break
                        try:
                            payload, out = canonical(data)
                        except (ValueError, RecursionError):
                            raise Reject(502, "model sandbox sent a malformed stream event") from None
                        if not isinstance(payload, dict):
                            raise Reject(502, "model sandbox sent a malformed stream event")
                        if scanner.has_tool_calls(payload) and not cfg.allow_tools:
                            raise Reject(502, "model emitted tool calls while gateway.allow_tools = false")
                        delta = scanner.extract_text(payload)
                        tools.extend(scanner.tool_call_names(payload))
                        if cfg.log_content:
                            text.append(delta)
                        if cfg.scanner != "off":
                            new = stream_scan.feed(delta)
                            if hold and scanner.blocking(new):
                                raise Reject(502, "completion blocked by silo output policy")
                        emit(b"data: " + out + b"\n\n")
            finally:
                entry.update(resp_bytes=total, resp_sha256=digest.hexdigest(), dropped_lines=dropped,
                             findings=[f.as_dict() for f in stream_scan.findings], tool_calls=sorted(set(tools)))
                if cfg.log_content:
                    entry["response_text"] = "".join(text)
            entry["status"] = 200
            if hold:
                self._audit(entry)
                self._send(200, SSE_TYPE, None)
                self._write(b"".join(held))
            else:
                self._audit(entry)

    return Handler


def serve(cfg: Config, socket_path: Path | None = None) -> None:
    gw = Gateway(cfg, socket_path)
    srv = gw.server()
    host, port = srv.server_address[:2]
    shown = f"[{host}]" if ":" in host else host
    print(f"silo[{cfg.name}] gateway on http://{shown}:{port}/v1  ->  {gw.socket_path}", file=sys.stderr)
    print(f"silo[{cfg.name}] scanner={cfg.gateway.scanner} tools={'allowed' if cfg.gateway.allow_tools else 'refused'}"
          f" audit={gw.audit.path}", file=sys.stderr, flush=True)
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
