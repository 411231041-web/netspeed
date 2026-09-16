"""A local HTTP server used as the measurement target in tests."""

from __future__ import annotations

import argparse
import gzip
import socket
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAYLOAD_BYTES = 512 * 1024
"""Body size of ``/payload``, the endpoint used as a large file."""

SMALL_BYTES = 1024
"""Body size of ``/small``, an endpoint whose body is tiny."""

GZIP_BYTES = 64 * 1024
"""Size of the decoded body served by the ``/gzip`` endpoint."""

CLOSE_DELIMITED_BYTES = 4096
"""Body size of ``/nolength``, served without ``Content-Length``."""

SHORT_DECLARED_BYTES = 5000
"""``Content-Length`` announced by ``/short`` while sending fewer."""

SHORT_SENT_BYTES = 100
"""Body bytes ``/short`` actually writes before closing."""

TE_BODY_BYTES = 1024
"""Body size served chunked by ``/te-and-cl``."""

TE_DECLARED_BYTES = 10
"""Bogus ``Content-Length`` sent alongside chunked framing."""

UNFRAMED_TE_BYTES = 2048
"""Body size of ``/te-identity``, which sends no length at all."""

CODED_TE_BYTES = 100
"""Body size of ``/te-gzip-cl``, sent with a coded transfer encoding."""

HOSTILE_ENCODING_BYTES = 1000
"""Body size of ``/hostile-encoding``, which lies about its coding."""

HOSTILE_ENCODING = "gzip\x1b]0;pwned\x07"
"""A ``Content-Encoding`` value carrying terminal control characters."""


@dataclass
class LocalServer:
    """A running local HTTP server together with its request logs.

    Attributes:
        base_url: Origin of the server, for example
            ``http://127.0.0.1:43210``.
        requests_seen: Path of every received request, in arrival order.
        encodings_seen: ``Accept-Encoding`` header of every request, in
            arrival order.
        connections_seen: Client address of every accepted connection;
            one entry per TCP connection, not per request.
        httpd: The underlying server instance.
        thread: Thread running the server's request loop.
    """

    base_url: str
    requests_seen: list[str] = field(default_factory=list)
    encodings_seen: list[str] = field(default_factory=list)
    connections_seen: list[str] = field(default_factory=list)
    httpd: ThreadingHTTPServer | None = None
    thread: threading.Thread | None = None

    def stop(self) -> None:
        """Shut the server down and wait for its thread to finish.

        Returns:
            None.
        """
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)


def _handler_class(
    log: list[str],
    encodings: list[str],
    connections: list[str],
) -> type[BaseHTTPRequestHandler]:
    """Build a request handler that serves the fixed test endpoints.

    Args:
        log: List that receives the path of every handled request.
        encodings: List that receives every request's
            ``Accept-Encoding``.
        connections: List that receives the client address of every
            accepted connection.

    Returns:
        A handler class bound to those lists, serving ``/payload``
        (512 KiB), ``/small`` (1 KiB), ``/empty`` (an empty 200),
        ``/gzip`` (a gzip-encoded 64 KiB body), ``/nolength`` (a
        close-delimited body with no ``Content-Length``), ``/short``
        (fewer bytes than the declared length), and 404 for any other
        path.
    """

    class Handler(BaseHTTPRequestHandler):
        """Serve the fixed test endpoints and record their paths."""

        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            """Record the accepted connection before serving it.

            Returns:
                None.
            """
            super().setup()
            connections.append(str(self.client_address))

        def do_GET(self) -> None:
            """Answer a GET request from the fixed endpoint table.

            Returns:
                None.
            """
            log.append(self.path)
            encodings.append(self.headers.get("Accept-Encoding", ""))
            if self.path == "/payload":
                self._respond(200, b"a" * PAYLOAD_BYTES)
            elif self.path == "/small":
                self._respond(200, b"b" * SMALL_BYTES)
            elif self.path == "/empty":
                self._respond(200, b"")
            elif self.path == "/gzip":
                compressed = gzip.compress(b"c" * GZIP_BYTES)
                self._respond(
                    200,
                    compressed,
                    extra={"Content-Encoding": "gzip"},
                )
            elif self.path == "/nolength":
                self._respond_close_delimited(b"d" * CLOSE_DELIMITED_BYTES)
            elif self.path == "/short":
                self._respond_truncated()
            elif self.path == "/te-and-cl":
                self._respond_chunked_with_length()
            elif self.path == "/te-identity":
                self._respond_unframed_te()
            elif self.path == "/te-gzip-cl":
                self._respond_coded_with_length()
            elif self.path == "/hostile-encoding":
                self._respond(
                    200,
                    b"e" * HOSTILE_ENCODING_BYTES,
                    extra={"Content-Encoding": HOSTILE_ENCODING},
                )
            else:
                self._respond(404, b"not found")

        def _respond(
            self,
            status: int,
            body: bytes,
            extra: dict[str, str] | None = None,
        ) -> None:
            """Write a complete response with an explicit body length.

            A client that stops reading and drops the connection (as the
            error-path tests do) would otherwise raise inside the
            handler and make the test output noisy.

            Args:
                status: HTTP status code to send.
                body: Response body, sent in one piece.
                extra: Additional headers to send.

            Returns:
                None.
            """
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(body)))
                for name, value in (extra or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _respond_close_delimited(self, body: bytes) -> None:
            """Write a 200 response with no ``Content-Length``.

            The body ends when the connection closes, so a client cannot
            verify how many bytes it should have received.

            Args:
                body: Response body, sent in one piece.

            Returns:
                None.
            """
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

        def _respond_truncated(self) -> None:
            """Announce more bytes than are sent, then close.

            Returns:
                None.
            """
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(SHORT_DECLARED_BYTES))
                self.end_headers()
                self.wfile.write(b"e" * SHORT_SENT_BYTES)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

        def _respond_chunked_with_length(self) -> None:
            """Frame the body as chunked while also declaring a length.

            RFC 9112 section 6.3 makes ``Transfer-Encoding``
            authoritative, so the declared length must be ignored by a
            conforming client.

            Returns:
                None.
            """
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(TE_DECLARED_BYTES))
                self.send_header("Transfer-Encoding", "chunked")
                self.end_headers()
                chunk = b"f" * TE_BODY_BYTES
                self.wfile.write(
                    b"%x\r\n" % len(chunk) + chunk + b"\r\n0\r\n\r\n"
                )
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _respond_unframed_te(self) -> None:
            """Declare a transfer coding that does not frame the body.

            ``Transfer-Encoding: identity`` carries no length, so the
            body ends only with the connection and its size cannot be
            verified.

            Returns:
                None.
            """
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Transfer-Encoding", "identity")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"g" * UNFRAMED_TE_BYTES)
            except (BrokenPipeError, ConnectionResetError):
                pass
            self.close_connection = True

        def _respond_coded_with_length(self) -> None:
            """Send a coded transfer encoding together with a length.

            RFC 9112 section 6.3 makes that coding authoritative,
            so a conforming client must not treat the declared length as
            proof that the body arrived whole.

            Returns:
                None.
            """
            try:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(CODED_TE_BYTES))
                self.send_header("Transfer-Encoding", "gzip")
                self.end_headers()
                self.wfile.write(b"h" * CODED_TE_BYTES)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, fmt: str, *args: object) -> None:
            """Suppress the default per-request logging to stderr.

            Args:
                fmt: Format string, ignored.
                *args: Format arguments, ignored.

            Returns:
                None.
            """

    return Handler


class QuietServer(ThreadingHTTPServer):
    """A test server that stays silent when a client vanishes."""

    def handle_error(
        self,
        request: socket.socket | tuple[bytes, socket.socket],
        client_address: tuple[str, int],
    ) -> None:
        """Report a failed request, ignoring a dropped connection.

        A client that resets the connection while the request line is
        being read reaches this hook, and the default implementation
        prints a traceback the tests do not want.

        Args:
            request: Socket the failed request arrived on.
            client_address: Address of the client.

        Returns:
            None.
        """
        _, error, _ = sys.exc_info()
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


def start_server(host: str = "127.0.0.1", port: int = 0) -> LocalServer:
    """Start an HTTP server on a loopback port.

    Args:
        host: Interface to bind.
        port: Port to bind, zero to let the operating system choose.

    Returns:
        The started server, with ``httpd`` and ``thread`` populated. The
        caller is responsible for calling :meth:`LocalServer.stop`.
    """
    log: list[str] = []
    encodings: list[str] = []
    connections: list[str] = []
    httpd = QuietServer(
        (host, port),
        _handler_class(log, encodings, connections),
    )
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    bound_host, bound_port = httpd.server_address[:2]
    return LocalServer(
        base_url=f"http://{str(bound_host)}:{bound_port}",
        requests_seen=log,
        encodings_seen=encodings,
        connections_seen=connections,
        httpd=httpd,
        thread=thread,
    )


def main(argv: list[str] | None = None) -> int:
    """Serve the test endpoints until interrupted.

    Args:
        argv: Command-line arguments, defaulting to ``sys.argv``.

    Returns:
        Zero once the server stops.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="interface to bind (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="port to bind, 0 for any free port (default: 0)",
    )
    options = parser.parse_args(argv)
    server = start_server(options.host, options.port)
    print(f"serving {server.base_url}/payload", flush=True)
    thread = server.thread
    try:
        while thread is not None and thread.is_alive():
            thread.join(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
