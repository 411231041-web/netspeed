"""A local HTTP forward proxy used to exercise ``--proxy`` in tests.

The proxy understands both forms a client can send it: the absolute
form of a plain ``http://`` request and the ``CONNECT`` method of a
tunnel. It logs what it saw, answers ``CONNECT`` with ``200`` and then
pipes bytes in both directions, and forwards plain requests to the
origin it names in the request line.
"""

from __future__ import annotations

import socket
import threading
from dataclasses import dataclass, field
from urllib.parse import urlsplit

_RECV_TIMEOUT = 5.0
"""Seconds a client or origin leg may stay silent before it is dropped."""

_TUNNEL_BUFFER = 65536
"""Bytes one ``recv`` of a tunnelled connection may carry."""


@dataclass
class ForwardProxy:
    """A running forward proxy together with its interaction log.

    Attributes:
        base_url: Origin of the proxy, for example
            ``http://127.0.0.1:43210``.
        plain_requests: First request line of every plain
            (absolute-form) request it received, in arrival order.
        connects: Target authority of every ``CONNECT`` request, in
            arrival order.
        httpd: The listening socket.
        thread: Thread running the accept loop.
    """

    base_url: str
    plain_requests: list[str] = field(default_factory=list)
    connects: list[str] = field(default_factory=list)
    httpd: socket.socket | None = None
    thread: threading.Thread | None = None

    def stop(self) -> None:
        """Close the listening socket and wait for the accept loop.

        Returns:
            None.
        """
        if self.httpd is not None:
            self.httpd.close()
        if self.thread is not None:
            self.thread.join(timeout=5)


def _serve_plain(
    conn: socket.socket,
    first_line: str,
    raw_headers: str,
    initial_body: bytes,
    log: list[str],
) -> None:
    """Forward one absolute-form request to the origin it names.

    Args:
        conn: Connection to the client, answered with the response.
        first_line: Request line naming the absolute URL.
        raw_headers: Header block after the request line, without the
            terminating blank line.
        initial_body: Bytes of the request body already received.
        log: List the request line is appended to.

    Returns:
        None.
    """
    log.append(first_line)
    target = urlsplit(first_line.split()[1])
    hop_by_hop = ("connection:", "proxy-", "keep-alive:", "te:")
    headers = [
        line
        for line in raw_headers.split("\r\n")
        if not line.lower().startswith(hop_by_hop)
    ]
    headers.append("Connection: close")
    request = (
        f"GET {target.path or '/'} HTTP/1.1\r\n"
        + "\r\n".join(headers)
        + "\r\n\r\n"
    )
    upstream = socket.create_connection(
        (target.hostname, target.port or 80),
        timeout=_RECV_TIMEOUT,
    )
    try:
        upstream.sendall(request.encode("latin-1") + initial_body)
        response = b""
        while True:
            piece = upstream.recv(_TUNNEL_BUFFER)
            if not piece:
                break
            response += piece
        conn.sendall(response)
    finally:
        upstream.close()


def _serve_tunnel(
    conn: socket.socket,
    first_line: str,
    log: list[str],
) -> None:
    """Answer a ``CONNECT`` request and pipe both directions blind.

    Args:
        conn: Connection to the client, which speaks TLS or HTTP after
            the ``200`` greeting.
        first_line: Request line naming ``host:port``.
        log: List the target authority is appended to.

    Returns:
        None.
    """
    authority = first_line.split()[1]
    log.append(authority)
    host, port = authority.rsplit(":", 1)
    upstream = socket.create_connection(
        (host, int(port)),
        timeout=_RECV_TIMEOUT,
    )
    conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")

    def pipe(source: socket.socket, sink: socket.socket) -> None:
        try:
            while True:
                piece = source.recv(_TUNNEL_BUFFER)
                if not piece:
                    break
                sink.sendall(piece)
        except OSError:
            pass
        finally:
            try:
                sink.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    to_origin = threading.Thread(target=pipe, args=(conn, upstream))
    to_client = threading.Thread(target=pipe, args=(upstream, conn))
    to_origin.start()
    to_client.start()
    to_origin.join()
    to_client.join()
    upstream.close()


def _serve_client(
    conn: socket.socket,
    plain_log: list[str],
    connect_log: list[str],
) -> None:
    """Handle one accepted client connection.

    Args:
        conn: The accepted socket.
        plain_log: Log of absolute-form request lines.
        connect_log: Log of ``CONNECT`` authorities.

    Returns:
        None.
    """
    try:
        conn.settimeout(_RECV_TIMEOUT)
        data = b""
        while b"\r\n\r\n" not in data:
            piece = conn.recv(_TUNNEL_BUFFER)
            if not piece:
                return
            data += piece
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        body = data.split(b"\r\n\r\n", 1)[1]
        first_line = head.split("\r\n")[0]
        headers = "\r\n".join(head.split("\r\n")[1:])
        if first_line.startswith("CONNECT "):
            _serve_tunnel(conn, first_line, connect_log)
        else:
            _serve_plain(conn, first_line, headers, body, plain_log)
    except OSError:
        pass
    finally:
        conn.close()


def start_proxy(host: str = "127.0.0.1", port: int = 0) -> ForwardProxy:
    """Start a forward proxy on a loopback port.

    Args:
        host: Interface to bind.
        port: Port to bind, zero to let the operating system choose.

    Returns:
        The started proxy. The caller is responsible for calling
        :meth:`ForwardProxy.stop`.
    """
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, port))
    listener.listen(16)
    proxy = ForwardProxy(base_url=f"http://{host}:{listener.getsockname()[1]}")
    proxy.httpd = listener

    def accept_loop() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:
                return
            worker = threading.Thread(
                target=_serve_client,
                args=(conn, proxy.plain_requests, proxy.connects),
                daemon=True,
            )
            worker.start()

    proxy.thread = threading.Thread(target=accept_loop, daemon=True)
    proxy.thread.start()
    return proxy


def main() -> int:
    """Serve the proxy until interrupted.

    Returns:
        Zero once the proxy stops.
    """
    proxy = start_proxy()
    print(f"serving proxy at {proxy.base_url}", flush=True)
    try:
        while True:
            proxy.thread.join(1.0)  # type: ignore[union-attr]
    except KeyboardInterrupt:
        pass
    finally:
        proxy.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
