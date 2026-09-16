"""Pytest fixtures exposing the local test servers and proxies."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from tests.http_proxy import ForwardProxy, start_proxy
from tests.http_server import LocalServer, start_server


@pytest.fixture()
def server() -> Iterator[LocalServer]:
    """Start a local HTTP server on an ephemeral loopback port.

    Yields:
        The running server, whose request log records every received
        path. The server is shut down after the test.
    """
    running = start_server()
    try:
        yield running
    finally:
        running.stop()


@pytest.fixture()
def proxy() -> Iterator[ForwardProxy]:
    """Start a local forward proxy on an ephemeral loopback port.

    Yields:
        The running proxy, whose logs record every plain request line
        and every ``CONNECT`` authority. It is stopped after the test.
    """
    running = start_proxy()
    try:
        yield running
    finally:
        running.stop()


@pytest.fixture()
def payload_url(server: LocalServer) -> str:
    """Return the URL of the 512 KiB endpoint.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/payload``.
    """
    return f"{server.base_url}/payload"


@pytest.fixture()
def small_url(server: LocalServer) -> str:
    """Return the URL of the 1 KiB endpoint.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/small``.
    """
    return f"{server.base_url}/small"


@pytest.fixture()
def empty_url(server: LocalServer) -> str:
    """Return the URL of the endpoint answering with an empty body.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/empty``.
    """
    return f"{server.base_url}/empty"


@pytest.fixture()
def gzip_url(server: LocalServer) -> str:
    """Return the URL of the gzip-encoded endpoint.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/gzip``, which ignores the identity request
        and answers with ``Content-Encoding: gzip``.
    """
    return f"{server.base_url}/gzip"


@pytest.fixture()
def nolength_url(server: LocalServer) -> str:
    """Return the URL of the endpoint without ``Content-Length``.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/nolength``, whose body ends with the
        connection.
    """
    return f"{server.base_url}/nolength"


@pytest.fixture()
def short_url(server: LocalServer) -> str:
    """Return the URL of the endpoint that truncates its body.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/short``, which declares more bytes than it
        sends.
    """
    return f"{server.base_url}/short"


@pytest.fixture()
def framed_url(server: LocalServer) -> str:
    """Return the URL of the chunked-framed endpoint.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/te-and-cl``, which frames its body with
        ``Transfer-Encoding: chunked`` while also declaring a bogus
        ``Content-Length``.
    """
    return f"{server.base_url}/te-and-cl"


@pytest.fixture()
def unframed_url(server: LocalServer) -> str:
    """Return the URL of the non-framing transfer-coding endpoint.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/te-identity``, which declares
        ``Transfer-Encoding: identity`` and no length, so the body ends
        with the connection.
    """
    return f"{server.base_url}/te-identity"


@pytest.fixture()
def coded_url(server: LocalServer) -> str:
    """Return the URL of the coded-transfer-encoding endpoint.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/te-gzip-cl``, which declares
        ``Transfer-Encoding: gzip`` alongside a ``Content-Length``.
    """
    return f"{server.base_url}/te-gzip-cl"


@pytest.fixture()
def missing_url(server: LocalServer) -> str:
    """Return the URL of an endpoint that answers 404.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/missing``.
    """
    return f"{server.base_url}/missing"


@pytest.fixture()
def hostile_url(server: LocalServer) -> str:
    """Return the URL of an endpoint with a hostile coding header.

    Args:
        server: Running local server.

    Returns:
        Absolute URL of ``/hostile-encoding``, whose
        ``Content-Encoding`` carries terminal control characters.
    """
    return f"{server.base_url}/hostile-encoding"
