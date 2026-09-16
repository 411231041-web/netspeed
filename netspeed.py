#!/usr/bin/env python3
"""Measure download speed with sequential HTTP GET requests.

The script fetches one URL a configurable number of times, keeps a
single TCP/TLS connection open through a reuse of
``requests.Session``, and reports the mean, median, and spread of the
achieved throughput together with the time to first byte (TTFB).

Throughput is computed over the body transfer only, so a slow handshake
does not distort the speed figure; TTFB is reported separately. The
volume counted is the decoded body size: with ``Accept-Encoding:
identity`` a cooperating server sends it uncompressed, and a server
that compresses anyway is reported with a warning.

The measurement goes directly by default and can be routed through an
explicit ``--proxy``; proxy environment variables are ignored either
way, so the route in force is always the one the invocation names.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import os
import re
import statistics
import sys
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import IO, NoReturn
from urllib.parse import unquote, urlsplit

import requests

CHUNK_SIZE = 64 * 1024
"""Default read size used while draining a response body, in bytes."""

MAX_CHUNK_SIZE = 16 * 1024 * 1024
"""Largest accepted ``--chunk-size``, in bytes."""

MAX_RUNS = 1000
"""Largest accepted ``--runs`` value."""

MAX_TIMEOUT = 3600.0
"""Largest accepted ``--timeout``, in seconds."""

MIB = 1024**2
"""Bytes in one mebibyte, the unit reported as MiB/s."""

MBIT = 1000**2
"""Bits in one megabit, the unit reported as Mbit/s."""

_UNSIGNED_INT = re.compile(r"[0-9]+")
_UNSIGNED_FLOAT = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)")
_PORT_RULE = "the URL port must be a number between 1 and 65535"
_NUMBER_SHELL = re.compile(r"[0-9._+\- ]*")
"""Characters a mistyped number can be made of, for ``_snippet``.

A rejected value is only echoed when every one of its characters could
have been part of the number the validator asked for; ``1_0`` and
``" 3 "`` are therefore shown, while a credential is not.
"""

_MAX_ARG_DIGITS = 9
"""Digit cap keeping ``int()`` clear of CPython's limit."""

_SCHEME_NAME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")
"""Matches the scheme of a URL, and nothing else.

The pattern is anchored with ``fullmatch`` where it is used, because a
credential typed in front of ``://`` such as ``alice:pw://host`` looks
like a scheme to ``str.partition`` but must never be treated as one.
"""

_MAX_DECODE_ROUNDS = 8
"""Times percent escapes are resolved before the text is called opaque.

A credential can be encoded more than once, so ``%253A`` has to be
decoded twice. Real spellings nest once or twice; a text that still
changes after this many rounds is treated as carrying a delimiter
rather than as clean, which keeps the failure closed.
"""

logger = logging.getLogger("netspeed")


class MeasurementError(RuntimeError):
    """Base class for responses that cannot be measured reliably.

    Such a failure aborts the whole series: a run that cannot be trusted
    must not enter the average or the spread.
    """


class EmptyBodyError(MeasurementError):
    """Raised when a response carried no body to measure."""


class BodySizeMismatchError(MeasurementError):
    """Raised when the received size contradicts the declared one."""


class UnmeasurableRunError(MeasurementError):
    """Raised when a run recorded no elapsed time to divide by."""


@dataclass(frozen=True)
class RunResult:
    """Outcome of a single measured GET request.

    Attributes:
        index: One-based number of the run.
        bytes_downloaded: Decoded body bytes received for this run.
        ttfb_s: Seconds from request start to the response headers.
        body_s: Seconds from the response headers to the last body byte.
        declared_bytes: ``Content-Length`` sent by the server, or
            ``None`` when the server sent none.
        verified: Whether the received size was established, by a
            declared length or by chunked framing; false when neither
            applies and when the body was content-decoded.
    """

    index: int
    bytes_downloaded: int
    ttfb_s: float
    body_s: float
    declared_bytes: int | None = None
    verified: bool = False

    @property
    def total_s(self) -> float:
        """Return the full request duration in seconds.

        Returns:
            The time to the response headers plus the body transfer
            time.
        """
        return self.ttfb_s + self.body_s

    @property
    def measured_s(self) -> float:
        """Return the time used as the throughput denominator.

        Returns:
            The body transfer time when it is measurable, otherwise the
            full request duration, so that a body arriving with the
            headers cannot produce an unbounded speed.

        Raises:
            UnmeasurableRunError: Both phases are zero, so no speed can
                be derived.
        """
        if self.body_s > 0.0:
            return self.body_s
        if self.total_s > 0.0:
            return self.total_s
        raise UnmeasurableRunError("run recorded no elapsed time")

    @property
    def mib_per_s(self) -> float:
        """Return the throughput of this run in mebibytes per second.

        Returns:
            Received size divided by the measured time.

        Raises:
            UnmeasurableRunError: The run has no elapsed time.
        """
        return self.bytes_downloaded / MIB / self.measured_s

    @property
    def mbit_per_s(self) -> float:
        """Return the throughput of this run in megabits per second.

        Returns:
            Received size in bits divided by the measured time.

        Raises:
            UnmeasurableRunError: The run has no elapsed time.
        """
        return self.bytes_downloaded * 8 / MBIT / self.measured_s


@dataclass(frozen=True)
class Summary:
    """Aggregated statistics over the measured runs.

    Attributes:
        runs: Number of runs included in the statistics.
        bytes_downloaded: Total body bytes received across all runs.
        mean_mib_per_s: Arithmetic mean of the per-run speeds, in MiB/s.
        aggregate_mib_per_s: Total bytes divided by total body time, in
            MiB/s; this is the pooled rate, which differs from the mean
            of the per-run rates when the runs moved different volumes.
        median_mib_per_s: Median throughput in MiB/s.
        min_mib_per_s: Lowest per-run throughput in MiB/s.
        max_mib_per_s: Highest per-run throughput in MiB/s.
        stdev_mib_per_s: Sample standard deviation in MiB/s, or ``None``
            when fewer than two runs were measured.
        mean_ttfb_s: Arithmetic mean time to first byte in seconds.
        mean_body_s: Arithmetic mean body transfer time in seconds.
        mean_total_s: Arithmetic mean full request time in seconds, the
            average request time of the task statement.
        unverified_runs: Number of runs whose size could not be checked,
            because no usable ``Content-Length`` was sent, the body was
            content-decoded, or a transfer coding did not frame it.
    """

    runs: int
    bytes_downloaded: int
    mean_mib_per_s: float
    aggregate_mib_per_s: float
    median_mib_per_s: float
    min_mib_per_s: float
    max_mib_per_s: float
    stdev_mib_per_s: float | None
    mean_ttfb_s: float
    mean_body_s: float
    mean_total_s: float
    unverified_runs: int


def _snippet(text: str) -> str:
    """Return a short, credential-free rendering of a rejected value.

    The value was rejected by a validator, so the tool is about to
    repeat a string the user typed. A value that could be the number the
    validator wanted is echoed, because it explains the error; any other
    value is withheld, because the message already names the option and
    the rule, while a credential typed as a value has nothing else to
    give away. Redaction runs before the truncation, so a password cut
    in half by the length limit cannot survive either.

    Args:
        text: Raw argument text.

    Returns:
        At most 20 characters of the text, or ``***`` when the text
        cannot be a number, with any userinfo replaced by ``***``.
    """
    if not _NUMBER_SHELL.fullmatch(text):
        return "***"
    return redact_argument(text)[:20]


def _unsigned_digits(text: str, name: str) -> int:
    """Parse a strictly decimal, unsigned command-line integer.

    The check rejects values ``int()`` would otherwise accept, such as
    ``1_0``, ``" 3 "`` or ``+5``. Leading zeros are padding, not value,
    so they are stripped before the length limit; the digits handed to
    ``int()`` are therefore never more than ``_MAX_ARG_DIGITS`` long.

    Args:
        text: Raw argument text.
        name: Argument name used in the error message.

    Returns:
        The parsed value.

    Raises:
        argparse.ArgumentTypeError: The text is not a run of digits, or
            has more digits than any accepted value.
    """
    if _UNSIGNED_INT.fullmatch(text) is None:
        raise argparse.ArgumentTypeError(
            f"{name} must be a whole number, got {_snippet(text)!r}"
        )
    digits = text.lstrip("0") or "0"
    if len(digits) > _MAX_ARG_DIGITS:
        raise argparse.ArgumentTypeError(
            f"{name} is out of range: {_snippet(text)}"
        )
    return int(digits)


def run_count(text: str) -> int:
    """Convert ``--runs`` text into a number of measured requests.

    Args:
        text: Raw argument text.

    Returns:
        The number of runs, between 1 and ``MAX_RUNS``.

    Raises:
        argparse.ArgumentTypeError: The text is not a whole number in
            range.
    """
    value = _unsigned_digits(text, "runs")
    if not 1 <= value <= MAX_RUNS:
        raise argparse.ArgumentTypeError(
            f"runs must be between 1 and {MAX_RUNS}, got {value}"
        )
    return value


def chunk_size_bytes(text: str) -> int:
    """Convert ``--chunk-size`` text into a body read size.

    Args:
        text: Raw argument text.

    Returns:
        The read size in bytes, between 1 and ``MAX_CHUNK_SIZE``.

    Raises:
        argparse.ArgumentTypeError: The text is not a whole number in
            range.
    """
    value = _unsigned_digits(text, "chunk size")
    if not 1 <= value <= MAX_CHUNK_SIZE:
        raise argparse.ArgumentTypeError(
            f"chunk size must be between 1 and {MAX_CHUNK_SIZE} bytes, "
            f"got {_snippet(text)!r}"
        )
    return value


def timeout_seconds(text: str) -> float:
    """Convert ``--timeout`` text into a finite positive duration.

    Nan, infinity, and values far beyond any usable budget are rejected
    here, because they surface later as platform errors from the socket
    layer instead of a readable argument error.

    Args:
        text: Raw argument text.

    Returns:
        The timeout in seconds, greater than zero and at most
        ``MAX_TIMEOUT``.

    Raises:
        argparse.ArgumentTypeError: The text is not a plain decimal
            number, or is outside the accepted range.
    """
    if _UNSIGNED_FLOAT.fullmatch(text) is None:
        raise argparse.ArgumentTypeError(
            "timeout must be a plain decimal number of seconds, "
            f"got {_snippet(text)!r}"
        )
    value = float(text)
    if not math.isfinite(value) or not 0.0 < value <= MAX_TIMEOUT:
        raise argparse.ArgumentTypeError(
            f"timeout must be greater than 0 and at most {MAX_TIMEOUT}, "
            f"got {_snippet(text)!r}"
        )
    return value


def validate_url(url: str) -> str:
    """Check that a URL is usable for an HTTP download measurement.

    Only ``http`` and ``https`` are accepted, so an accidental
    ``file://`` or ``ftp://`` argument fails before any request is made.

    Args:
        url: Candidate URL.

    Returns:
        The URL unchanged when it is valid.

    Raises:
        ValueError: The argument cannot be parsed, its scheme is not
        HTTP(S), its host is missing, or its authority is not a
        literal host with an optional port in ``1..65535``. That
        authority test is the one the redactor uses, so a literal
        malformed authority is refused here as well as hidden there.
        Percent-encoded text is judged as typed here and as decoded
        there, so a text the redactor hides whole can still be a URL
        that is requested; the other texts it hides, such as a colon
        outside the authority, are legal URLs and are measured. No
        message echoes the argument, because a scheme-less credential
        such as ``alice:secret@host/x`` parses as a scheme named
        after the user.
    """
    try:
        parsed = urlsplit(url)
    except ValueError as exc:
        raise ValueError("the URL could not be parsed") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("unsupported scheme; use http or https")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("URL has no host")
    rest = url.partition("://")[2]
    authority = rest[: _authority_end(rest)]
    if _has_unusable_port(authority.rpartition("@")[2]):
        raise ValueError(_PORT_RULE)
    return url


def _is_port(text: str) -> bool:
    """Report whether text is a usable port number.

    Leading zeros are padding, as they are for the numeric options, so
    ``065535`` is the port 65535. The zeros are stripped before the
    digit count, which keeps ``int()`` clear of its digit limit and
    keeps the value, not the spelling, the thing that is judged.

    Args:
        text: Candidate port.

    Returns:
        True when the text is all ASCII digits and its value lies in
        ``1..65535``. ASCII is required because ``str.isdigit`` also
        accepts characters such as ``²`` that ``int()`` rejects.
    """
    if not text.isascii() or not text.isdigit():
        return False
    digits = text.lstrip("0") or "0"
    return len(digits) <= 5 and 1 <= int(digits) <= 65535


def _decode_escapes(text: str) -> tuple[str, bool]:
    """Resolve percent escapes as far as they are nested.

    A credential can be encoded more than once, so ``%253A`` reaches the
    checks as ``%3A`` and needs a second round. This is the only place a
    decoded text is produced; callers use it to decide, and print text
    taken from the argument, so a decoded newline cannot reach a log.

    Args:
        text: Text that may be percent-encoded, once or repeatedly.

    Returns:
        The decoded text, and whether the round cap stopped the decoding
        while escapes were still being resolved.
    """
    candidate = text
    for _ in range(_MAX_DECODE_ROUNDS):
        if "%" not in candidate:
            return candidate, False
        decoded = unquote(candidate)
        if decoded == candidate:
            return candidate, False
        candidate = decoded
    return candidate, True


def _has_unusable_port(authority: str) -> bool:
    """Report whether an authority cannot be a host with a port.

    A host whose port is not numeric, such as ``http://alice:pa``, one
    whose port is outside ``1..65535``, such as ``alice:987654``, one
    with a colon and no port at all, and an authority holding more than
    one colon, such as ``alice:pw:8080``, are all malformed rather than
    real targets; each is what a truncated ``user:password`` looks like
    once its at sign is gone. An IPv6 literal is accepted in brackets,
    followed by at most one valid port, so a credential cannot hide
    behind the brackets that make the colon checks meaningless.

    Args:
        authority: Host and optional port, without userinfo.

    Returns:
        True when the authority is not a bare host or a host followed by
        one port number.
    """
    if authority.startswith("["):
        _, bracket, suffix = authority.partition("]")
        if not bracket or not suffix:
            return not bracket
        return not (suffix.startswith(":") and _is_port(suffix[1:]))
    if ":" not in authority:
        return False
    host, _, port = authority.rpartition(":")
    if not host or authority.count(":") > 1:
        return True
    return not _is_port(port)


def _has_delimiter(text: str) -> bool:
    """Report whether text holds a credential delimiter.

    A colon or an at sign is the delimiter of a ``user:password`` pair.
    Percent-encoded spellings count too, including a double-encoded one,
    so that ``alice%3ASECRETpw%40host`` is recognised as a credential
    rather than printed verbatim. A text that keeps changing as escapes
    are resolved counts as well, because the delimiter cannot be ruled
    out.

    Args:
        text: Raw argument text.

    Returns:
        True when the text, after its escapes are resolved, holds a
        colon or an at sign, or when it carries escapes that do not
        settle within the round cap.
    """
    decoded, capped = _decode_escapes(text)
    if ":" in decoded or "@" in decoded:
        return True
    return capped


def _redact_unstructured(text: str) -> str:
    """Hide a credential that carries no usable scheme.

    Args:
        text: Raw argument text whose prefix is not a scheme.

    Returns:
        ``***`` when the text holds a credential delimiter, decoded or
        not, since either can be what is left of a ``user:password``
        after its host was lost, and the text unchanged otherwise.
    """
    if _has_delimiter(text):
        return "***"
    return text


def _hides_nothing(rest: str) -> bool:
    """Report whether the part of a URL after its scheme is clean.

    Args:
        rest: Text after ``scheme://``, with any userinfo already
            removed.

    Returns:
        True when the text carries no whitespace and no credential
        delimiter outside an authority that is a host with an optional
        valid port. Text whose escapes do not settle within the round
        cap is not clean, because a delimiter cannot be ruled out.
    """
    if any(character.isspace() for character in rest):
        return False
    decoded, capped = _decode_escapes(rest)
    if capped or "@" in decoded:
        return False
    authority = decoded.split("/", 1)[0]
    authority = authority.split("?", 1)[0].split("#", 1)[0]
    if _has_unusable_port(authority):
        return False
    return ":" not in decoded[len(authority) :]


def _authority_end(rest: str) -> int:
    """Return the index where the authority of a URL remainder ends.

    Args:
        rest: Text after ``scheme://``.

    Returns:
        The length of the text when it carries no path, query, or
        fragment delimiter, and the index of the first one otherwise.
    """
    for index, character in enumerate(rest):
        if character in "/?#":
            return index
    return len(rest)


_PROXY_SCHEMES = ("http", "https", "socks4", "socks4a", "socks5", "socks5h")
"""Proxy URL schemes this tool accepts.

``http`` and ``https`` proxies work with ``requests`` alone; the SOCKS
family needs the ``PySocks`` package installed, which the option names
in its help so a refusal by the transport explains itself.
"""

_LOCAL_DNS_SOCKS = {"socks4": "socks4a", "socks5": "socks5h"}
"""Client-resolving SOCKS schemes mapped to their remote-DNS siblings.

``socks5h`` and ``socks4a`` exist because a name resolved on this
machine can strand the proxy with an address worthless from its own
vantage point: a CDN picks an edge for this network, while the proxy
must reach the file from elsewhere. When a run behind one of these
spellings dies on a timeout, the failure points at the sibling.
"""


def _remote_dns_scheme(proxy: str) -> str | None:
    """Name the sibling scheme that pushes hostname lookup to the proxy.

    Args:
        proxy: Proxy URL as validated by :func:`validate_proxy`.

    Returns:
        The remote-resolving scheme name such as ``socks5h``, or
        ``None`` when the spelling is not a client-resolving SOCKS one.
    """
    scheme = proxy.split("://", 1)[0]
    return _LOCAL_DNS_SOCKS.get(scheme.lower())


def validate_proxy(proxy: str) -> str:
    """Check that a proxy URL is usable for routing the measurement.

    A proxy with a wrong port or no host would only fail later at the
    transport level, where the message would be about a tunnel rather
    than about the argument that caused it, so the same authority rules
    the URL option follows are applied here. A proxy spelled without a
    scheme is read as HTTP, which is the spelling of a bare ``host:
    port``.

    Args:
        proxy: Candidate proxy URL.

    Returns:
        The proxy URL unchanged when it is valid.

    Raises:
        argparse.ArgumentTypeError: The argument cannot be parsed, its
            scheme is not one of ``_PROXY_SCHEMES``, its host is
            missing, or its authority is not a literal host with an
            optional port in ``1..65535``. The same type the other
            validators raise, so ``argparse`` reports the message
            alone and never re-counts the argument with ``%r``, where
            a credential typed in the proxy would be echoed. No
            message echoes the argument, because a scheme-less
            credential such as ``alice:secret@host`` parses as a
            scheme named after the user.
    """
    candidate = f"http://{proxy}" if "://" not in proxy else proxy
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "the proxy could not be parsed"
        ) from exc
    if parsed.scheme not in _PROXY_SCHEMES:
        raise argparse.ArgumentTypeError(
            "unsupported proxy scheme; use http, https, socks5 (or a "
            "neighbouring socks spelling)"
        )
    if not parsed.netloc or not parsed.hostname:
        raise argparse.ArgumentTypeError("the proxy has no host")
    rest = candidate.partition("://")[2]
    authority = rest[: _authority_end(rest)]
    if _has_unusable_port(authority.rpartition("@")[2]):
        raise argparse.ArgumentTypeError(
            "the proxy port must be a number between 1 and 65535"
        )
    return proxy


def apply_proxy(session: requests.Session, proxy: str) -> None:
    """Route every request of a session through one proxy.

    The mapping spells out both schemes, so an ``https://`` target is
    tunnelled through the proxy as well; listing only ``http`` would
    send HTTPS traffic directly, which is the mistake the option exists
    to prevent.

    Args:
        session: Session whose requests are routed.
        proxy: Proxy URL validated beforehand.

    Returns:
        None.
    """
    session.proxies = {"http": proxy, "https": proxy}


@contextmanager
def direct_session() -> Iterator[requests.Session]:
    """Yield a session pinned to a direct, environment-free route.

    The session ignores the ``http_proxy`` family of environment
    variables, because a speed measurement that promised a direct
    connection must not be silently routed through whatever the
    ambient environment names.

    Yields:
        The session with ``trust_env`` disabled.

    Returns:
        None.
    """
    with requests.Session() as session:
        session.trust_env = False
        yield session


@contextmanager
def session_route(
    proxy: str | None,
) -> Iterator[tuple[requests.Session, str | None]]:
    """Open a session routed directly, or through the given proxy.

    This is the one place the session and its routing meet, so the
    caller cannot end up with a session whose trust environment was
    forgotten or whose proxy mapping misses one of the two schemes.

    Args:
        proxy: Validated proxy URL, or ``None`` for a direct route.

    Yields:
        The session and the proxy actually in force, ``None`` when
        direct.

    Returns:
        None.
    """
    with direct_session() as session:
        if proxy is not None:
            apply_proxy(session, proxy)
        yield session, proxy


def redact_url(url: str) -> str:
    """Hide credentials embedded in a URL.

    The report, the JSON payload, and every error message are written to
    terminals and CI logs, so userinfo from the argument must not be
    echoed. The function fails closed: everything between the scheme and
    the last at sign of the authority is replaced, and a URL is redacted
    whole when it carries whitespace, when it carries a credential
    delimiter anywhere outside its authority, when its authority is
    malformed, or when its text is not a URL at all. An at sign outside
    the authority is treated as a credential too, because the module
    reads it as a delimiter elsewhere and the text behind it may be the
    secret half of the pair. The text after a userinfo at sign is
    checked by these same rules, so a password repeated in a path or a
    query cannot ride along behind valid userinfo. Percent escapes are
    resolved to make those decisions, but only text taken from the
    argument itself is ever returned, so a decoded newline cannot reach
    a log line.

    Args:
        url: URL that may carry ``user:password@`` userinfo.

    Returns:
        The URL with any userinfo replaced by ``***``; a URL that holds
        no credential delimiter outside its authority is returned
        unchanged, and one that does is reduced to ``scheme://***``.
        Text whose prefix only looks like a scheme, such as
        ``alice:pw://host``, is redacted wholesale.
    """
    scheme, separator, rest = url.partition("://")
    if not separator or not _SCHEME_NAME.fullmatch(scheme):
        return _redact_unstructured(url)
    at_sign = rest.rfind("@")
    if at_sign == -1:
        return url if _hides_nothing(rest) else f"{scheme}://***"
    if at_sign >= _authority_end(rest):
        return f"{scheme}://***"
    tail = rest[at_sign + 1 :]
    if not _hides_nothing(tail):
        return f"{scheme}://***"
    return f"{scheme}://***@{tail}"


def redact_argument(text: str) -> str:
    """Hide credentials in a raw command-line argument.

    The tool knows the text is one argument rather than prose, so it can
    fail hard: an argument that carries a scheme is redacted like a URL,
    and one without a scheme, including text whose prefix only looks
    like one, is treated as wholly secret as soon as it holds a colon or
    an at sign, percent-encoded or not, because ``user:password`` can be
    typed with no host at all.

    Args:
        text: Raw argument text.

    Returns:
        The text with its credentials replaced by ``***``, or unchanged
        when it carries no scheme and no credential delimiter.
    """
    scheme, separator, _ = text.partition("://")
    if separator and _SCHEME_NAME.fullmatch(scheme):
        return redact_url(text)
    return _redact_unstructured(text)


def redact_text(text: str) -> str:
    """Hide URL credentials that a third-party message embedded.

    Library errors quote the failing URL, so their text needs the same
    treatment as the URL this module prints itself. The function fails
    closed by replacing a whitespace-delimited token whole as soon as it
    holds both a scheme and an at sign: such a token may be a URL with
    userinfo, but it may equally be a URL whose at sign belongs to a
    path, where the text behind that at sign is the secret. A token that
    already carries the redaction marker is left as it stands, because
    this module has redacted it and redacting it again would hide the
    host its own passes kept readable. It recognises a scheme rather
    than a credential, so it is a fallback; the argument paths use
    ``redact_argument``, which hides more.

    Args:
        text: Message that may contain ``scheme://user:password@host``.

    Returns:
        The message with every token that pairs a scheme with an at sign
        replaced by ``***``.
    """
    if "://" not in text or "@" not in text:
        return text
    return " ".join(
        (
            "***"
            if "://" in token and "@" in token and "***" not in token
            else token
        )
        for token in text.split(" ")
    )


def _visible(text: str) -> str:
    """Escape control characters so a message cannot drive a terminal.

    A status reason phrase, a header value, and the URL itself can carry
    bytes a server or the caller chose, and a terminal turns some of
    them into commands. Everything a reader could not see is written as
    its
    escape sequence instead, so one message stays one line.

    Args:
        text: Message text that may carry control characters.

    Returns:
        The text with every character that is not printable replaced by
        its escaped form.
    """
    if text.isprintable():
        return text
    return "".join(
        (
            character
            if character.isprintable()
            else character.encode("unicode_escape").decode("ascii")
        )
        for character in text
    )


def _quotes_credentials(url: str, text: str) -> bool:
    """Report whether text may repeat a credential of the URL.

    A target receives the userinfo of the requested URL as basic
    authentication and can echo it into a header or an error text, so
    every server-supplied string is tested before it is printed. The
    test is deliberately coarse: a URL that needed redaction taints the
    text whole, because a library can quote userinfo without its scheme.

    Args:
        url: URL the text belongs to.
        text: Text a library or a server supplied.

    Returns:
        True when the text must not be printed as it stands.
    """
    if redact_url(url) != url:
        return True
    return any(fragment in text for fragment in _userinfo_fragments(url))


def _server_text(url: str | None, text: str) -> str:
    """Escape server-supplied text, hiding a credential it may quote.

    Args:
        url: URL the text came from, or ``None`` when it is unknown.
        text: Text the server supplied.

    Returns:
        The text with control characters escaped, or a placeholder when
        it could repeat a credential of the URL.
    """
    if url is not None and _quotes_credentials(url, text):
        return "***"
    return _visible(text)


def declared_length(
    response: requests.Response,
    *,
    url: str | None = None,
) -> int | None:
    """Read the body size a response declares.

    Args:
        response: Response whose headers are inspected.
        url: URL the response answered, used to keep the header out of
            the log when it could repeat a credential.

    Returns:
        ``Content-Length`` as a non-negative integer, or ``None`` when
        the header is absent or unusable.
    """
    raw = response.headers.get("Content-Length")
    if raw is None:
        return None
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning(
            "ignoring malformed Content-Length '%s'", _server_text(url, raw)
        )
        return None
    if value < 0:
        logger.warning(
            "ignoring negative Content-Length '%s'", _server_text(url, raw)
        )
        return None
    return value


def check_body_size(
    received: int,
    declared: int | None,
    *,
    comparable: bool,
) -> None:
    """Compare the received body size with the declared one.

    Args:
        received: Body bytes counted while draining the response.
        declared: Value of the ``Content-Length`` header, if usable.
        comparable: Whether ``declared`` describes the counted bytes.
            It does not when content decoding was applied, because the
            header counts compressed bytes, nor when the response is
            framed by ``Transfer-Encoding``, which RFC 9112 section 6.3
            makes authoritative over ``Content-Length``.

    Returns:
        None.

    Raises:
        BodySizeMismatchError: ``declared`` applies and ``received``
            differs from it, so the transfer was cut short or padded.
    """
    if declared is None or not comparable:
        return
    if received != declared:
        raise BodySizeMismatchError(
            f"received {received} of {declared} declared bytes"
        )


def _userinfo_fragments(url: str) -> tuple[str, ...]:
    """Return the credential strings a URL carries.

    The whole prefix before the last at sign is a candidate userinfo,
    including its delimiter-separated pieces, because a library may
    quote only the fragment it choked on.

    Args:
        url: URL that may embed ``user:password@`` userinfo, with or
            without a scheme.

    Returns:
        Every credential fragment found, longest first: the whole
        candidate, its delimiter-separated pieces, and the user and
        password halves of each. Empty when the text carries no at sign.
    """
    _, _, rest = url.partition("://")
    if "@" not in rest:
        rest = url
    if "@" not in rest:
        return ()
    authority, _, _ = rest.rpartition("@")
    if not authority:
        return ()
    fragments: set[str] = set()
    for piece in re.split(r"[/?#]", authority):
        if not piece:
            continue
        fragments.add(piece)
        user, colon, password = piece.partition(":")
        if colon:
            if user:
                fragments.add(user)
            if password:
                fragments.add(password)
    return tuple(sorted(fragments, key=len, reverse=True))


def _transport_failure(
    url: str,
    index: int,
    error: requests.RequestException,
) -> MeasurementError:
    """Describe a failed request without leaking its credentials.

    The exception text is logged at DEBUG for diagnosis, but withheld
    when it repeats a credential fragment of the URL, or when the URL
    itself had to be redacted: libraries can quote userinfo without its
    scheme, which no pattern can recognise, and a malformed authority
    hides a truncated password that the message may carry in full.

    Args:
        url: URL that was being fetched.
        index: One-based run number, or zero for the warm-up request.
        error: Exception raised by the HTTP layer.

    Returns:
        A measurement error whose message names the redacted URL and the
        HTTP status when the server answered one.
    """
    status = ""
    response = getattr(error, "response", None)
    if response is not None:
        status = f"HTTP {response.status_code}: "
    detail = _visible(redact_text(str(error)))
    if _quotes_credentials(url, detail):
        detail = "detail withheld: it quoted URL credentials"
    logger.debug("run %d transport failure: %s", index, detail)
    return MeasurementError(
        _visible(f"{redact_url(url)}: {status}{_failure_kind(error)}")
    )


def _failure_kind(error: requests.RequestException) -> str:
    """Name a transport failure in terms a reader can act on.

    The exception class alone is accurate but silent about the cause a
    reader cares about: an idle socket, an unreachable host, and a short
    response all surface as generic connection errors. The cause is
    taken from the class wherever the class carries it, so a proxy or
    TLS failure keeps its own name even when its text mentions a
    timeout; only the bare ``ConnectionError`` that the HTTP layer
    raises for a stalled body needs its text consulted. A ``ProxyError``
    gets two different readings: ``urllib3`` folds a refusal at the
    proxy's port and a rejection of a ``CONNECT`` tunnel into the same
    class, so the exception chain is searched for the tunnel-rejection
    wording to tell a wrong-spelling mistake (routing SOCKS traffic at
    an http proxy URL) from an unreachable helper.

    Args:
        error: Exception raised by the HTTP layer.

    Returns:
        The exception class name, with the likely cause appended when
        the class does not carry it.
    """
    kind = type(error).__name__
    if isinstance(error, requests.ConnectTimeout):
        return f"{kind} (timed out while connecting to the host)"
    if isinstance(error, requests.exceptions.InvalidSchema):
        return f"{kind} (a socks proxy needs the PySocks package)"
    if isinstance(error, requests.exceptions.ProxyError):
        causes: list[BaseException] = []
        seen: set[int] = set()
        nested: BaseException | None = error.args[0] if error.args else None
        while isinstance(nested, BaseException) and id(nested) not in seen:
            seen.add(id(nested))
            causes.append(nested)
            nested = nested.__context__
        if any("tunnel connection failed" in str(c).lower() for c in causes):
            # urllib3 speaks for the proxy here; the text is a safe
            # template ("Tunnel connection failed: <code>") rather than
            # arbitrary remote input, yet quoting it wholesale would
            # still undercut the redaction contract, so only its shape
            # is named.
            return f"{kind} (the proxy refused the CONNECT tunnel)"
        return f"{kind} (the proxy is unreachable or refused the connection)"
    if isinstance(error, requests.exceptions.ChunkedEncodingError):
        return f"{kind} (the response ended before its declared size)"
    if type(error) is requests.ConnectionError:
        if "timed out" in str(error):
            return (
                f"{kind} (timed out waiting for the response headers "
                "or body)"
            )
        return f"{kind} (the host is unreachable or refused the connection)"
    if isinstance(error, requests.Timeout):
        return f"{kind} (timed out waiting for the response headers or body)"
    return kind


def measure_once(
    session: requests.Session,
    url: str,
    index: int,
    *,
    chunk_size: int = CHUNK_SIZE,
    timeout: float = 15.0,
) -> RunResult:
    """Fetch a URL once and time its header and body phases.

    The body is drained in ``chunk_size`` pieces and never held in
    memory as a whole. ``Accept-Encoding: identity`` is requested, and
    the received size is checked against ``Content-Length`` when the
    server sends one and neither content decoding nor
    ``Transfer-Encoding`` framing makes that header inapplicable.

    Args:
        session: Session whose connection pool is reused across runs.
        url: Absolute http(s) URL to fetch.
        index: One-based run number stored in the result.
        chunk_size: Read size for draining the body, in bytes.
        timeout: Per-request socket timeout in seconds, applied to the
            connection attempt and to each read, so it is an inactivity
            limit rather than a total deadline.

    Returns:
        The measured run, with ``declared_bytes`` set whenever the
        server sent a ``Content-Length`` and ``verified`` telling
        whether the received size was established, by that header or by
        chunked framing.

    Raises:
        MeasurementError: The request failed at the transport level, the
            server answered with a 4xx/5xx status, the body was empty,
            or the received size contradicted the declared one. The
            message names the URL with any credentials redacted.
    """
    started = time.perf_counter()
    try:
        with session.get(
            url,
            stream=True,
            timeout=timeout,
            headers={"Accept-Encoding": "identity"},
        ) as response:
            response.raise_for_status()
            ttfb_s = time.perf_counter() - started
            encoding = response.headers.get("Content-Encoding", "").lower()
            framing = response.headers.get("Transfer-Encoding", "").strip()
            declared = declared_length(response, url=url)
            received = 0
            for chunk in response.iter_content(chunk_size=chunk_size):
                received += len(chunk)
            body_s = time.perf_counter() - started - ttfb_s
    except requests.RequestException as exc:
        raise _transport_failure(url, index, exc) from None
    decoded = encoding not in {"", "identity"}
    codings = [
        part.strip().lower() for part in framing.split(",") if part.strip()
    ]
    chunk_framed = bool(codings) and codings[-1] == "chunked"
    length_checked = not decoded and not codings and declared is not None
    check_body_size(
        received,
        declared,
        comparable=not decoded and not codings,
    )
    if received == 0:
        raise EmptyBodyError(
            _visible(f"{redact_url(url)} returned an empty body")
        )
    size_established = chunk_framed or length_checked
    if decoded:
        logger.warning(
            "run %d: Content-Encoding '%s'; counted %d decoded bytes, "
            "which is more than the compressed transfer",
            index,
            _server_text(url, encoding),
            received,
        )
    elif not size_established:
        transfer = f"'{_server_text(url, framing)}'" if framing else "missing"
        logger.warning(
            "run %d: the received size cannot be verified "
            "(Content-Length %s, Transfer-Encoding %s)",
            index,
            declared if declared is not None else "missing",
            transfer,
        )
    logger.debug(
        "run %d: %d bytes, ttfb %.3fs, body %.3fs",
        index,
        received,
        ttfb_s,
        body_s,
    )
    return RunResult(
        index,
        received,
        ttfb_s,
        body_s,
        declared,
        verified=not decoded and size_established,
    )


def run_series(
    session: requests.Session,
    url: str,
    runs: int,
    *,
    chunk_size: int = CHUNK_SIZE,
    timeout: float = 15.0,
    warmup: bool = True,
) -> list[RunResult]:
    """Fetch a URL sequentially and collect the measured runs.

    Args:
        session: Session whose connection pool is reused across runs.
        url: Absolute http(s) URL to fetch.
        runs: Number of measured runs, at least one.
        chunk_size: Read size for draining a body, in bytes.
        timeout: Per-request socket timeout in seconds.
        warmup: Whether to send one discarded request first, so DNS
            resolution and the TLS handshake do not land in the sample.

    Returns:
        The measured runs in execution order; the warm-up request is not
        part of the list.

    Raises:
        ValueError: ``runs`` is less than one, which is a programming
            error because the CLI itself rejects such a value.
        MeasurementError: A request failed or a response could not be
            measured reliably; the series is aborted instead of
            reporting a partial average.
    """
    if runs < 1:
        raise ValueError("runs must be at least 1")
    if warmup:
        logger.info("warm-up request (excluded from statistics)")
        measure_once(
            session,
            url,
            0,
            chunk_size=chunk_size,
            timeout=timeout,
        )
    results: list[RunResult] = []
    for index in range(1, runs + 1):
        result = measure_once(
            session,
            url,
            index,
            chunk_size=chunk_size,
            timeout=timeout,
        )
        results.append(result)
        logger.info(
            "run %d/%d: %.2f MiB/s (%.1f Mbit/s)",
            index,
            runs,
            result.mib_per_s,
            result.mbit_per_s,
        )
    return results


def summarize(results: Sequence[RunResult]) -> Summary:
    """Aggregate per-run results into the reported statistics.

    Args:
        results: Non-empty sequence of measured runs.

    Returns:
        Mean, pooled, median, and extreme throughputs, the spread, mean
        phase and total timings, the total bytes received, and how many
        runs had no verifiable size.

    Raises:
        ValueError: ``results`` is empty.
        UnmeasurableRunError: A run recorded no elapsed time.
    """
    if not results:
        raise ValueError("cannot summarize an empty result set")
    speeds = [result.mib_per_s for result in results]
    total_bytes = sum(result.bytes_downloaded for result in results)
    pooled_s = sum(result.measured_s for result in results)
    return Summary(
        runs=len(results),
        bytes_downloaded=total_bytes,
        mean_mib_per_s=statistics.fmean(speeds),
        aggregate_mib_per_s=total_bytes / MIB / pooled_s,
        median_mib_per_s=statistics.median(speeds),
        min_mib_per_s=min(speeds),
        max_mib_per_s=max(speeds),
        stdev_mib_per_s=(
            statistics.stdev(speeds) if len(speeds) > 1 else None
        ),
        mean_ttfb_s=statistics.fmean(result.ttfb_s for result in results),
        mean_body_s=statistics.fmean(result.body_s for result in results),
        mean_total_s=statistics.fmean(result.total_s for result in results),
        unverified_runs=sum(1 for result in results if not result.verified),
    )


def _mbit(mib_per_s: float) -> float:
    """Convert a mebibyte-per-second rate into megabits per second.

    Args:
        mib_per_s: Rate in MiB/s.

    Returns:
        The equivalent rate in Mbit/s.
    """
    return mib_per_s * MIB * 8 / MBIT


def format_report(
    url: str,
    results: Sequence[RunResult],
    summary: Summary,
    *,
    warmup: bool,
    proxy: str | None = None,
) -> str:
    """Render the human-readable measurement report.

    Any credentials in ``url`` and in ``proxy`` are redacted.

    Args:
        url: Measured URL.
        results: Measured runs in execution order.
        summary: Aggregated statistics of ``results``.
        warmup: Whether a discarded warm-up request was sent.
        proxy: Proxy the requests were routed through, or ``None``
            when they went directly.

    Returns:
        The report text, without a trailing newline.
    """
    head = (
        f"{'#':>3}  {'MiB':>9}  {'TTFB s':>7}  {'body s':>7}  "
        f"{'basis s':>7}  {'MiB/s':>9}  {'Mbit/s':>9}"
    )
    rows = [
        f"{result.index:>3}  "
        f"{result.bytes_downloaded / MIB:>9.2f}  "
        f"{result.ttfb_s:>7.3f}  "
        f"{result.body_s:>7.3f}  "
        f"{result.measured_s:>7.3f}  "
        f"{result.mib_per_s:>9.2f}  "
        f"{result.mbit_per_s:>9.1f}"
        for result in results
    ]
    spread = (
        "n/a (single run)"
        if summary.stdev_mib_per_s is None
        else f"{summary.stdev_mib_per_s:.2f} MiB/s"
    )
    lines = [
        f"URL: {_visible(redact_url(url))}",
        *([] if proxy is None else [f"Proxy: {_visible(redact_url(proxy))}"]),
        f"Runs measured: {summary.runs}"
        + (" (warm-up excluded)" if warmup else ""),
        "",
        head,
        *rows,
        "",
        "Summary",
        f"  total downloaded: {summary.bytes_downloaded} bytes "
        f"({summary.bytes_downloaded / MIB:.2f} MiB)",
        f"  mean TTFB:        {summary.mean_ttfb_s:.3f} s",
        f"  mean body time:   {summary.mean_body_s:.3f} s",
        f"  mean request:     {summary.mean_total_s:.3f} s",
        f"  mean of runs:     {summary.mean_mib_per_s:.2f} MiB/s "
        f"= {_mbit(summary.mean_mib_per_s):.1f} Mbit/s",
        f"  aggregate:        {summary.aggregate_mib_per_s:.2f} MiB/s "
        f"= {_mbit(summary.aggregate_mib_per_s):.1f} Mbit/s "
        "(total bytes / total measured time)",
        f"  median:           {summary.median_mib_per_s:.2f} MiB/s "
        f"= {_mbit(summary.median_mib_per_s):.1f} Mbit/s",
        f"  min / max:        {summary.min_mib_per_s:.2f} / "
        f"{summary.max_mib_per_s:.2f} MiB/s",
        f"  std deviation:    {spread}",
    ]
    if summary.unverified_runs:
        lines.append(
            f"  note:             {summary.unverified_runs} run(s) could "
            "not be size-verified (no usable Content-Length, a decoded "
            "body, or a coding that does not frame the body)"
        )
    return "\n".join(lines)


def configure_logging(verbose: bool) -> None:
    """Attach a fresh stderr handler to this module's logger.

    Handlers installed by an earlier call are detached first, so that
    repeated runs in one process (as in tests) always write to the
    current ``sys.stderr``.

    Args:
        verbose: When true, DEBUG records are emitted as well.

    Returns:
        None.
    """
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(
        logging.Formatter("%(levelname)s: %(message)s")
    )
    logger.addHandler(stream_handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def _is_host_like(text: str) -> bool:
    """Report whether text could be the host of an authority.

    Args:
        text: Text that appeared before a colon.

    Returns:
        True when the text starts with an alphanumeric character and
        carries only characters a host name may hold. An option
        rewritten by ``argparse``, such as ``-alice`` from
        ``-valice:8080``, starts with a dash and is therefore not a
        host.
    """
    if not text or not text[0].isalnum():
        return False
    return all(character.isalnum() or character in ".-_" for character in text)


def _bare(word: str) -> str:
    """Return a message word without the quotes argparse wrapped it in.

    ``argparse`` renders a rejected value between quotes, so the
    argument a word came from appears as ``'value'`` rather than
    ``value`` and has to be unwrapped before it can be matched against
    the argument list.

    Args:
        word: One whitespace-delimited word of an error message.

    Returns:
        The word with one pair of surrounding quotes removed.
    """
    for quote in ("'", '"'):
        if len(word) > 1 and word.startswith(quote) and word.endswith(quote):
            return word[1:-1]
    return word


def _looks_like_credential(word: str) -> bool:
    """Report whether a message word may carry part of a credential.

    ``argparse`` can split one typed argument into several words, as it
    does for ``-valice:pa ss@host/x``, so the parser redacts each word
    as well as each token. Plain message words such as ``usage:`` or
    ``netspeed:`` end in a colon with nothing after it, and a real
    ``host:8080`` pairs a host with a port number, so neither is
    touched. Escapes are resolved first, because ``argparse`` rewrites
    ``-valice%3ASECRETpw`` into ``-alice%3ASECRETpw``, which carries no
    delimiter until it is decoded.

    Args:
        word: One whitespace-delimited word of an error message.

    Returns:
        True when the word contains an at sign, a scheme, or a colon
        followed by something other than the port of a host-like name,
        in the word or in its decoded form.
    """
    if "@" in word or "://" in word:
        return True
    decoded, capped = _decode_escapes(word)
    if capped or "@" in decoded or "://" in decoded:
        return True
    head, separator, tail = decoded.rpartition(":")
    if not separator or not head or not tail:
        return False
    return not (_is_port(tail) and _is_host_like(head))


def _hide(
    word: str,
    guarded: frozenset[str],
    loose: frozenset[str],
) -> bool:
    """Report whether a message word matches a string to withhold.

    A word may arrive as ``--runs=x`` or as the bare ``x`` that
    ``argparse`` quotes on its own, so both the word and the value it
    assigns are tried, with any surrounding quotes removed.

    Args:
        word: One whitespace-delimited word of an error message.
        guarded: Strings recognised by structure as sensitive.
        loose: Arguments that become sensitive once one of them is.

    Returns:
        True when the word or the value it carries must be withheld.
    """
    for candidate in (_bare(word), word.partition("=")[2]):
        if candidate and (candidate in guarded or candidate in loose):
            return True
    return False


class RedactingArgumentParser(argparse.ArgumentParser):
    """Argument parser that redacts credentials from its error output.

    ``argparse`` quotes the offending argument in a usage error, so a
    URL typed twice would otherwise print its password to stderr. The
    raw tokens are remembered while parsing, because a userinfo that
    contains a space cannot be recognised in the finished message by any
    pattern.
    """

    _raw_arguments: tuple[str, ...] = ()

    def remember_arguments(self, argv: Sequence[str] | None) -> None:
        """Store the raw tokens so error output can redact them.

        Args:
            argv: Argument list without the program name; ``None`` reads
                ``sys.argv``.

        Returns:
            None.
        """
        self._raw_arguments = tuple(sys.argv[1:] if argv is None else argv)

    def error(self, message: str) -> NoReturn:
        """Report a usage error with any credentials redacted.

        Args:
            message: Error text from argparse, which may quote the
                offending argument, its value, spacing and all.

        Raises:
            SystemExit: Always, with status 2.
        """
        super().error(redact_text(self._redact_runs(message)))

    def _redact_runs(self, message: str) -> str:
        """Redact a credential that was typed as several arguments.

        A password containing a space arrives as separate tokens,
        whose tail alone carries neither a colon nor an at sign, so it
        is recognised only by looking at its neighbours. The runs are
        found in the message rather than in the argument list, because
        ``argparse`` quotes tokens that were not adjacent on the
        command line: ``unrecognized arguments`` juxtaposes the
        positionals it rejected, which an option may have separated.
        Every stretch of message words that are all raw arguments is
        replaced by ``***`` as soon as one of them needs redacting, so
        the piece carrying the delimiter hides the pieces that do not,
        and a lone word that is one of the tainted arguments is
        replaced on its own. Once any argument holds a credential, no
        other argument can be ruled out, because the pieces are only
        recognisable together.

        Args:
            message: Error text that may quote the typed tokens.

        Returns:
            The message with every credential run replaced by ``***``.
        """
        guarded = self._guarded_strings()
        raw = {
            piece
            for token in self._raw_arguments
            for piece in (token, token.partition("=")[2])
            if piece
        }
        loose: frozenset[str] = (
            frozenset(raw)
            if any(
                redact_argument(token) != token
                for token in self._raw_arguments
            )
            else frozenset()
        )
        words = message.split(" ")
        quoted = [
            _hide(word, guarded, loose) or _looks_like_credential(word)
            for word in words
        ]
        index = 0
        while index < len(words):
            if not quoted[index]:
                index += 1
                continue
            end = index
            while end < len(words) and quoted[end]:
                end += 1
            run = words[index:end]
            if len(run) == 1:
                word = run[0]
                redacted = redact_argument(word)
                if redacted != word:
                    message = message.replace(word, redacted)
                elif _hide(word, guarded, loose):
                    message = message.replace(word, "***")
            elif any(
                redact_argument(word) != word or _hide(word, guarded, loose)
                for word in run
            ):
                message = message.replace(" ".join(run), "***")
            index = end
        return message

    def _guarded_strings(self) -> frozenset[str]:
        """Return the strings that must never be printed.

        ``argparse`` repeats what the user typed in several shapes: a
        value attached to its option with ``=``, the pieces of an
        argument that contains whitespace, the remainder it reports when
        it peels known short flags from a cluster such as ``-vvsecret``,
        and a token that merely extends a known long option such as
        ``--jsonsecret``. Each shape is recognised by structure rather
        than by content, so a credential is withheld even though
        nothing in it looks like one, while a plain typo such as
        ``--jsno`` or an unknown flag such as ``-x`` stays readable.

        Returns:
            The strings to withhold when they appear in a message.
        """
        guarded: set[str] = set()
        options = self._option_string_actions
        for token in self._raw_arguments:
            value = token.partition("=")[2]
            if value:
                guarded.add(value)
            pieces = token.split()
            if len(pieces) > 1:
                guarded.update(pieces)
            if not token.startswith("-"):
                continue
            if token.startswith("--"):
                if any(
                    token.startswith(option) and token != option
                    for option in options
                ):
                    guarded.add(token)
                continue
            index = 1
            while index < len(token) and f"-{token[index]}" in options:
                remainder = "-" + token[index + 1 :]
                if remainder != "-":
                    guarded.add(remainder)
                index += 1
        return frozenset(guarded)


def build_parser() -> RedactingArgumentParser:
    """Build the command-line parser.

    Returns:
        Parser accepting a URL plus the run, timeout, chunk, and output
        options.
    """
    parser = RedactingArgumentParser(
        prog="netspeed",
        description=(
            "Measure download speed by fetching a URL several times and "
            "reporting the average throughput."
        ),
        epilog=(
            "Units: MiB/s is 1048576 bytes per second (many tools call "
            "this MB/s); Mbit/s is 10^6 bits per second. Speed is "
            "computed over the body transfer, TTFB is separate. "
            "--timeout is an inactivity limit per read, not a total "
            "deadline."
        ),
    )
    parser.add_argument(
        "url",
        help="http(s) URL of a large file, for example an image",
    )
    parser.add_argument(
        "-n",
        "--runs",
        type=run_count,
        default=10,
        help=f"number of measured requests, 1..{MAX_RUNS} (default: 10)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=timeout_seconds,
        default=15.0,
        help=(
            "socket timeout in seconds, up to "
            f"{MAX_TIMEOUT:g} (default: 15)"
        ),
    )
    parser.add_argument(
        "--chunk-size",
        type=chunk_size_bytes,
        default=CHUNK_SIZE,
        help=(
            "body read size in bytes, 1.."
            f"{MAX_CHUNK_SIZE} (default: {CHUNK_SIZE})"
        ),
    )
    parser.add_argument(
        "--no-warmup",
        action="store_true",
        help="skip the discarded first request (DNS and TLS land in run 1)",
    )
    parser.add_argument(
        "-p",
        "--proxy",
        type=validate_proxy,
        metavar="URL",
        default=None,
        help=(
            "route the measurement through this http(s) or socks5 "
            "proxy (a bare host:port counts as http), for example "
            "http://gate.local:3128; credentials typed in the URL "
            "appear as *** everywhere; SOCKS needs the PySocks package"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the runs and summary as JSON instead of a table",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="log per-run details and tracebacks to stderr",
    )
    return parser


def build_payload(
    url: str,
    results: Sequence[RunResult],
    summary: Summary,
    *,
    warmup: bool,
    proxy: str | None = None,
) -> dict[str, object]:
    """Build the JSON document printed by ``--json``.

    Any credentials in ``url`` and in ``proxy`` are redacted, and each
    run carries the speeds the table prints, so a consumer need not
    re-derive them from the byte count and the elapsed time.

    Args:
        url: Measured URL.
        results: Measured runs in execution order.
        summary: Aggregated statistics of ``results``.
        warmup: Whether a discarded warm-up request was sent.
        proxy: Proxy the requests were routed through, or ``None``
            when they went directly.

    Returns:
        A JSON-serializable mapping with the URL, the per-run results,
        the summary, the units used, and the route.
    """
    return {
        "url": redact_url(url),
        "proxy": None if proxy is None else redact_url(proxy),
        "warmup": warmup,
        "units": {
            "speed": "MiB/s",
            "bit_speed": "Mbit/s",
            "mib_bytes": MIB,
        },
        "runs": [
            {
                **asdict(result),
                "mib_per_s": result.mib_per_s,
                "mbit_per_s": _mbit(result.mib_per_s),
            }
            for result in results
        ],
        "summary": asdict(summary),
    }


def _redirect_to_devnull(stream: IO[str] | None) -> None:
    """Point a standard stream at the null device.

    Args:
        stream: Stream to redirect, or ``None`` when it is closed.

    Returns:
        None.
    """
    if stream is None:
        return
    try:
        null_fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null_fd, stream.fileno())
        os.close(null_fd)
    except (OSError, ValueError):
        logger.debug("could not redirect a stream to the null device")


def _silence_stdout() -> None:
    """Point stdout at the null device after a failed report write.

    Without this, the interpreter's own flush at shutdown fails again
    and replaces the exit status with 120.

    Returns:
        None.
    """
    _redirect_to_devnull(sys.stdout)


def flush_stderr() -> None:
    """Flush stderr, silencing it when the write fails.

    A full disk or a closed descriptor behind ``2>`` would otherwise
    make the interpreter's shutdown flush replace the exit status with
    120.

    Returns:
        None.
    """
    stream = sys.stderr
    if stream is None:
        return
    try:
        stream.flush()
    except (OSError, ValueError):
        _redirect_to_devnull(stream)


def write_report(text: str) -> bool:
    """Write the final report to stdout.

    A reader that has gone away, a closed descriptor, a full disk, and a
    text the stream cannot encode are all reported instead of surfacing
    as a traceback and an undocumented exit code.

    Args:
        text: Complete report text, without a trailing newline.

    Returns:
        True when the report reached stdout, false when the write failed
        for a reason already logged.
    """
    stream = sys.stdout
    if stream is None:
        logger.error("stdout is closed; the report cannot be written")
        return False
    try:
        print(text, file=stream)
        stream.flush()
    except BrokenPipeError:
        _silence_stdout()
        logger.error("stdout was closed before the report was written")
        return False
    except (OSError, UnicodeError) as exc:
        _silence_stdout()
        logger.error("could not write the report: %s", exc)
        return False
    return True


def _run(argv: Sequence[str] | None) -> int:
    """Carry out one command-line invocation.

    Args:
        argv: Argument list without the program name; ``None`` reads
            ``sys.argv``.

    Returns:
        The exit status documented for :func:`main`.
    """
    parser = build_parser()
    parser.remember_arguments(argv)
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        url = validate_url(args.url)
        proxy: str | None = args.proxy
    except ValueError as exc:
        logger.error("%s", exc)
        return 2
    try:
        with session_route(proxy) as (session, _active_proxy):
            results = run_series(
                session,
                url,
                args.runs,
                chunk_size=args.chunk_size,
                timeout=args.timeout,
                warmup=not args.no_warmup,
            )
        summary = summarize(results)
    except UnicodeError:
        logger.error(
            "measurement failed: %s: the URL cannot be encoded for a "
            "request",
            _visible(redact_url(args.url)),
        )
        return 1
    except (requests.RequestException, MeasurementError) as exc:
        logger.error("measurement failed: %s", _visible(redact_text(str(exc))))
        if proxy is not None:
            alternative = _remote_dns_scheme(proxy)
            if alternative is not None:
                logger.info(
                    "note: %s resolves the hostname on this machine; the "
                    "same proxy spelled %s asks the proxy to resolve it, "
                    "which avoids addresses picked for this network",
                    proxy.split("://", 1)[0],
                    alternative,
                )
        if args.verbose:
            logger.debug("traceback", exc_info=True)
        return 1
    except KeyboardInterrupt:
        logger.error("interrupted before the measurement finished")
        return 130
    if args.json:
        payload = build_payload(
            url,
            results,
            summary,
            warmup=not args.no_warmup,
            proxy=proxy,
        )
        report = json.dumps(payload, indent=2)
    else:
        report = format_report(
            url,
            results,
            summary,
            warmup=not args.no_warmup,
            proxy=proxy,
        )
    if not write_report(report):
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Unusable argument text is reported by ``argparse``, which exits the
    process itself with status 2 before this function returns.

    Args:
        argv: Argument list without the program name; ``None`` reads
            ``sys.argv``.

    Returns:
        ``0`` when the measurement completed, ``1`` when a request, a
        response, or the report write failed, ``2`` when the URL is
        unusable, ``130`` when the user interrupted the measurement.
        Every message it logs has any URL credentials redacted.
    """
    try:
        return _run(argv)
    finally:
        flush_stderr()


if __name__ == "__main__":
    sys.exit(main())
