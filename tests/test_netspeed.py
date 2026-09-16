"""Tests for the netspeed measurement script."""

from __future__ import annotations

import argparse
import importlib.util
import json
import logging
import socket
import statistics
import sys
import threading
import time
from collections.abc import Iterator
from urllib.parse import quote

import pytest
import requests

import netspeed
from tests.http_proxy import ForwardProxy
from tests.http_server import (
    CLOSE_DELIMITED_BYTES,
    CODED_TE_BYTES,
    GZIP_BYTES,
    HOSTILE_ENCODING_BYTES,
    PAYLOAD_BYTES,
    SMALL_BYTES,
    TE_BODY_BYTES,
    UNFRAMED_TE_BYTES,
    LocalServer,
)

MIB = netspeed.MIB


class FullStderr:
    """Stand-in for a stderr whose writes fail, as on a full disk."""

    def write(self, text: str) -> int:
        """Fail the way a full filesystem does.

        Args:
            text: Ignored text.

        Raises:
            OSError: Always, with ENOSPC.
        """
        raise OSError(28, "No space left on device")

    def flush(self) -> None:
        """Fail the way a full filesystem does.

        Raises:
            OSError: Always, with ENOSPC.
        """
        raise OSError(28, "No space left on device")

    def fileno(self) -> int:
        """Report that there is no usable file descriptor.

        Raises:
            ValueError: Always.
        """
        raise ValueError("no fileno")


@pytest.fixture()
def session() -> Iterator[requests.Session]:
    """Provide a requests session that is closed after the test.

    Yields:
        An open session with a reusable connection pool.
    """
    with requests.Session() as active:
        yield active


@pytest.mark.parametrize(
    "url",
    ["http://example.com/big.jpg", "https://example.com/big.jpg"],
)
def test_validate_url_accepts_http_schemes(url: str) -> None:
    """A well-formed http(s) URL passes validation unchanged."""
    assert netspeed.validate_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/big.jpg",
        "example.com/big.jpg",
        "http://",
        "http://:8080/x",
        "",
    ],
)
def test_validate_url_rejects_other_input(url: str) -> None:
    """Local files, other schemes, and host-less input are rejected."""
    with pytest.raises(ValueError):
        netspeed.validate_url(url)


@pytest.mark.parametrize("value", ["1", "10", "1000"])
def test_run_count_accepts_values_in_range(value: str) -> None:
    """Run counts inside the accepted range are parsed."""
    assert netspeed.run_count(value) == int(value)


@pytest.mark.parametrize(
    "value",
    ["0", "-1", "abc", "1.5", "", "1001", "1_0", " 3 ", "+5", "1e2"],
)
def test_run_count_rejects_bad_values(value: str) -> None:
    """Out-of-range and non-decimal run counts are rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        netspeed.run_count(value)


def test_run_count_rejects_an_absurdly_long_number() -> None:
    """A digit string beyond the cap is rejected as out of range."""
    with pytest.raises(argparse.ArgumentTypeError) as excinfo:
        netspeed.run_count("1" * 5000)

    assert "out of range" in str(excinfo.value)


def test_run_count_rejects_a_ten_digit_number_as_out_of_range() -> None:
    """A long but well-formed number is reported as out of range."""
    with pytest.raises(argparse.ArgumentTypeError) as excinfo:
        netspeed.run_count("1000000000")

    assert "out of range" in str(excinfo.value)


@pytest.mark.parametrize("value", ["1", "1024", "16777216"])
def test_chunk_size_accepts_values_in_range(value: str) -> None:
    """Chunk sizes inside the accepted range are parsed."""
    assert netspeed.chunk_size_bytes(value) == int(value)


@pytest.mark.parametrize(
    "value",
    ["0", "-4096", "x", "16777217", "1_048_576", ""],
)
def test_chunk_size_rejects_bad_values(value: str) -> None:
    """Out-of-range and non-decimal chunk sizes are rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        netspeed.chunk_size_bytes(value)


@pytest.mark.parametrize("value", ["0.5", "15", "3600"])
def test_timeout_accepts_values_in_range(value: str) -> None:
    """Timeouts inside the accepted range are parsed."""
    assert netspeed.timeout_seconds(value) == pytest.approx(float(value))


@pytest.mark.parametrize(
    "value",
    ["0", "-3", "x", "", "nan", "inf", "-inf", "1e400", "3600.5", "1e3"],
)
def test_timeout_rejects_bad_values(value: str) -> None:
    """Zero, negative, non-finite, and huge timeouts are rejected."""
    with pytest.raises(argparse.ArgumentTypeError):
        netspeed.timeout_seconds(value)


def test_redact_url_hides_credentials() -> None:
    """Userinfo is replaced, and the rest of the URL survives."""
    redacted = netspeed.redact_url("http://alice:s3cr3t@example.com/a.jpg")

    assert redacted == "http://***@example.com/a.jpg"
    assert "s3cr3t" not in redacted


def test_redact_url_leaves_plain_url_alone() -> None:
    """A URL without an at sign is returned unchanged."""
    url = "https://example.com/big.jpg?token=abc"

    assert netspeed.redact_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://alice:pa/ss@127.0.0.1:1/x",
        "http://alice:pa?ss@127.0.0.1:1/x",
        "http://alice:pa#ss@127.0.0.1:1/x",
        "http://alice:pa@x/hunter2@127.0.0.1:1/x",
        "https://example.com/mail@example.com",
    ],
)
def test_redact_url_fails_closed_on_odd_at_signs(url: str) -> None:
    """An at sign outside the authority is treated as a credential."""
    redacted = netspeed.redact_url(url)

    assert redacted in {"http://***", "https://***"}
    assert "alice" not in redacted
    assert "hunter2" not in redacted
    assert "example.com" not in redacted


@pytest.mark.parametrize("scheme", ["HTTP", "Http", "HTTPS", "hTTps"])
def test_redact_text_matches_the_scheme_case_insensitively(
    scheme: str,
) -> None:
    """An upper-case scheme does not hide a credential."""
    text = f"{scheme}://alice:s3cr3t@example.com/big.jpg"

    cleaned = netspeed.redact_text(text)

    assert "s3cr3t" not in cleaned
    assert cleaned == "***"


@pytest.mark.parametrize("scheme", ["HTTP", "HTTPS"])
def test_redact_url_matches_the_scheme_case_insensitively(
    scheme: str,
) -> None:
    """An upper-case scheme is redacted too."""
    redacted = netspeed.redact_url(f"{scheme}://alice:s3cr3t@example.com")

    assert redacted == f"{scheme}://***@example.com"


@pytest.mark.parametrize("scheme", ["HTTP", "HTTPS"])
def test_main_redacts_credentials_with_an_upper_case_scheme(
    scheme: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """argparse output is redacted whatever the scheme case is."""
    url = f"{scheme}://alice:s3cr3t@example.com/big.jpg"

    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["http://ok.example/x", url])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert f"{scheme}://***@example.com/big.jpg" in captured.err


def test_main_redacts_credentials_in_argument_errors(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """argparse output does not echo a duplicated credential URL."""
    url = "http://alice:s3cr3t@example.com/big.jpg"

    with pytest.raises(SystemExit) as excinfo:
        netspeed.main([url, url])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert "http://***@example.com/big.jpg" in captured.err


def test_declared_length_reads_header() -> None:
    """A well-formed Content-Length is returned as an integer."""
    response = requests.Response()
    response.headers["Content-Length"] = "4096"

    assert netspeed.declared_length(response) == 4096


@pytest.mark.parametrize("raw", ["abc", "-1", "12.5"])
def test_declared_length_ignores_unusable_values(raw: str) -> None:
    """Malformed, negative, and fractional lengths are unusable."""
    response = requests.Response()
    response.headers["Content-Length"] = raw

    assert netspeed.declared_length(response) is None


def test_declared_length_absent_returns_none() -> None:
    """A response without the header reports no declared size."""
    assert netspeed.declared_length(requests.Response()) is None


def test_check_body_size_accepts_matching_size() -> None:
    """An exact match against the declared size passes."""
    netspeed.check_body_size(100, 100, comparable=True)


def test_check_body_size_rejects_short_body() -> None:
    """A short body raises instead of reporting a good run."""
    with pytest.raises(netspeed.BodySizeMismatchError):
        netspeed.check_body_size(99, 100, comparable=True)


def test_check_body_size_skips_decoded_bodies() -> None:
    """A decoded body cannot be compared with the compressed length."""
    netspeed.check_body_size(200, 20, comparable=False)


def test_check_body_size_skips_unknown_length() -> None:
    """Without a declared length there is nothing to compare."""
    netspeed.check_body_size(200, None, comparable=True)


def test_measure_once_counts_received_bytes(
    session: requests.Session,
    payload_url: str,
) -> None:
    """The measured body size equals the served payload size."""
    result = netspeed.measure_once(session, payload_url, 1)

    assert result.bytes_downloaded == PAYLOAD_BYTES
    assert result.declared_bytes == PAYLOAD_BYTES
    assert result.verified is True
    assert result.index == 1
    assert result.ttfb_s >= 0.0
    assert result.body_s >= 0.0
    assert result.mib_per_s > 0.0
    assert result.mbit_per_s == pytest.approx(
        result.mib_per_s * MIB * 8 / netspeed.MBIT
    )


def test_measure_once_requests_identity_encoding(
    session: requests.Session,
    server: LocalServer,
    payload_url: str,
) -> None:
    """The client asks the server not to compress the body."""
    netspeed.measure_once(session, payload_url, 1)

    assert server.encodings_seen == ["identity"]


def test_measure_once_respects_chunk_size(
    session: requests.Session,
    payload_url: str,
) -> None:
    """A small read size does not change the byte count."""
    result = netspeed.measure_once(
        session,
        payload_url,
        1,
        chunk_size=1024,
    )

    assert result.bytes_downloaded == PAYLOAD_BYTES


def test_measure_once_reads_a_tiny_body(
    session: requests.Session,
    small_url: str,
) -> None:
    """A body far smaller than the chunk size is still counted."""
    result = netspeed.measure_once(session, small_url, 1)

    assert result.bytes_downloaded == SMALL_BYTES


def test_measure_once_counts_decoded_bytes_for_gzip(
    session: requests.Session,
    gzip_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A compressed response is counted decoded, and flagged."""
    with caplog.at_level(logging.WARNING, logger="netspeed"):
        result = netspeed.measure_once(session, gzip_url, 1)

    assert result.bytes_downloaded == GZIP_BYTES
    assert result.verified is False
    assert "Content-Encoding 'gzip'" in caplog.text


def test_measure_once_warns_when_size_is_unverifiable(
    session: requests.Session,
    nolength_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A close-delimited body is accepted but flagged as unverified."""
    with caplog.at_level(logging.WARNING, logger="netspeed"):
        result = netspeed.measure_once(session, nolength_url, 1)

    assert result.bytes_downloaded == CLOSE_DELIMITED_BYTES
    assert result.declared_bytes is None
    assert result.verified is False
    assert "cannot be verified" in caplog.text
    assert "Content-Length missing, Transfer-Encoding missing" in caplog.text


def test_measure_once_rejects_a_truncated_body(
    session: requests.Session,
    short_url: str,
) -> None:
    """A body shorter than Content-Length never becomes a good run."""
    with pytest.raises(netspeed.MeasurementError):
        netspeed.measure_once(session, short_url, 1)


def test_measure_once_trusts_chunked_framing_over_length(
    session: requests.Session,
    framed_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Transfer-Encoding wins over a contradicting Content-Length."""
    with caplog.at_level(logging.WARNING, logger="netspeed"):
        result = netspeed.measure_once(session, framed_url, 1)

    assert result.bytes_downloaded == TE_BODY_BYTES
    assert result.verified is True
    assert "cannot be verified" not in caplog.text


def test_measure_once_does_not_trust_a_non_framing_coding(
    session: requests.Session,
    unframed_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Transfer-Encoding: identity leaves the size unverifiable."""
    with caplog.at_level(logging.WARNING, logger="netspeed"):
        result = netspeed.measure_once(session, unframed_url, 1)

    assert result.bytes_downloaded == UNFRAMED_TE_BYTES
    assert result.declared_bytes is None
    assert result.verified is False
    assert "cannot be verified" in caplog.text


def test_measure_once_ignores_a_length_beside_a_coding(
    session: requests.Session,
    coded_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A declared length beside a coding proves no whole body."""
    with caplog.at_level(logging.WARNING, logger="netspeed"):
        result = netspeed.measure_once(session, coded_url, 1)

    assert result.bytes_downloaded == CODED_TE_BYTES
    assert result.declared_bytes == CODED_TE_BYTES
    assert result.verified is False
    assert "cannot be verified" in caplog.text


def test_measure_once_raises_on_http_error(
    session: requests.Session,
    missing_url: str,
) -> None:
    """A 404 response aborts the measurement."""
    with pytest.raises(netspeed.MeasurementError) as excinfo:
        netspeed.measure_once(session, missing_url, 1)

    assert "404" in str(excinfo.value)


def test_measure_once_redacts_credentials_in_failures(
    session: requests.Session,
) -> None:
    """A failing request never echoes the URL password."""
    url = "http://alice:s3cr3t@127.0.0.1:1/big.jpg"

    with pytest.raises(netspeed.MeasurementError) as excinfo:
        netspeed.measure_once(session, url, 1)

    message = str(excinfo.value)
    assert "s3cr3t" not in message
    assert "http://***@127.0.0.1:1/big.jpg" in message


def test_measure_once_redacts_a_userinfo_split_by_a_slash(
    session: requests.Session,
) -> None:
    """A malformed credential URL still never reaches the message."""
    url = "http://alice:s3cr3t/part@127.0.0.1:1/big.jpg"

    with pytest.raises(netspeed.MeasurementError) as excinfo:
        netspeed.measure_once(session, url, 1)

    message = str(excinfo.value)
    assert "s3cr3t" not in message
    assert "alice" not in message


def test_transport_detail_withholds_quoted_credentials(
    session: requests.Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Even the DEBUG detail omits a credential the library echoed."""
    url = "http://alice:s3cr3t/part@127.0.0.1:1/big.jpg"

    with caplog.at_level(logging.DEBUG, logger="netspeed"):
        with pytest.raises(netspeed.MeasurementError):
            netspeed.measure_once(session, url, 1)

    assert "s3cr3t" not in caplog.text
    assert "alice" not in caplog.text
    assert "withheld" in caplog.text


def test_measure_once_raises_on_empty_body(
    session: requests.Session,
    empty_url: str,
) -> None:
    """An empty body cannot be timed and is reported as an error."""
    with pytest.raises(netspeed.EmptyBodyError):
        netspeed.measure_once(session, empty_url, 1)


def test_run_series_returns_requested_runs(
    session: requests.Session,
    payload_url: str,
) -> None:
    """The series returns exactly the requested number of runs."""
    results = netspeed.run_series(
        session,
        payload_url,
        3,
        warmup=False,
    )

    assert [result.index for result in results] == [1, 2, 3]
    assert all(result.bytes_downloaded == PAYLOAD_BYTES for result in results)


def test_run_series_warmup_is_excluded_from_results(
    session: requests.Session,
    server: LocalServer,
    payload_url: str,
) -> None:
    """The warm-up request is sent but not part of the sample."""
    results = netspeed.run_series(
        session,
        payload_url,
        2,
        warmup=True,
    )

    assert len(results) == 2
    assert len(server.requests_seen) == 3
    assert server.requests_seen[0] == "/payload"


def test_run_series_reuses_one_connection(
    session: requests.Session,
    server: LocalServer,
    payload_url: str,
) -> None:
    """Warm-up and measured runs share a single TCP connection."""
    netspeed.run_series(session, payload_url, 2, warmup=True)

    assert len(set(server.connections_seen)) == 1


def test_run_series_rejects_zero_runs(
    session: requests.Session,
    payload_url: str,
) -> None:
    """Zero runs are rejected instead of returning an empty average."""
    with pytest.raises(ValueError):
        netspeed.run_series(session, payload_url, 0, warmup=False)


def test_run_series_aborts_on_failure(
    session: requests.Session,
    missing_url: str,
) -> None:
    """A failure propagates instead of yielding a partial sample."""
    with pytest.raises(netspeed.MeasurementError):
        netspeed.run_series(session, missing_url, 3, warmup=False)


def test_summarize_computes_statistics() -> None:
    """Mean, median, extremes, and spread come from the run speeds."""
    results = [
        netspeed.RunResult(1, MIB, 0.5, 1.0, MIB, True),
        netspeed.RunResult(2, MIB, 0.5, 0.5, MIB, True),
        netspeed.RunResult(3, MIB, 0.5, 0.25, MIB, True),
    ]

    summary = netspeed.summarize(results)

    assert summary.runs == 3
    assert summary.bytes_downloaded == 3 * MIB
    assert summary.mean_mib_per_s == pytest.approx(7 / 3)
    assert summary.aggregate_mib_per_s == pytest.approx(3 / 1.75)
    assert summary.median_mib_per_s == pytest.approx(2.0)
    assert summary.min_mib_per_s == pytest.approx(1.0)
    assert summary.max_mib_per_s == pytest.approx(4.0)
    assert summary.stdev_mib_per_s == pytest.approx(
        statistics.stdev([1.0, 2.0, 4.0])
    )
    assert summary.mean_ttfb_s == pytest.approx(0.5)
    assert summary.mean_body_s == pytest.approx(1.75 / 3)
    assert summary.mean_total_s == pytest.approx(0.5 + 1.75 / 3)
    assert summary.unverified_runs == 0


def test_summarize_pooled_rate_differs_from_mean_of_ratios() -> None:
    """Pooling bytes and time is not the mean of the per-run ratios."""
    results = [
        netspeed.RunResult(1, 10 * MIB, 0.0, 1.0, 10 * MIB, True),
        netspeed.RunResult(2, MIB, 0.0, 0.2, MIB, True),
    ]

    summary = netspeed.summarize(results)

    assert summary.mean_mib_per_s == pytest.approx(7.5)
    assert summary.aggregate_mib_per_s == pytest.approx(11 / 1.2)


def test_summarize_pools_the_time_each_run_used() -> None:
    """A run falling back to total time keeps its measured time."""
    results = [
        netspeed.RunResult(1, MIB, 0.5, 0.0, None, False),
        netspeed.RunResult(2, MIB, 0.0, 1.0, MIB, True),
    ]

    summary = netspeed.summarize(results)

    assert summary.aggregate_mib_per_s == pytest.approx(2 / 1.5)


def test_summarize_counts_unverified_runs() -> None:
    """Runs without a verified size are counted for the report."""
    results = [
        netspeed.RunResult(1, MIB, 0.1, 1.0, None, False),
        netspeed.RunResult(2, MIB, 0.1, 1.0, MIB, True),
    ]

    assert netspeed.summarize(results).unverified_runs == 1


def test_summarize_single_run_has_no_spread() -> None:
    """A single run yields no sample standard deviation."""
    summary = netspeed.summarize([netspeed.RunResult(1, MIB, 0.1, 0.4)])

    assert summary.stdev_mib_per_s is None
    assert summary.mean_mib_per_s == pytest.approx(2.5)
    assert summary.median_mib_per_s == pytest.approx(2.5)


def test_summarize_rejects_empty_input() -> None:
    """Summarizing nothing is an error rather than a zero result."""
    with pytest.raises(ValueError):
        netspeed.summarize([])


def test_run_result_falls_back_to_total_time() -> None:
    """A body that arrives with the headers cannot inflate the speed."""
    result = netspeed.RunResult(1, MIB, 0.5, 0.0)

    assert result.measured_s == pytest.approx(0.5)
    assert result.mib_per_s == pytest.approx(2.0)


def test_run_result_rejects_zero_elapsed_time() -> None:
    """A run with no elapsed time has no defined speed."""
    result = netspeed.RunResult(1, MIB, 0.0, 0.0)

    with pytest.raises(netspeed.UnmeasurableRunError):
        _ = result.mib_per_s


def test_redact_text_hides_embedded_credentials() -> None:
    """A library message quoting a URL loses that URL whole."""
    message = (
        "HTTPSConnectionPool: Max retries exceeded with url: "
        "https://alice:s3cr3t@example.com/big.jpg (Caused by ...)"
    )

    cleaned = netspeed.redact_text(message)

    assert "s3cr3t" not in cleaned
    assert "alice" not in cleaned
    assert cleaned.startswith("HTTPSConnectionPool: Max retries exceeded")
    assert "***" in cleaned


def test_redact_text_removes_a_password_containing_at_sign() -> None:
    """An at sign in the userinfo takes the whole token with it."""
    message = "Last URL: http://bob:p@ss:w0rd@host/loop"

    cleaned = netspeed.redact_text(message)

    assert cleaned == "Last URL: ***"
    assert "w0rd" not in cleaned


def test_redact_text_fails_closed_on_an_at_sign_in_a_path() -> None:
    """An at sign in a path is over-redacted rather than risked."""
    message = "url: https://example.com/mail@example.com"

    assert netspeed.redact_text(message) == "url: ***"


def test_redact_text_removes_a_credential_split_by_a_delimiter() -> None:
    """A userinfo containing a slash still loses the whole prefix."""
    message = "Invalid URL 'http://alice:pa/ss@127.0.0.1:1/x'"

    cleaned = netspeed.redact_text(message)

    assert "alice" not in cleaned
    assert cleaned == "Invalid URL ***"


def test_redact_text_leaves_a_redacted_token_alone() -> None:
    """A host this module already kept readable is not hidden again."""
    message = "measurement failed: http://***@example.com/big.jpg: HTTPError"

    assert netspeed.redact_text(message) == message


def test_redact_text_is_linear_in_the_text_length() -> None:
    """A huge argument cannot turn a message through a regex hang."""
    text = "a" * 1_000_000

    started = time.monotonic()

    assert netspeed.redact_text(text) == text
    assert time.monotonic() - started < 1.0


def test_format_report_contains_units_and_summary(
    session: requests.Session,
    payload_url: str,
) -> None:
    """The report shows per-run rows and both speed units."""
    results = netspeed.run_series(
        session,
        payload_url,
        2,
        warmup=False,
    )
    summary = netspeed.summarize(results)

    report = netspeed.format_report(
        payload_url,
        results,
        summary,
        warmup=False,
    )

    assert f"URL: {payload_url}" in report
    assert "MiB/s" in report
    assert "Mbit/s" in report
    assert "aggregate:" in report
    assert "mean request:" in report
    assert "Runs measured: 2" in report
    assert "MB/s" not in report


def test_format_report_redacts_credentials() -> None:
    """The report never echoes the password from the URL."""
    results = [netspeed.RunResult(1, MIB, 0.1, 1.0, MIB)]
    summary = netspeed.summarize(results)

    report = netspeed.format_report(
        "http://alice:s3cr3t@example.com/big.jpg",
        results,
        summary,
        warmup=False,
    )

    assert "s3cr3t" not in report
    assert "***@example.com" in report


def test_format_report_flags_unverified_sizes() -> None:
    """A run without Content-Length is called out in the report."""
    results = [netspeed.RunResult(1, MIB, 0.1, 1.0, None)]
    summary = netspeed.summarize(results)

    report = netspeed.format_report(
        "http://example.com/big.jpg",
        results,
        summary,
        warmup=False,
    )

    assert "size-verified" in report


def test_build_payload_redacts_credentials() -> None:
    """The JSON payload never echoes the password from the URL."""
    results = [netspeed.RunResult(1, MIB, 0.1, 1.0, MIB)]
    summary = netspeed.summarize(results)

    payload = netspeed.build_payload(
        "http://alice:s3cr3t@example.com/big.jpg",
        results,
        summary,
        warmup=False,
    )

    assert payload["url"] == "http://***@example.com/big.jpg"


def test_main_sends_ten_requests_by_default(
    server: LocalServer,
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The default is one warm-up plus ten measured requests."""
    exit_code = netspeed.main([payload_url])

    assert exit_code == 0
    assert len(server.requests_seen) == 11
    out = capsys.readouterr().out
    assert "Runs measured: 10" in out
    assert "warm-up excluded" in out


def test_main_no_warmup_sends_exactly_the_requested_runs(
    server: LocalServer,
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--no-warmup removes the discarded request."""
    exit_code = netspeed.main([payload_url, "-n", "2", "--no-warmup"])

    assert exit_code == 0
    assert len(server.requests_seen) == 2
    assert "warm-up excluded" not in capsys.readouterr().out


def test_main_accepts_chunk_size_option(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--chunk-size is honoured end to end."""
    exit_code = netspeed.main([payload_url, "-n", "1", "--chunk-size", "1024"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert f"total downloaded: {PAYLOAD_BYTES} bytes" in out


def test_main_json_output_is_parseable(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--json prints a machine-readable document on stdout."""
    exit_code = netspeed.main([payload_url, "-n", "2", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["url"] == payload_url
    assert payload["units"]["speed"] == "MiB/s"
    assert len(payload["runs"]) == 2
    assert payload["summary"]["runs"] == 2
    assert payload["summary"]["aggregate_mib_per_s"] > 0.0
    assert payload["summary"]["unverified_runs"] == 0


def test_main_returns_one_on_request_failure(
    missing_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An HTTP error exits with status 1 and no report."""
    exit_code = netspeed.main([missing_url, "-n", "2"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "measurement failed" in captured.err


def test_main_redacts_credentials_in_failure_output(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failing run never writes the URL password to stderr."""
    exit_code = netspeed.main(
        ["http://alice:s3cr3t@127.0.0.1:1/big.jpg", "-n", "1"]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert "http://***@127.0.0.1:1/big.jpg" in captured.err


def test_main_returns_one_when_a_run_has_no_elapsed_time(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unmeasurable run is reported instead of crashing."""
    broken = [netspeed.RunResult(1, MIB, 0.0, 0.0)]

    def fake_series(
        *args: object,
        **kwargs: object,
    ) -> list[netspeed.RunResult]:
        """Return a run with no elapsed time.

        Args:
            *args: Ignored positional arguments.
            **kwargs: Ignored keyword arguments.

        Returns:
            A single zero-duration run.
        """
        return broken

    monkeypatch.setattr(netspeed, "run_series", fake_series)

    exit_code = netspeed.main([payload_url])

    assert exit_code == 1
    assert "elapsed time" in capsys.readouterr().err


def test_main_returns_one_on_truncated_body(
    short_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A truncated transfer exits with status 1 and no report."""
    exit_code = netspeed.main([short_url, "-n", "2"])

    assert exit_code == 1
    assert capsys.readouterr().out == ""


def test_main_returns_one_on_empty_body(
    empty_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An empty body exits with status 1 and no report."""
    exit_code = netspeed.main([empty_url, "-n", "2"])

    assert exit_code == 1
    assert capsys.readouterr().out == ""


def test_main_returns_one_when_stdout_is_closed(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A closed stdout is reported, not left to a broken-pipe crash."""

    class ClosedStdout:
        """Stand-in for a stdout whose reader has gone away."""

        def write(self, text: str) -> int:
            """Fail the way a closed pipe does.

            Args:
                text: Ignored report text.

            Raises:
                BrokenPipeError: Always.
            """
            raise BrokenPipeError

        def flush(self) -> None:
            """Fail the way a closed pipe does.

            Raises:
                BrokenPipeError: Always.
            """
            raise BrokenPipeError

        def fileno(self) -> int:
            """Report that there is no usable file descriptor.

            Raises:
                ValueError: Always.
            """
            raise ValueError("no fileno")

    monkeypatch.setattr(sys, "stdout", ClosedStdout())

    exit_code = netspeed.main([payload_url, "-n", "1"])

    assert exit_code == 1
    assert "stdout was closed" in capsys.readouterr().err


def test_main_returns_one_when_report_write_fails(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full disk is reported instead of crashing at flush time."""

    class FullDisk:
        """Stand-in for a stdout that cannot accept more bytes."""

        def write(self, text: str) -> int:
            """Fail the way a full filesystem does.

            Args:
                text: Ignored report text.

            Raises:
                OSError: Always, with ENOSPC.
            """
            raise OSError(28, "No space left on device")

        def flush(self) -> None:
            """Fail the way a full filesystem does.

            Raises:
                OSError: Always, with ENOSPC.
            """
            raise OSError(28, "No space left on device")

        def fileno(self) -> int:
            """Report that there is no usable file descriptor.

            Raises:
                ValueError: Always.
            """
            raise ValueError("no fileno")

    monkeypatch.setattr(sys, "stdout", FullDisk())

    exit_code = netspeed.main([payload_url, "-n", "1"])

    assert exit_code == 1
    assert "could not write the report" in capsys.readouterr().err


def test_main_returns_one_when_report_cannot_be_encoded(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unencodable report is reported, not raised as a traceback."""

    class AsciiOnly:
        """Stand-in for a stream that cannot encode the report."""

        def write(self, text: str) -> int:
            """Fail the way an ASCII stream does.

            Args:
                text: Ignored report text.

            Raises:
                UnicodeEncodeError: Always.
            """
            raise UnicodeEncodeError("ascii", text, 0, 1, "not ascii")

        def flush(self) -> None:
            """Succeed, because the failure happens on write.

            Returns:
                None.
            """
            return None

        def fileno(self) -> int:
            """Report that there is no usable file descriptor.

            Raises:
                ValueError: Always.
            """
            raise ValueError("no fileno")

    monkeypatch.setattr(sys, "stdout", AsciiOnly())

    exit_code = netspeed.main([payload_url, "-n", "1"])

    assert exit_code == 1
    assert "could not write the report" in capsys.readouterr().err


def test_main_returns_one_when_stdout_is_absent(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stdout closed before start is reported cleanly."""
    monkeypatch.setattr(sys, "stdout", None)

    exit_code = netspeed.main([payload_url, "-n", "1"])

    assert exit_code == 1
    assert "stdout is closed" in capsys.readouterr().err


def test_main_redacts_credentials_with_a_space_in_userinfo(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A userinfo containing a space never reaches the usage error."""
    url = "http://alice:pa ss@127.0.0.1:1/auth"

    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["http://ok.example/x", url])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "alice" not in captured.err
    assert "pa ss" not in captured.err
    assert "127.0.0.1" not in captured.err
    assert "***" in captured.err


@pytest.mark.parametrize("option", ["--timeout", "--runs", "--chunk-size"])
def test_option_value_errors_redact_credentials(
    option: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A credential URL used as an option value is never echoed."""
    url = "https://alice:s3cr3t@example.com/big.jpg"

    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["http://ok.example/x", option, url])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert "alice" not in captured.err


@pytest.mark.parametrize("option", ["--timeout", "--runs", "--chunk-size"])
@pytest.mark.parametrize(
    "value",
    [
        "alice:s3cr3t",
        "alice:s3cr3t@example.com",
        "alice:p@ss:w0rd",
        "alice:supers3cr3tpassword",
    ],
)
def test_option_value_errors_redact_scheme_less_credentials(
    option: str,
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A credential typed without a scheme is redacted in an error."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["http://ok.example/x", option, value])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert "alice" not in captured.err
    assert "w0rd" not in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ["--json=ftp://alice:s3cr3t@example.com/x", "http://ok.example/x"],
        ["--json=alice:s3cr3t@example.com/x", "http://ok.example/x"],
        ["--json=http://alice:pa ss@example.com/x", "http://ok.example/x"],
        ["--verbose=alice:s3cr3t@example.com/x", "http://ok.example/x"],
        ["http://ok.example/x", "alice:s3cr3t@example.com/x"],
        ["--bogus=alice:s3cr3t@example.com/x", "http://ok.example/x"],
        ["-valice:s3cr3t@example.com/x", "http://ok.example/x"],
        ["-vftp://alice:s3cr3t@example.com/x", "http://ok.example/x"],
        ["-valice:pa ss@example.com/x", "http://ok.example/x"],
        ["--runs=alice:s3cr3t", "http://ok.example/x"],
        ["--runs=alice:s3cr3t://host/big", "http://ok.example/x"],
        ["http://ok.example/x", "alice:s3cr3t@http://host/big"],
        ["http://ok.example/x", "alice:s3cr3t", "wwq2"],
        ["-valice:987654", "http://ok.example/x"],
    ],
)
def test_argument_errors_never_echo_credentials(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No spelling of a credential argument reaches the usage error."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(argv)

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert "alice" not in captured.err


def test_main_rejects_a_scheme_less_credential_url_quietly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A credential without a scheme exits 2 without echoing it."""
    exit_code = netspeed.main(["alice:s3cr3t@example.com/big.jpg"])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert "alice" not in captured.err
    assert "unsupported scheme" in captured.err


def test_main_rejects_an_unparseable_url_without_a_traceback(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A URL urlsplit cannot parse exits 2 with its own message."""
    exit_code = netspeed.main(["http://alice:pw@[::1/x"])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "could not be parsed" in captured.err
    assert "alice" not in captured.err


def test_redact_argument_handles_scheme_less_credentials() -> None:
    """The argument redactor needs no scheme to hide userinfo."""
    assert netspeed.redact_argument("alice:s3cr3t") == "***"
    assert netspeed.redact_argument("alice:s3cr3t@example.com/x") == "***"


def test_redact_argument_leaves_a_plain_value_alone() -> None:
    """A value without an at sign or colon is returned unchanged."""
    assert netspeed.redact_argument("15.5") == "15.5"
    assert netspeed.redact_argument("1024") == "1024"


def test_redact_argument_keeps_a_scheme_ful_url_readable() -> None:
    """A URL with a scheme keeps it, minus its credentials."""
    assert (
        netspeed.redact_argument("http://alice:s3cr3t@example.com/x")
        == "http://***@example.com/x"
    )


@pytest.mark.parametrize(
    "url",
    ["http://alice:pa", "http://alice:pa/x", "https://alice:pa?q=1"],
)
def test_redact_url_drops_a_malformed_authority(url: str) -> None:
    """A non-numeric port is treated as a truncated credential."""
    assert netspeed.redact_url(url) == "http://***" or (
        netspeed.redact_url(url) == "https://***"
    )


def test_redact_url_keeps_a_numeric_port() -> None:
    """A real port is not mistaken for a credential."""
    url = "http://example.com:8080/big.jpg"

    assert netspeed.redact_url(url) == url


def test_main_redacts_a_truncated_credential_url(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A URL whose port is a truncated credential is rejected."""
    exit_code = netspeed.main(["-n", "1", "http://alice:pa"])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "alice" not in captured.err
    assert "pa" not in captured.err
    assert "port must be a number" in captured.err
    assert captured.out == ""


def test_redact_argument_rejects_a_fake_scheme() -> None:
    """Text whose prefix only resembles a scheme is hidden whole."""
    assert netspeed.redact_argument("alice:s3cr3t://host/big") == "***"
    assert netspeed.redact_url("alice:s3cr3t://host/big") == "***"
    assert netspeed.redact_argument("alice:s3cr3t@http://host") == "***"


def test_redact_argument_keeps_a_real_scheme() -> None:
    """A genuine scheme is still recognised after the check."""
    assert (
        netspeed.redact_argument("HTTP://alice:s3cr3t@host/big")
        == "HTTP://***@host/big"
    )
    assert netspeed.redact_argument("http://host/big") == "http://host/big"


@pytest.mark.parametrize(
    "url",
    ["http://alice:987654", "http://alice:0", "http://alice:65536"],
)
def test_redact_url_drops_an_out_of_range_port(url: str) -> None:
    """A port outside 1..65535 is treated as a truncated credential."""
    assert netspeed.redact_url(url) == "http://***"


@pytest.mark.parametrize(
    "url",
    ["http://example.com:1/x", "http://example.com:65535/x"],
)
def test_redact_url_keeps_a_port_in_range(url: str) -> None:
    """The edges of the port range are real targets, not credentials."""
    assert netspeed.redact_url(url) == url


def test_main_redacts_an_out_of_range_port(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A numeric password long enough to overflow a port is hidden."""
    exit_code = netspeed.main(
        ["--no-warmup", "-n", "1", "http://alice:987654"]
    )

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "alice" not in captured.err
    assert "987654" not in captured.err
    assert "port must be a number" in captured.err
    assert captured.out == ""


def test_transport_detail_is_withheld_when_the_url_is_redacted(
    session: requests.Session,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A password requests quotes without an at sign stays unlogged."""
    url = "http://alice:zzqwerty"

    with caplog.at_level(logging.DEBUG, logger="netspeed"):
        with pytest.raises(netspeed.MeasurementError):
            netspeed.measure_once(session, url, 1)

    assert "zzqwerty" not in caplog.text
    assert "alice" not in caplog.text
    assert "withheld" in caplog.text


def test_main_rejects_a_host_less_url_quietly(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A URL with a port but no host exits 2 without echoing it."""
    exit_code = netspeed.main(["http://:8080/x"])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "no host" in captured.err


@pytest.mark.parametrize(
    "url",
    [
        "http://alice:SECRETpw:8080/x",
        "http://alice:SECRETpw:80",
        "http://alice:SECRETpw:1/big.jpg",
    ],
)
def test_redact_url_drops_an_authority_with_two_colons(url: str) -> None:
    """A lost at sign cannot be hidden by appending a real port."""
    assert netspeed.redact_url(url) == "http://***"


def test_main_hides_a_truncated_credential_with_a_port(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A credential followed by a port never reaches stderr."""
    exit_code = netspeed.main(
        ["--no-warmup", "-n", "1", "http://alice:SECRETpw:8080/x"]
    )

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err
    assert "alice" not in captured.err
    assert "port must be a number" in captured.err


def test_main_hides_a_truncated_credential_with_a_port_at_debug(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Even verbose output stays free of such a credential."""
    exit_code = netspeed.main(
        ["-v", "--no-warmup", "-n", "1", "http://alice:SECRETpw:80"]
    )

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err
    assert "Traceback" not in captured.err


def test_main_redacts_a_credential_split_by_an_option(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An option between two password fragments hides the middle."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["alice:pa", "MYSECRETPASSWORD", "-v", "more@host"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "MYSECRETPASSWORD" not in captured.err
    assert "more@host" not in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ["alice:pa", "MYSECRETPASSWORD", "more@host"],
        ["alice:pa", "MYSECRETPASSWORD", "-n", "2", "more@host"],
        ["alice:pa", "MYSECRETPASSWORD", "--chunk-size", "2", "more@host"],
        ["alice:pa", "MYSECRETPASSWORD", "-v"],
    ],
)
def test_main_redacts_a_credential_typed_in_pieces(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """No arrangement of the pieces reaches the usage error."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(argv)

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "MYSECRETPASSWORD" not in captured.err
    assert "alice" not in captured.err
    assert "more@host" not in captured.err


@pytest.mark.parametrize(
    "text",
    [
        "http://alice%3ASECRETpw%40host/x",
        "alice%3ASECRETpw%40host/x",
        "alice%3ASECRETpw",
        "alice%253ASECRETpw",
    ],
)
def test_redaction_decodes_percent_escapes(text: str) -> None:
    """A percent-encoded delimiter is still a delimiter."""
    redacted = netspeed.redact_argument(text)

    assert "SECRETpw" not in redacted
    assert "alice" not in redacted
    assert "***" in redacted


def test_main_hides_a_percent_encoded_credential_url(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An encoded userinfo never reaches stderr or DEBUG."""
    exit_code = netspeed.main(
        ["-v", "--no-warmup", "-n", "1", "http://alice%3ASECRETpw%40host/x"]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err
    assert "alice" not in captured.err


def test_main_hides_a_percent_encoded_option_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An encoded credential used as an option value is hidden too."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["http://ok.example/x", "--runs", "a%3ASECRETpw"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err


def test_main_hides_a_credential_after_a_space_in_a_url(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A space inside one URL argument cannot shelter a credential."""
    url = "http://127.0.0.1:1/x alice:SECRETpw"

    exit_code = netspeed.main(["-v", "--no-warmup", "-n", "1", url])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:1/x?u=alice:SECRETpw",
        "http://127.0.0.1:1/x#alice:SECRETpw",
        "http://127.0.0.1:1/a:b",
        "http://127.0.0.1:1/x%3Aalice",
    ],
)
def test_redact_url_drops_a_colon_outside_the_authority(url: str) -> None:
    """A colon in the path, query, or fragment counts as a secret."""
    assert netspeed.redact_url(url) == "http://***"


@pytest.mark.parametrize(
    "url",
    [
        "http://alice:xx@127.0.0.1:1/x?u=bob:SECRETpw",
        "http://alice:xx@127.0.0.1:1/x?u=bob%3ASECRETpw",
        "http://alice:xx@127.0.0.1:1/x#bob:SECRETpw",
        "http://alice:xx@127.0.0.1:1/a:b",
        "http://alice:xx@127.0.0.1:1/x@bob:SECRETpw",
    ],
)
def test_redact_url_drops_a_secret_behind_userinfo(url: str) -> None:
    """Valid userinfo does not shelter a credential in the tail."""
    assert netspeed.redact_url(url) == "http://***"


def test_redact_url_keeps_a_clean_tail_behind_userinfo() -> None:
    """A readable host and path survive the userinfo they follow."""
    url = "http://alice:xx@127.0.0.1:8080/payload?size=1024"

    assert netspeed.redact_url(url) == (
        "http://***@127.0.0.1:8080/payload?size=1024"
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:1/x?u=alice%253ASECRETpw",
        "http://alice%253ASECRETpw%2540host/x",
        "http://127.0.0.1:1/x%2540alice",
    ],
)
def test_redact_url_resolves_nested_escapes(url: str) -> None:
    """A delimiter encoded twice is still a delimiter."""
    assert netspeed.redact_url(url) == "http://***"


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1]:alice:SECRETpw/x",
        "http://[::1]:SECRETpw/x",
        "http://[::1]:8080:alice/x",
        "http://[::1]:65536/x",
        "http://[::1]:/x",
        "http://[::1:8080/x",
    ],
)
def test_redact_url_drops_a_malformed_ipv6_authority(url: str) -> None:
    """Brackets do not exempt an authority from credential checks."""
    assert netspeed.redact_url(url) == "http://***"


@pytest.mark.parametrize("url", ["http://[::1]/x", "http://[::1]:8080/x"])
def test_redact_url_keeps_a_clean_ipv6_authority(url: str) -> None:
    """A bracketed host with a real port is not a secret."""
    assert netspeed.redact_url(url) == url


@pytest.mark.parametrize("url", ["http://alice:/x", "http://alice:"])
def test_redact_url_drops_an_empty_port(url: str) -> None:
    """A colon with no port behind it is a truncated credential."""
    assert netspeed.redact_url(url) == "http://***"


def test_main_redacts_a_clustered_option_credential(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A credential on a short option is hidden even with a port."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["-valice:8080", "http://ok.example/x"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "alice" not in captured.err
    assert "***" in captured.err


def test_redaction_leaves_a_percent_literal_alone() -> None:
    """A stray percent sign is not a credential delimiter."""
    assert netspeed.redact_argument("100%") == "100%"


def test_redaction_survives_deeply_nested_escapes() -> None:
    """Escapes past the round cap fail closed, not into a crash."""
    token = ":"
    for _ in range(1200):
        token = quote(token, safe="")

    assert netspeed.redact_argument("alice" + token + "SECRETpw") == "***"


def test_main_survives_deeply_nested_escapes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A token nested beyond the round cap cannot crash or leak."""
    token = ":"
    for _ in range(1200):
        token = quote(token, safe="")

    exit_code = netspeed.main(
        ["--no-warmup", "-n", "1", "http://127.0.0.1:1/" + token]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "RecursionError" not in captured.err
    assert "Traceback (most recent call last)" not in captured.err
    assert "%2525" not in captured.err


def test_main_hides_a_credential_in_a_query(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A credential in a query string stays out of the error message."""
    url = "http://127.0.0.1:1/x?u=alice:SECRETpw"

    exit_code = netspeed.main(["-v", "--no-warmup", "-n", "1", url])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err
    assert "alice" not in captured.err


def test_redact_url_keeps_a_clean_url_with_a_query() -> None:
    """A URL with no credential delimiter in its authority stands."""
    url = "https://example.com/big.jpg?size=25000000&units=mib"

    assert netspeed.redact_url(url) == url


def test_redact_url_drops_an_at_sign_outside_the_authority() -> None:
    """An at sign in a path is a credential, not userinfo."""
    url = "http://127.0.0.1:1/x?u=alice@SECRETpw"

    assert netspeed.redact_url(url) == "http://***"


@pytest.mark.parametrize(
    "url",
    [
        "http://bob:pw@127.0.0.1:1/x?u=alice@SECRETpw",
        "http://bob:pw@127.0.0.1:1/x?token=@s3cr3tvalue",
        "http://127.0.0.1:1/alice@SECRETpw",
        "http://127.0.0.1:1/x?u=alice@SECRET%70w",
    ],
)
def test_main_hides_a_secret_behind_an_at_sign(
    url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Text behind a non-userinfo at sign never reaches the output."""
    exit_code = netspeed.main(["-v", "--no-warmup", "-n", "1", url])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err
    assert "s3cr3tvalue" not in captured.err
    assert "alice" not in captured.err
    assert "http://***" in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ["alice:pa", "-n", "MYSECRETPASSWORD", "more@host"],
        ["alice:pa", "-t", "MYSECRETPASSWORD"],
        ["alice:pa", "--chunk-size", "MYSECRETPASSWORD"],
        ["alice:pa", "--runs=MYSECRETPASSWORD", "more@host"],
    ],
)
def test_main_redacts_a_quoted_fragment_of_a_credential(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A tainted fragment wrapped in quotes is still withheld."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(argv)

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "MYSECRETPASSWORD" not in captured.err
    assert "alice" not in captured.err


def test_measure_once_escapes_server_control_characters(
    session: requests.Session,
    hostile_url: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A header a hostile server sends cannot reach the terminal raw."""
    with caplog.at_level(logging.WARNING, logger="netspeed"):
        result = netspeed.measure_once(session, hostile_url, 1)

    assert result.bytes_downloaded == HOSTILE_ENCODING_BYTES
    assert "\x1b" not in caplog.text
    assert "\x07" not in caplog.text
    assert "\\x1b" in caplog.text


@pytest.mark.parametrize(
    "argv",
    [
        ["-valice%3ASECRETpw", "http://ok.example/x"],
        ["-valice%253ASECRETpw", "http://ok.example/x"],
        ["-valice%40SECRETpw", "http://ok.example/x"],
        ["-v%3ASECRETpw", "http://ok.example/x"],
        ["-vSECRETpw", "http://ok.example/x"],
        ["-v=SECRETpw", "http://ok.example/x"],
        ["--alice=SECRETpw", "http://ok.example/x"],
    ],
)
def test_main_redacts_a_credential_on_a_clustered_option(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An attached option value is withheld whatever its spelling is."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(argv)

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "SECRETpw" not in captured.err
    assert "alice" not in captured.err


@pytest.mark.parametrize(
    "argv",
    [
        ["--runs=MYSECRETPASSWORD", "http://ok.example/x"],
        ["-n", "MYSECRETPASSWORD", "http://ok.example/x"],
        ["-t", "MYSECRETPASSWORD", "http://ok.example/x"],
        ["--chunk-size=MYSECRETPASSWORD", "http://ok.example/x"],
    ],
)
def test_main_withholds_a_rejected_option_value(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A value no number could be is hidden; the option is named."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(argv)

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "MYSECRETPASSWORD" not in captured.err
    assert "argument" in captured.err


def test_main_keeps_a_mistyped_number_readable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A rejected number is quoted, because it explains the error."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["-n", "1_0", "http://ok.example/x"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "1_0" in captured.err


def test_main_hides_a_credential_split_by_a_clean_url(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A readable URL between two fragments does not break the run."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["alice:pa", "http://127.0.0.1:1/x", "SECRETrest"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "SECRETrest" not in captured.err
    assert "alice" not in captured.err


def test_visible_escapes_control_characters() -> None:
    """A message cannot carry a terminal command any further."""
    assert netspeed._visible("plain text") == "plain text"
    assert netspeed._visible("bell\x07") == "bell\\x07"
    assert netspeed._visible("esc\x1b]0;pwn\x07") == "esc\\x1b]0;pwn\\x07"
    assert netspeed._visible("line\nbreak") == "line\\nbreak"
    assert netspeed._visible("lone\ud800surrogate") == "lone\\ud800surrogate"


def test_transport_failure_escapes_server_text() -> None:
    """A hostile reason phrase reaches neither log nor message."""
    response = requests.Response()
    response.status_code = 500
    error = requests.HTTPError(
        "500 Server Error: \x1b]0;pwn\x07 for url: http://host/x",
        response=response,
    )

    failure = netspeed._transport_failure("http://host/x", 1, error)

    assert "\x1b" not in str(failure)
    assert "\x07" not in str(failure)
    assert "HTTP 500" in str(failure)


def test_failure_kind_names_the_likely_cause() -> None:
    """A timeout and a short response say more than their class name."""
    assert "timed out waiting for the response" in netspeed._failure_kind(
        requests.ReadTimeout("Read timed out.")
    )
    assert "timed out while connecting" in netspeed._failure_kind(
        requests.ConnectTimeout("Connection to h timed out.")
    )
    assert "ended before its declared size" in netspeed._failure_kind(
        requests.exceptions.ChunkedEncodingError("Read timed out.")
    )
    assert "unreachable or refused" in netspeed._failure_kind(
        requests.ConnectionError("refused")
    )
    assert "timed out waiting for the response" in netspeed._failure_kind(
        requests.ConnectionError("Read timed out.")
    )


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.SSLError("timed out during handshake"),
        requests.exceptions.TooManyRedirects("exceeded 30 redirects"),
        requests.exceptions.InvalidURL("no host"),
    ],
)
def test_failure_kind_keeps_the_class_when_it_speaks(
    error: requests.RequestException,
) -> None:
    """A class that names its own cause is not given another one."""
    assert netspeed._failure_kind(error) == type(error).__name__


@pytest.mark.parametrize(
    "tail",
    [
        "('CONNECT')",
        "500 Permission Denied",
        "502 Cannot connect to destination",
    ],
)
def test_failure_kind_reads_the_proxy_verdict_from_the_chain(
    tail: str,
) -> None:
    """A refused CONNECT tunnel is told apart from a dead proxy port."""
    try:
        raise OSError(f"Tunnel connection failed: {tail}")
    except OSError as refusal:
        error = requests.exceptions.ProxyError(refusal)
    assert "refused the CONNECT tunnel" in netspeed._failure_kind(error)


def test_failure_kind_names_an_unreached_proxy_without_a_tunnel() -> None:
    """Refusal before any tunnel is reported as an unreachable proxy."""
    error = requests.exceptions.ProxyError(
        ConnectionRefusedError(111, "Connection refused")
    )
    kind = netspeed._failure_kind(error)
    assert kind.startswith("ProxyError ")
    assert "the proxy is unreachable or refused" in kind
    assert "CONNECT" not in kind


@pytest.mark.parametrize(
    "token",
    [
        "-vvBLORPT",
        "-vvvvBLORPT",
        "-vBLORPT",
        "--verboseBLORPT",
        "--jsonBLORPT",
        "--no-warmupBLORPT",
        "--runsBLORPT",
    ],
)
def test_main_hides_a_secret_glued_to_an_option(
    token: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A tail argparse peels or a known option extends is withheld."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main([token, "http://ok.example/x"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "BLORPT" not in captured.err
    assert "***" in captured.err


@pytest.mark.parametrize(
    "token", ["-valice:pa VEXILrest", "-valice:pa  VEXILrest"]
)
def test_main_hides_a_split_secret_behind_a_cluster(
    token: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A rewritten token with a space hides all of its pieces."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main([token, "http://ok.example/x"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "VEXILrest" not in captured.err
    assert "alice" not in captured.err


@pytest.mark.parametrize(
    ("arguments", "message", "secret"),
    [
        (["-vSECRETpw"], "unrecognized arguments: -SECRETpw", "SECRETpw"),
        (
            ["-vSECRETpw"],
            "ignored explicit argument 'SECRETpw'",
            "SECRETpw",
        ),
        (
            ["-valice:pa VEXILrest"],
            "ignored explicit argument 'alice:pa VEXILrest'",
            "VEXILrest",
        ),
        (
            ["-valice:pa  VEXILrest"],
            "ignored explicit argument 'alice:pa  VEXILrest'",
            "VEXILrest",
        ),
    ],
)
def test_error_hides_a_cluster_remainder_in_every_spelling(
    arguments: list[str],
    message: str,
    secret: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A remainder argparse peels off a cluster is withheld.

    Interpreters disagree about the text of the message that names it:
    the tail of ``-vSECRETpw`` reaches the reader with the dash that was
    peeled and without it, and a remainder that holds whitespace arrives
    with only one of its two quotes. Every spelling has to be
    recognised, whatever interpreter produced it.
    """
    parser = netspeed.build_parser()
    parser.remember_arguments(arguments)

    with pytest.raises(SystemExit) as excinfo:
        parser.error(message)

    assert excinfo.value.code == 2
    assert secret not in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["-x", "http://ok.example/x"],
        ["--jsno", "http://ok.example/x"],
        ["http://ok.example/x", "http://ok.example/y"],
    ],
)
def test_main_keeps_ordinary_diagnostics_readable(
    argv: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A mistyped option or an extra URL is still named in the error."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(argv)

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert argv[0] in captured.err or argv[1] in captured.err


def test_main_reports_an_unencodable_url(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A URL the request layer cannot encode fails cleanly."""
    exit_code = netspeed.main(["http://alice:BLORPT\udcff@127.0.0.1:1/x"])

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "cannot be encoded" in captured.err
    assert "Traceback (most recent call last)" not in captured.err
    assert "BLORPT" not in captured.err
    assert "\udcff" not in captured.err


def test_format_report_escapes_the_url() -> None:
    """A control byte in the URL cannot reach the report raw."""
    results = [netspeed.RunResult(1, MIB, 0.1, 1.0, MIB, True)]

    report = netspeed.format_report(
        "http://127.0.0.1:1/x?\x1b[2J",
        results,
        netspeed.summarize(results),
        warmup=False,
    )

    assert "\x1b" not in report
    assert "\\x1b[2J" in report


def test_build_payload_carries_per_run_speeds() -> None:
    """Each JSON run exposes the speeds the table prints."""
    results = [netspeed.RunResult(1, MIB, 0.1, 1.0, MIB, True)]

    payload = netspeed.build_payload(
        "http://ok.example/x",
        results,
        netspeed.summarize(results),
        warmup=False,
    )

    runs = payload["runs"]
    assert isinstance(runs, list)
    run = runs[0]
    assert isinstance(run, dict)
    assert run["mib_per_s"] == pytest.approx(1.0)
    assert run["mbit_per_s"] == pytest.approx(8.388608)
    assert run["bytes_downloaded"] == MIB


def test_main_stays_fast_on_a_huge_argument_list() -> None:
    """A credential-free argv fails immediately, not quadratically.

    The list stays at the size where ``argparse`` itself is fast:
    before 3.13 it rescans every option index once per rejected token,
    so a longer list measures the interpreter rather than this module.
    The redaction of a large message is asserted on its own by
    :func:`test_redaction_runs_in_linear_time`.
    """
    argv = ["--zz%d" % index for index in range(5_000)]

    started = time.monotonic()
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main([*argv, "http://ok.example/x"])

    assert excinfo.value.code == 2
    assert time.monotonic() - started < 10.0


def test_chunk_size_error_quotes_the_value(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An out-of-range chunk size names the value that was rejected."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["--chunk-size", "0", "http://ok.example/x"])

    assert excinfo.value.code == 2
    assert "got '0'" in capsys.readouterr().err


def test_redaction_runs_in_linear_time() -> None:
    """A huge argument list cannot turn an error into a hang."""
    parser = netspeed.build_parser()
    argv = ["alice:pw"] * 5000
    parser.remember_arguments(argv)

    started = time.monotonic()
    with pytest.raises(SystemExit) as excinfo:
        parser.error("unrecognized arguments: " + " ".join(argv))

    assert excinfo.value.code == 2
    assert time.monotonic() - started < 10.0


def test_flush_stderr_tolerates_a_failing_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stderr that cannot be flushed does not raise."""
    monkeypatch.setattr(sys, "stderr", FullStderr())

    netspeed.flush_stderr()


def test_main_survives_a_full_stderr(
    payload_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed stderr write cannot change the exit status."""
    monkeypatch.setattr(sys, "stderr", FullStderr())

    assert netspeed.main([payload_url, "-n", "1"]) == 0


def test_main_returns_two_on_unsupported_scheme(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unsupported scheme exits with status 2 before any request."""
    exit_code = netspeed.main(["file:///etc/passwd"])

    assert exit_code == 2
    assert "unsupported scheme" in capsys.readouterr().err


def test_main_rejects_zero_runs(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--runs 0 is a usage error."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main([payload_url, "-n", "0"])

    assert excinfo.value.code == 2


def test_main_rejects_non_finite_timeout(
    payload_url: str,
) -> None:
    """A nan or infinite timeout is a usage error, not a crash."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main([payload_url, "-t", "inf"])

    assert excinfo.value.code == 2


def test_main_returns_130_on_interrupt(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ctrl-C ends with status 130 instead of a traceback."""

    def interrupt(*args: object, **kwargs: object) -> list[object]:
        """Raise as a user interrupt would.

        Args:
            *args: Ignored positional arguments.
            **kwargs: Ignored keyword arguments.

        Returns:
            Nothing; the call always raises.

        Raises:
            KeyboardInterrupt: Always.
        """
        raise KeyboardInterrupt

    monkeypatch.setattr(netspeed, "run_series", interrupt)

    exit_code = netspeed.main([payload_url])

    assert exit_code == 130
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "interrupted" in captured.err


def test_configure_logging_writes_to_current_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Diagnostics follow the stderr stream present at call time."""
    netspeed.configure_logging(verbose=False)
    netspeed.logger.info("probe message")

    assert "probe message" in capsys.readouterr().err


def test_configure_logging_verbose_enables_debug(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--verbose lowers the logger threshold to DEBUG."""
    netspeed.configure_logging(verbose=True)
    netspeed.logger.debug("debug message")

    assert "debug message" in capsys.readouterr().err


def _echo_password_once(
    listener: socket.socket,
    password: bytes,
    stop: threading.Event,
) -> None:
    """Answer every request with a header quoting the request password.

    Args:
        listener: Bound, listening socket.
        password: Password to echo in ``Content-Encoding``.
        stop: Event that ends the loop.
    """
    listener.settimeout(0.2)
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except OSError:
            return
        with conn:
            reader = conn.makefile("rb")
            while reader.readline() not in (b"\r\n", b"\n", b""):
                pass
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Encoding: "
                + password
                + b"\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n"
                + b"q" * 1000
            )


def test_measurement_hides_a_password_the_server_echoes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Server text quoting the request password is not logged."""
    password = "zq7secret99"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    stop = threading.Event()
    server = threading.Thread(
        target=_echo_password_once,
        args=(listener, password.encode(), stop),
        daemon=True,
    )
    server.start()
    url = f"http://alice:{password}@127.0.0.1:{listener.getsockname()[1]}/x"
    try:
        with caplog.at_level(logging.WARNING, logger="netspeed"):
            netspeed.main(["--no-warmup", "-n", "1", url])
    finally:
        stop.set()
        listener.close()
        server.join(timeout=5)

    assert password not in caplog.text
    assert "***" in caplog.text


@pytest.mark.parametrize("header", ["Content-Length", "Transfer-Encoding"])
def test_server_text_hides_every_tainted_header(header: str) -> None:
    """Every server header value is withheld on a tainted URL."""
    url = "http://alice:zq7secret99@127.0.0.1:1/x"
    response = requests.Response()
    response.headers[header] = "zq7secret99"

    hidden = netspeed._server_text(url, response.headers[header])

    assert hidden == "***"
    assert "zq7secret99" not in hidden


def test_server_text_keeps_a_clean_header_readable() -> None:
    """A credential-free URL still shows the header, escaped."""
    assert netspeed._server_text("http://host/x", "gzip") == "gzip"

    escaped = netspeed._server_text("http://host/x", "gzip\x1b]0;pwn\x07")

    assert "\x1b" not in escaped
    assert "\\x1b]0;pwn\\x07" in escaped
    assert netspeed._server_text(None, "gzip") == "gzip"


def test_declared_length_withholds_a_credentialed_header(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A malformed length echoing the password is not logged."""
    response = requests.Response()
    response.headers["Content-Length"] = "zq7secret99"

    with caplog.at_level(logging.WARNING, logger="netspeed"):
        declared = netspeed.declared_length(
            response, url="http://alice:zq7secret99@127.0.0.1:1/x"
        )

    assert declared is None
    assert "zq7secret99" not in caplog.text
    assert "***" in caplog.text


@pytest.mark.parametrize("text", ["²", "①", "١٢٣", "١٢٣٤٥٦"])
def test_port_like_unicode_digits_do_not_crash(text: str) -> None:
    """Digit-like characters that ``int()`` rejects are not a port."""
    url = f"http://alice:{text}@127.0.0.1:1/x"

    redacted = netspeed.redact_url(url)

    assert text not in redacted
    assert netspeed._is_port(text) is False


def test_main_handles_a_unicode_digit_port(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A port made of non-ASCII digits exits 2 instead of raising."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["http://ok.example/x", "http://alice:²"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "²" not in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:0/x",
        "http://127.0.0.1:65536/x",
        "http://127.0.0.1:99999999999999999999/x",
        "http://127.0.0.1:abc/x",
        "http://127.0.0.1:/x",
        "http://[::1]:/x",
        "http://alice:²",
    ],
)
def test_main_rejects_an_unusable_port(
    url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A port outside 1..65535 is a usage error, not a request."""
    exit_code = netspeed.main([url])

    assert exit_code == 2
    captured = capsys.readouterr()
    assert "port must be a number between 1 and 65535" in captured.err
    assert url not in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:1/x",
        "http://h:65535/x",
        "http://h:00080/x",
        "http://h:065535/x",
        "http://h:" + "0" * 40 + "80/x",
        "http://[::1]:8080/x",
        "http://[2001:db8::1]/x",
        "http://alice:pw@h:8080/x",
        "http://h/x?a:b",
    ],
)
def test_validate_url_keeps_a_usable_authority(url: str) -> None:
    """Real hosts, real ports, and colons outside the authority pass."""
    assert netspeed.validate_url(url) == url


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("1", True),
        ("65535", True),
        ("065535", True),
        ("00080", True),
        ("0" * 40 + "80", True),
        ("0", False),
        ("000", False),
        ("65536", False),
        ("²", False),
        ("", False),
        ("80 ", False),
    ],
)
def test_is_port_judges_the_value_not_the_spelling(
    text: str,
    expected: bool,
) -> None:
    """Leading zeros are padding, and any other text is not a port."""
    assert netspeed._is_port(text) is expected


@pytest.mark.parametrize("value", [".5", "15.", "0.5"])
def test_timeout_accepts_every_plain_decimal(value: str) -> None:
    """A decimal spelling with an empty side is still a number."""
    assert netspeed.timeout_seconds(value) == pytest.approx(float(value))


@pytest.mark.parametrize("value", ["1e9", "inf", "nan", "1_0"])
def test_timeout_calls_a_non_decimal_spelling_a_spelling(
    value: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A number in another notation is called a spelling problem."""
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main(["-t", value, "http://127.0.0.1:1/x"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "plain decimal number" in captured.err
    assert "greater than 0" not in captured.err


@pytest.mark.parametrize(
    ("text", "expected"),
    [("0000000010", 10), ("1024", 1024), ("0" * 40 + "1", 1)],
)
def test_zero_padded_numbers_are_padding_not_range(
    text: str,
    expected: int,
) -> None:
    """Leading zeros do not push a valid value out of range."""
    assert netspeed._unsigned_digits(text, "runs") == expected


@pytest.mark.parametrize("text", ["0" * 9 + "1" * 10, "1" * 10])
def test_out_of_range_numbers_are_still_rejected(text: str) -> None:
    """The digit limit still applies to the value, not its padding."""
    with pytest.raises(argparse.ArgumentTypeError):
        netspeed._unsigned_digits(text, "runs")


def test_main_accepts_a_zero_padded_run_count(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A padded count reaches measurement instead of failing usage."""
    code = netspeed.main(["--runs", "0000000003", "http://127.0.0.1:1/x"])

    assert code == 1
    assert "out of range" not in capsys.readouterr().err


def test_validate_proxy_accepts_spellings() -> None:
    """http(s) and socks proxies and a bare host:port are accepted."""
    assert netspeed.validate_proxy("http://g:3128") == "http://g:3128"
    assert netspeed.validate_proxy("https://g:8443") == "https://g:8443"
    assert netspeed.validate_proxy("socks5://g:1080") == "socks5://g:1080"
    assert netspeed.validate_proxy("g:3128") == "g:3128"


@pytest.mark.parametrize(
    "proxy",
    [
        "ftp://g:3128",
        "http:/missing-slash",
        "http:///x",
        "http://g:99999",
        "g:notaport",
        "g:notaport/",
    ],
)
def test_validate_proxy_rejects_unusable_urls(proxy: str) -> None:
    """A proxy the transport could not use is refused before connecting."""
    with pytest.raises(argparse.ArgumentTypeError):
        netspeed.validate_proxy(proxy)


def test_validate_proxy_refusal_never_echoes_the_argument() -> None:
    """A credential typed in the proxy does not reach the error text."""
    with pytest.raises(argparse.ArgumentTypeError) as excinfo:
        netspeed.validate_proxy("http://alice:s3cr3t@g:99999")

    assert "s3cr3t" not in str(excinfo.value)


def test_apply_proxy_covers_both_schemes() -> None:
    """The proxy mapping lists http and https, so HTTPS tunnels too."""
    session = requests.Session()
    try:
        netspeed.apply_proxy(session, "http://g:3128")
        assert session.proxies == {
            "http": "http://g:3128",
            "https": "http://g:3128",
        }
    finally:
        session.close()


def test_session_route_sets_the_proxy_and_unlocks_the_environment() -> None:
    """A routed session carries the proxy and distrusts the env vars."""
    with netspeed.session_route("http://g:3128") as (session, proxy):
        assert proxy == "http://g:3128"
        assert session.proxies["http"] == "http://g:3128"
        assert session.proxies["https"] == "http://g:3128"
        assert session.trust_env is False


def test_session_route_direct_pins_the_session_to_the_wire() -> None:
    """Without a proxy the session is direct and ignores http_proxy."""

    session_holder: list[requests.Session] = []
    with netspeed.session_route(None) as (session, proxy):
        session_holder.append(session)
        assert proxy is None
        assert session.trust_env is False

    assert session_holder[0].proxies == {}


def test_main_routes_through_a_local_forward_proxy(
    proxy: ForwardProxy,
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--proxy sends every request through the named proxy."""
    exit_code = netspeed.main(
        [payload_url, "-n", "2", "--no-warmup", "-p", proxy.base_url]
    )

    assert exit_code == 0
    assert len(proxy.plain_requests) == 2
    assert all(line.startswith("GET http://") for line in proxy.plain_requests)
    assert "Proxy: " in capsys.readouterr().out


def test_main_https_target_tunnels_through_the_proxy(
    server: LocalServer,
    proxy: ForwardProxy,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An https:// target is tunnelled, CONNECT names the authority."""
    tls_target = server.base_url.replace("http://", "https://")
    exit_code = netspeed.main(
        [tls_target, "-n", "1", "--no-warmup", "-p", proxy.base_url]
    )

    assert exit_code == 1  # the plain local server cannot speak TLS
    assert proxy.plain_requests == []  # nothing leaked in plain form
    assert proxy.connects == [server.base_url.split("//")[1]]


def test_main_reports_a_routed_measurement_in_json(
    proxy: ForwardProxy,
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """--json carries the proxy, redacted, alongside the URL."""
    credentialed = "http://alice:s3cr3t@" + proxy.base_url.split("//")[1]
    exit_code = netspeed.main(
        [payload_url, "-n", "1", "--json", "--no-warmup", "-p", credentialed]
    )

    assert exit_code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["proxy"] == "http://***@" + proxy.base_url.split("//")[1]
    assert "s3cr3t" not in out


def test_main_failure_message_hides_proxy_credentials(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A failing proxied run never writes the proxy password to stderr."""
    exit_code = netspeed.main(
        [
            "http://127.0.0.1:1/big.jpg",
            "-n",
            "1",
            "-p",
            "http://alice:s3cr3t@127.0.0.1:1",
        ]
    )

    assert exit_code == 1
    captured = capsys.readouterr()
    assert "s3cr3t" not in captured.err
    assert "measurement failed" in captured.err


def test_main_keeps_the_environment_out_of_the_route(
    payload_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ambient proxy variables do not route an unqualified run."""
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
    ):
        monkeypatch.setenv(name, "http://127.0.0.1:1")

    assert netspeed.main([payload_url, "-n", "1", "--no-warmup"]) == 0


def test_main_failure_with_socks_proxy_names_the_dependency(
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A SOCKS proxy without PySocks fails with a hint, not a crash."""
    if importlib.util.find_spec("socks") is not None:
        pytest.skip("PySocks is installed; the hint path is unreachable")

    exit_code = netspeed.main(
        [payload_url, "-n", "1", "-p", "socks5://127.0.0.1:1"]
    )

    assert exit_code == 1
    assert "PySocks" in capsys.readouterr().err


def test_main_rejects_a_bad_proxy_before_any_request(
    server: LocalServer,
    payload_url: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """An unusable proxy is a usage error, not a transport failure."""
    seen = len(server.requests_seen)
    with pytest.raises(SystemExit) as excinfo:
        netspeed.main([payload_url, "-n", "1", "-p", "http://g:99999"])

    assert excinfo.value.code == 2
    captured = capsys.readouterr()
    assert "proxy port" in captured.err
    assert len(server.requests_seen) == seen


@pytest.mark.parametrize(
    "proxy",
    [
        "socks5://127.0.0.1:9050",
        "socks4://127.0.0.1:1080",
    ],
)
def test_failed_run_suggests_remote_dns_spelling(
    proxy: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A dying client-resolving socks run advertises socks5h/socks4a."""
    assert (
        netspeed.main(["http://127.0.0.1:1/big.jpg", "-n", "1", "-p", proxy])
        == 1
    )
    sibling = "socks5h" if proxy.startswith("socks5") else "socks4a"
    assert f"spelled {sibling}" in capsys.readouterr().err


def test_failed_http_proxy_run_stays_quiet_about_dns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The dns suggestion belongs to client-resolving socks alone."""
    assert (
        netspeed.main(
            [
                "http://127.0.0.1:1/big.jpg",
                "-n",
                "1",
                "-p",
                "http://127.0.0.1:1",
            ]
        )
        == 1
    )
    assert "resolves the hostname" not in capsys.readouterr().err


def test_parses_remote_dns_scheme_for_failures() -> None:
    """Only bare socks4/socks5 map to a remote-resolving sibling."""
    assert netspeed._remote_dns_scheme("socks5://g:9050") == "socks5h"
    assert netspeed._remote_dns_scheme("socks4://g:1080") == "socks4a"
    assert netspeed._remote_dns_scheme("socks5h://g:9050") is None
    assert netspeed._remote_dns_scheme("http://g:3128") is None


def test_parsed_proxy_defaults_to_none() -> None:
    """Without the option the route stays direct (proxy is None)."""
    args = netspeed.build_parser().parse_args(["http://example.com/x"])

    assert args.proxy is None
