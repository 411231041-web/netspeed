# netspeed

[![CI](https://github.com/411231041-web/netspeed/actions/workflows/ci.yml/badge.svg)](https://github.com/411231041-web/netspeed/actions/workflows/ci.yml)

Russian version: [README.ru.md](README.ru.md)

Measures download speed from this machine by fetching one URL several
times in sequence and reporting the average throughput.

## What it measures

- **Speed** — body bytes divided by body transfer time. The header
  phase (DNS, TCP, TLS) is excluded, so a slow handshake cannot distort
  the figure.
- **TTFB** — time from starting the request to receiving the response
  headers, reported separately.
- **Units** — `MiB/s` is `1024**2` bytes per second, which many tools
  label "MB/s"; `Mbit/s` is `10**6` bits per second. Both are printed,
  because "MB/s" alone is ambiguous.
- **Statistics** — 10 sequential requests by default. The report shows
  the average request time, the mean of the per-run speeds (the
  headline the task asks for), the pooled rate
  (`total bytes / total measured time`, which differs from the mean when
  runs moved different volumes), the median, the extremes, and the
  sample standard deviation, which a single run reports as not
  applicable.

Each measured run reuses one `requests.Session`, so DNS, TCP, and TLS
happen once and the runs share a single keep-alive connection — for a
target that keeps the connection alive and does not redirect. A `3xx`
answer is followed transparently: its round trips land in the header
phase (TTFB) and in the mean request time, but not in the speed
denominator, which is the body time; the body measured is that of the
final target while the report keeps naming the URL that was requested,
and a server that answers `Connection: close` costs one connection per
run. One extra warm-up request is sent first and discarded from the
statistics.

## How the volume is counted

- `Accept-Encoding: identity` is requested, so a cooperating server
  sends the body uncompressed and the counted bytes are the bytes on
  the wire (plus nothing else — no headers, no chunk framing).
- A server that compresses anyway is still measured, but the count is
  then the *decoded* size; the run is flagged with a warning on stderr
  and counted as not size-verified.
- When the server sends `Content-Length` and the response carries
  neither a content encoding nor a transfer encoding, the received size
  must match it exactly. A short transfer aborts the whole measurement
  with exit code 1 instead of entering the average as a good run. The
  comparison covers the bytes the client reads: a server that keeps
  writing past its own `Content-Length` is counted to the declared size
  and the surplus is discarded unread, which no client can observe
  without a second, speculative read.
- A `Transfer-Encoding` header takes precedence over a contradicting
  `Content-Length`, as RFC 9112 section 6.3 requires. Chunked framing is
  validated by the HTTP layer, so a truncated chunked body fails the
  run; any other coding leaves the size unverified.
- A close-delimited body (HTTP/1.0 style, no framing) that ends early
  cannot be detected: without a usable `Content-Length` the run is
  accepted with a warning, and the report adds a note that the size
  could not be verified.

The body is streamed in 64 KiB chunks and never held in memory, so a
multi-gigabyte file is a safe target.

## Requirements

Python 3.10 or newer and the packages in `requirements.txt`.

## Install

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```sh
# 10 measured requests plus a discarded warm-up
python netspeed.py https://speed.cloudflare.com/__down?bytes=25000000

# 5 requests, 30-second socket timeout, no warm-up
python netspeed.py -n 5 -t 30 --no-warmup https://example.com/big.jpg

# machine-readable output
python netspeed.py --json https://example.com/big.jpg

# per-run detail and tracebacks on stderr
python netspeed.py -v https://example.com/big.jpg

# through a forward proxy; a bare host:port counts as http://
python netspeed.py -p http://proxy.com:3128 https://example.com/big.jpg

# a proxy with credentials; they reach the proxy but are printed as ***
python netspeed.py -p http://user:pass@proxy.com:3128 https://example.com/big.jpg

# a SOCKS proxy, e.g. the Tor daemon; needs the PySocks package
python netspeed.py -p socks5://127.0.0.1:9050 https://example.com/big.jpg

# the same through remote DNS (recommended for Tor): the proxy itself
# resolves the hostname
python netspeed.py -p socks5h://127.0.0.1:9050 https://example.com/big.jpg
```

Options: `-n/--runs` (1..1000, default 10), `-t/--timeout` (up to 3600
seconds, default 15), `--chunk-size` (up to 16 MiB, default 64 KiB),
`--no-warmup`, `-p/--proxy`, `--json`, `-v/--verbose`. `--runs` and
`--chunk-size` are whole numbers and `--timeout` a decimal number of
seconds; leading zeros are padding.

By default the measurement connects directly and proxy environment
variables (`http_proxy`, `HTTPS_PROXY`, …) are ignored, so the route in
force is always the one the invocation names. `-p/--proxy` routes every
request through the given proxy instead — an `https://` target is sent
through it as a `CONNECT` tunnel — and the report and the JSON payload
then name the proxy, with any `user:password` in it redacted. The proxy
must speak http or one of the socks spellings and obeys the same host
and port rules as the URL argument; a bad proxy is a usage error before
any request is made. A bare `host:port` counts as `http://` — a SOCKS
endpoint (say, the Tor daemon listening on `127.0.0.1:9050`) needs an
explicit scheme, preferably `socks5h://`, where the proxy itself
resolves the hostname. The `socks5://` and `socks4://` spellings resolve
the name on this machine, which can leave the proxy chasing an address
picked for this network; when such a run fails, the report suggests
their remote-resolving siblings (`socks5h://`, `socks4a://`) instead.
SOCKS additionally needs the `PySocks` package, which the transport
error names when the dependency is missing.

`--timeout` is a socket timeout applied to the connection attempt and to
each read, so it limits inactivity rather than the total duration of a
run: a server that drips one byte at a time can keep a single run alive
longer than the timeout. Use a large file and a reasonable `-n` for a
meaningful number.

Credentials in the URL (`http://user:pass@host/file`) are used for the
request but replaced by `***` in the report, in the JSON payload, and in
every error message, including the ones quoting a failed argument. The
redaction fails closed and errs towards hiding too much. Hidden are:

* a credential typed without a scheme (`user:pass`), as an option value,
  or split across arguments by a space, where the arguments around the
  piece carrying the delimiter are hidden with it — up to the next whole
  `scheme://` URL, which stays readable because it is the part of the
  message most worth seeing;
* an argument whose prefix only looks like a scheme (`user:pass://host`),
  which is treated as a credential, not as a URL;
* text whose prefix is not a scheme, hidden whole once it holds a colon
  or an at sign, since either may be a lost `user:password`;
* percent-encoded delimiters (`alice%3ASECRETpw%40host`, and the
  double-encoded spelling), which are decoded, repeatedly, before that
  test; a text whose escapes never settle is hidden as well;
* a URL argument whose last at sign lies outside its authority, such as
  `?u=user@secret` or a path like `mail@example.com`, which is hidden
  whole, because an at sign is read as a credential delimiter wherever it
  stands; when the at sign is real userinfo, the text behind it is held
  to these same rules, so a password repeated there is hidden too as
  soon as it carries a delimiter of its own — a spelling without one is
  one of the three blind spots listed below;
* a URL argument containing whitespace, and one carrying a colon outside
  its authority, such as a query or a fragment like `?u=user:pass`;
* an authority that is not a bare host or a host with one port in
  `1..65535`, whether the port is non-numeric, out of range, or empty,
  or a second colon follows it, as in `http://alice:pw:8080/x`; an IPv6
  literal is held to the same rule inside its brackets, so
  `http://[::1]:user:pw/x` is hidden too. Such a URL is also rejected
  before any request is made, with a usage error that states the port
  rule and never repeats the argument;
* a value that belongs to an option, whether separated (`-n secret`),
  assigned (`--runs=secret`), glued to a known flag (`-vsecret`,
  `-vvsecret`), or added to a known option name (`--jsonsecret`); and a
  value the tool rejects, which is quoted only when every character of it
  could have been part of the number asked for;
* any transport detail a library reports, which `-v` withholds whenever
  the URL had to be redacted, because that detail can quote the
  credential without its scheme.

Three spellings cannot be recognised by syntax alone, and all are best
avoided: a bare secret attached to no colon and no at sign, whether it
stands alone (`netspeed.py URL SECRET`), is glued to an unknown option
(`-xSECRET`), or sits in a path, query, or fragment, encoded or not; a
numeric password that reads as a valid port, such as
`http://alice:1234`; and a delimiter written with a lookalike character,
such as a fullwidth colon. An unknown option is left readable on
purpose, so that a mistyped `--jsno` is still named in the error.
Over-redaction costs a scheme, host, or path in the output; only the
request itself keeps the full URL.

Text a server supplies is escaped rather than printed raw — the
`Content-Encoding` and `Transfer-Encoding` header values, the
`Content-Length` value, and the reason phrase of a failing status line —
so a hostile server cannot drive the terminal through `-v`. Those header
values are withheld entirely, and not merely escaped, when the URL
carries credentials: the target receives that userinfo as basic
authentication and can echo it back, so nothing it sends is trusted to be
free of them.

## Example output

```
URL: https://speed.cloudflare.com/__down?bytes=25000000
Runs measured: 3 (warm-up excluded)

  #        MiB   TTFB s   body s  basis s      MiB/s     Mbit/s
  1      23.84    0.040    1.974    1.974      12.08      101.3
  2      23.84    0.039    2.210    2.210      10.79       90.5
  3      23.84    0.036    2.239    2.239      10.65       89.3

Summary
  total downloaded: 75000000 bytes (71.53 MiB)
  mean TTFB:        0.038 s
  mean body time:   2.141 s
  mean request:     2.179 s
  mean of runs:     11.17 MiB/s = 93.7 Mbit/s
  aggregate:        11.13 MiB/s = 93.4 Mbit/s (total bytes / total measured time)
  median:           10.79 MiB/s = 90.5 Mbit/s
  min / max:        10.65 / 12.08 MiB/s
  std deviation:    0.79 MiB/s
```

`mean request` is the average request time (TTFB plus body time) the
task asks for. `basis s` is the time actually used as the denominator:
the body time, or the full request time in the rare case where the body
arrived with the headers and no body time could be measured.

`--json` prints the same figures machine-readably: the URL, one object
per run with its byte count, phases, declared size, verification flag,
and both speeds, plus the summary and the units used.

Pick a target file of at least a few megabytes; a small file measures
latency rather than throughput and the numbers will be meaningless.

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | Measurement completed |
| 1 | A request or response failed (transport error, 4xx/5xx, empty body, size mismatch, unmeasurable run), or the report could not be written |
| 2 | Unusable arguments (non-http(s) URL, unusable port, bad `--runs`, `--timeout`, `--chunk-size`, or `--proxy`) |
| 130 | Interrupted by the user (Ctrl-C) |

A failed run aborts the series; no partial average is printed.

## Tests

```sh
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest
flake8 .
isort --check-only --diff .
black --line-length 79 --check --diff .
mypy .
```

CI (`.github/workflows/ci.yml`) runs the same checks on every push to
`main` and every pull request: the four checks once, on Python 3.13, and
`pytest` on Python 3.10 through 3.14.

The suite starts a local HTTP server and a local forward proxy on
ephemeral ports, so it needs no network access. The same server can be
run by hand as a measurement target, which is useful on a machine with
no internet access:

```sh
python tests/http_server.py --port 8123
# in another terminal
python netspeed.py -n 3 http://127.0.0.1:8123/payload
```

The proxy can be exercised the same way:

```sh
python tests/http_proxy.py
# in another terminal
python netspeed.py -n 3 -p http://127.0.0.1:<port> http://127.0.0.1:8123/payload
```

## Layout

```
netspeed.py                 measurement CLI
tests/http_server.py        local target server used by the tests
tests/http_proxy.py         local forward proxy used by the tests
tests/conftest.py           pytest fixtures (server, proxy, endpoint URLs)
tests/test_netspeed.py      test suite
.github/workflows/ci.yml    GitHub Actions workflow: tests and lint
setup.cfg                   flake8 and isort configuration
requirements.txt            runtime dependency
requirements-dev.txt        test and lint tooling
```

The tests run against the `.venv` virtual environment, which
`.gitignore` keeps out of version control.
