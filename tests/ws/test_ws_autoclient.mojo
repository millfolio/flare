"""Unit tests for the WS ALPN-driven auto-dispatcher
(``flare.ws.auto_client`` -- Track Q8 scaffold).

The decision function :func:`decide_wire` is the pure piece the
dispatcher consults after the TLS handshake completes; this
suite pins every observable outcome at the byte level.  The
runtime hand-off to :class:`flare.ws.WsClient` /
:class:`flare.ws.WsOverH2Stream` ships in the Track Q8 follow-up;
:meth:`WsAutoClient.connect` raises with a clear message today.

The 12 test cases:

1.  `prefer_h2 = True` default, with the runtime hint matrix
    that flows through the pure decision function.
2.  Cleartext ``ws://`` always routes to HTTP/1.1.
3.  TLS ``wss://`` with ``prefer_h2=False`` forces HTTP/1.1.
4.  TLS ``wss://`` + ALPN ``h2`` + ENABLE_CONNECT_PROTOCOL=1
    routes to HTTP/2 (the new path).
5.  TLS ``wss://`` + ALPN ``h2`` + no CONNECT-Protocol bit
    falls back to HTTP/1.1 (RFC 8441 §3 mandates the toggle).
6.  TLS ``wss://`` + ALPN ``http/1.1`` routes to HTTP/1.1.
7.  TLS ``wss://`` + empty ALPN (no extension) -> HTTP/1.1.
8.  Unknown ALPN identifier -> FAILED.
9.  Garbage URL scheme -> FAILED.
10. :meth:`WsAutoClient.url_scheme` parses ``wss://...``.
11. :meth:`WsAutoClient.url_scheme` parses ``ws://...``.
12. :meth:`WsAutoClient.connect` raises pending the Track Q8
    follow-up commit.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.ws import (
    WsAutoClient,
    WsAutoClientConfig,
    WsWireChoice,
    decide_wire,
)


def _config_for(url: String, prefer_h2: Bool = True) -> WsAutoClientConfig:
    var cfg = WsAutoClientConfig()
    cfg.url = url
    cfg.prefer_h2 = prefer_h2
    return cfg^


def test_wire_choice_codepoints() raises:
    """Stable codepoints so the dispatcher can switch on them
    monomorphically + tests can pin specific outcomes."""
    assert_equal(WsWireChoice.UNDETERMINED, 0)
    assert_equal(WsWireChoice.HTTP_1_1, 1)
    assert_equal(WsWireChoice.HTTP_2, 2)
    assert_equal(WsWireChoice.FAILED, 3)


def test_config_defaults() raises:
    """A default config picks WS-over-h2 if possible (the v0.8
    Phase D production posture)."""
    var cfg = WsAutoClientConfig()
    assert_equal(cfg.url, String(""))
    assert_true(cfg.prefer_h2)
    assert_equal(len(cfg.subprotocols), 0)
    assert_equal(len(cfg.extensions), 0)


def test_decide_wire_cleartext_ws_skips_h2() raises:
    """``ws://`` (cleartext) always picks HTTP/1.1, regardless of
    the prefer_h2 toggle.  TLS is the precondition for any h2
    upgrade per RFC 8441 §1."""
    var pick = decide_wire(String("ws"), True, String(""), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_prefer_h2_false_forces_h1() raises:
    """``wss://`` with ``prefer_h2=False`` forces HTTP/1.1."""
    var pick = decide_wire(String("wss"), False, String("h2"), True)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_h2_alpn_with_connect_protocol() raises:
    """The happy h2 path: ``wss://`` + prefer_h2 + ALPN ``h2`` +
    ``ENABLE_CONNECT_PROTOCOL=1`` -> WS-over-h2."""
    var pick = decide_wire(String("wss"), True, String("h2"), True)
    assert_equal(pick, WsWireChoice.HTTP_2)


def test_decide_wire_wss_h2_alpn_without_connect_protocol() raises:
    """ALPN h2 but the server didn't advertise the CONNECT-
    Protocol setting -> fall back to HTTP/1.1 (RFC 8441 §3)."""
    var pick = decide_wire(String("wss"), True, String("h2"), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_http11_alpn() raises:
    """The server picked http/1.1 in ALPN -> HTTP/1.1 wire."""
    var pick = decide_wire(String("wss"), True, String("http/1.1"), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_wss_no_alpn() raises:
    """TLS without ALPN (older TLS or server with no advertise)
    -> HTTP/1.1."""
    var pick = decide_wire(String("wss"), True, String(""), False)
    assert_equal(pick, WsWireChoice.HTTP_1_1)


def test_decide_wire_unknown_alpn_fails() raises:
    """An ALPN identifier the dispatcher doesn't understand
    -> FAILED.  The caller surfaces this as a connect-time
    error rather than silently downgrading to HTTP/1.1."""
    var pick = decide_wire(String("wss"), True, String("h3"), False)
    assert_equal(pick, WsWireChoice.FAILED)


def test_decide_wire_invalid_scheme_fails() raises:
    """A garbage URL scheme means the caller passed a bug; the
    dispatcher returns FAILED to surface it."""
    var pick = decide_wire(String("ftp"), True, String("h2"), True)
    assert_equal(pick, WsWireChoice.FAILED)


def test_url_scheme_parses_wss() raises:
    """The carrier's URL parser recognises ``wss://``."""
    var cfg = _config_for(String("wss://example.com/chat"))
    var auto = WsAutoClient(cfg^)
    assert_equal(auto.url_scheme(), String("wss"))


def test_url_scheme_parses_ws() raises:
    """The carrier's URL parser recognises ``ws://``."""
    var cfg = _config_for(String("ws://example.com/chat"))
    var auto = WsAutoClient(cfg^)
    assert_equal(auto.url_scheme(), String("ws"))


def test_connect_raises_pending_wiring() raises:
    """:meth:`WsAutoClient.connect` raises with a Track Q8 follow-up
    pointer.  The decision logic + carrier are in place;
    plumbing through to :class:`flare.ws.WsClient` /
    :class:`flare.ws.WsOverH2Stream` is the focused follow-up."""
    var cfg = _config_for(String("wss://example.com/chat"))
    var auto = WsAutoClient(cfg^)
    var raised = False
    try:
        auto.connect()
    except:
        raised = True
    assert_true(raised, "expected WsAutoClient.connect to raise")


def main() raises:
    test_wire_choice_codepoints()
    test_config_defaults()
    test_decide_wire_cleartext_ws_skips_h2()
    test_decide_wire_wss_prefer_h2_false_forces_h1()
    test_decide_wire_wss_h2_alpn_with_connect_protocol()
    test_decide_wire_wss_h2_alpn_without_connect_protocol()
    test_decide_wire_wss_http11_alpn()
    test_decide_wire_wss_no_alpn()
    test_decide_wire_unknown_alpn_fails()
    test_decide_wire_invalid_scheme_fails()
    test_url_scheme_parses_wss()
    test_url_scheme_parses_ws()
    test_connect_raises_pending_wiring()
    print("test_ws_autoclient: 13 passed")
