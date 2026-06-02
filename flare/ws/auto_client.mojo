"""`flare.ws.auto_client` -- ALPN-driven WebSocket client dispatcher
(Track Q8 scaffold).

WebSocket has two carrying wires:

* HTTP/1.1 ``Upgrade: websocket`` (RFC 6455) -- the original
  bootstrap. Always available.
* HTTP/2 Extended CONNECT (RFC 8441) -- the modern variant. The
  server MUST advertise ``SETTINGS_ENABLE_CONNECT_PROTOCOL = 1``
  for the client to use it.

The choice between the two is naturally ALPN-driven: when the
TLS handshake on a ``wss://`` URL negotiates ALPN ``"h2"`` and
the h2 SETTINGS frame includes ``ENABLE_CONNECT_PROTOCOL = 1``,
the client runs WS-over-h2; otherwise it falls back to the
HTTP/1.1 path.

The v0.7 cycle shipped the WS-over-h2 *primitive*
(:class:`flare.ws.WsOverH2Stream` and
:func:`flare.ws.bootstrap_ws_over_h2`). The v0.8 Phase D cycle
absorbs the high-level ALPN-driven *dispatcher* (this module).

## Scope of this commit (Track Q8 scaffold)

The decision logic + the carrier shape land today; the full
runtime dispatch (opening a TLS + h2 client connection,
inspecting the negotiated ALPN, observing SETTINGS, opening the
Extended CONNECT stream, then handing off to
:class:`WsOverH2Stream`) is the focused follow-up commit. The
intent of this scaffold is the same as the other Q-tracks: lock
the API + make every observable decision testable + raise a
clear error from any path that depends on the deferred runtime
wiring.

References:
- RFC 6455 "The WebSocket Protocol" -- HTTP/1.1 path.
- RFC 8441 "Bootstrapping WebSockets with HTTP/2" -- h2 path.
- RFC 7301 "ALPN" -- the wire-selection mechanism.
"""

from std.collections import List


# ── Wire choice codepoints ─────────────────────────────────────────────


struct WsWireChoice:
    """Stable codepoints for the wire :class:`WsAutoClient` picks
    after the runtime negotiation completes. The reactor / call-
    site dispatches on these to pick the carrier driver.
    """

    comptime UNDETERMINED: Int = 0
    """The dispatcher hasn't run :meth:`WsAutoClient.connect` yet.
    The initial carrier state."""

    comptime HTTP_1_1: Int = 1
    """RFC 6455 over an HTTP/1.1 Upgrade stream.  Used when:
    - the URL scheme is ``ws://`` (no TLS, no ALPN), OR
    - ``prefer_h2 = False``, OR
    - the TLS handshake negotiated ALPN ``http/1.1``, OR
    - the negotiated h2 connection didn't advertise
      ``ENABLE_CONNECT_PROTOCOL = 1`` (RFC 8441 §3)."""

    comptime HTTP_2: Int = 2
    """RFC 8441 Extended CONNECT over an HTTP/2 stream.  Used
    when the URL scheme is ``wss://``, ``prefer_h2 = True``,
    the TLS handshake negotiated ALPN ``h2``, and the negotiated
    h2 connection's SETTINGS frame includes
    ``ENABLE_CONNECT_PROTOCOL = 1``."""

    comptime FAILED: Int = 3
    """The dispatcher attempted to connect but the underlying
    TCP / TLS / h2 handshake failed before reaching the
    application protocol decision.  See
    :attr:`WsAutoClient.last_error` for the per-attempt reason."""


# ── Configuration carrier ──────────────────────────────────────────────


struct WsAutoClientConfig(Copyable, Defaultable, Movable):
    """Inputs to :class:`WsAutoClient`'s wire-selection.

    The carrier holds the URL + the protocol preferences; the
    dispatcher consults this carrier when running its decision
    sequence.  The carrier is value-typed + copyable so call
    sites can build a base config, clone it, and tweak per-call.
    """

    var url: String
    """The target URL.  ``ws://`` skips TLS + uses the HTTP/1.1
    wire unconditionally; ``wss://`` runs TLS + consults
    :attr:`prefer_h2` and the ALPN outcome."""

    var prefer_h2: Bool
    """When True (default), the client advertises both ``h2``
    and ``http/1.1`` in ALPN and runs WS-over-h2 if the server
    picks ``h2`` AND advertises
    ``ENABLE_CONNECT_PROTOCOL = 1``.  When False the client
    advertises only ``http/1.1`` and skips the h2 path entirely.
    """

    var subprotocols: List[String]
    """RFC 6455 §1.9 / RFC 8441 §5.1 Sec-WebSocket-Protocol
    candidates.  Empty list means "no subprotocol request",
    which is the protocol's default."""

    var extensions: List[String]
    """RFC 6455 §9.1 / RFC 8441 §5.1 Sec-WebSocket-Extensions
    candidates (e.g. ``"permessage-deflate; client_no_context_takeover"``).
    Empty list means "no extension request"."""

    def __init__(out self):
        self.url = String("")
        self.prefer_h2 = True
        self.subprotocols = List[String]()
        self.extensions = List[String]()


# ── Decision function ──────────────────────────────────────────────────


def decide_wire(
    url_scheme: String,
    prefer_h2: Bool,
    negotiated_alpn: String,
    h2_advertises_connect_protocol: Bool,
) -> Int:
    """The pure WS-wire decision the dispatcher executes after the
    TLS handshake completes.

    Inputs:

    - ``url_scheme`` -- ``"ws"`` (cleartext) or ``"wss"`` (TLS).
    - ``prefer_h2`` -- whether the carrier advertised ALPN ``h2``
      alongside ``http/1.1``.
    - ``negotiated_alpn`` -- the protocol the TLS handshake
      picked; empty when no ALPN was negotiated (cleartext or
      old TLS).
    - ``h2_advertises_connect_protocol`` -- whether the h2 peer's
      SETTINGS frame advertised ``ENABLE_CONNECT_PROTOCOL = 1``
      per RFC 8441 §3.  Only meaningful when the negotiated ALPN
      is ``h2``.

    The function is pure + testable without any I/O.  The runtime
    dispatcher (deferred to the Track Q8 follow-up) plumbs the
    real values from the TLS + h2 layers into this call.
    """
    if url_scheme == "ws":
        return WsWireChoice.HTTP_1_1
    if url_scheme != "wss":
        return WsWireChoice.FAILED
    if not prefer_h2:
        return WsWireChoice.HTTP_1_1
    if negotiated_alpn == "h2":
        if h2_advertises_connect_protocol:
            return WsWireChoice.HTTP_2
        return WsWireChoice.HTTP_1_1
    if negotiated_alpn == "http/1.1":
        return WsWireChoice.HTTP_1_1
    if negotiated_alpn == "":
        return WsWireChoice.HTTP_1_1
    return WsWireChoice.FAILED


# ── Client carrier ─────────────────────────────────────────────────────


struct WsAutoClient(Movable):
    """High-level WebSocket client that picks the carrying wire
    at runtime based on negotiated ALPN + h2 SETTINGS.

    The carrier exposes the *decision*; the underlying I/O lives
    in the existing :class:`flare.ws.WsClient` (h1 path) and
    :class:`flare.ws.WsOverH2Stream` (h2 path).  The dispatcher
    is the small piece on top that picks between them.

    Today :meth:`connect` raises with a clear pointer at the
    Track Q8 follow-up commit; the per-property accessors +
    :func:`decide_wire` are fully exercised by the test corpus.
    """

    var config: WsAutoClientConfig
    """The inputs the dispatcher consults."""

    var chosen_wire: Int
    """Set by :meth:`connect` once the wire-selection completes.
    Starts at :data:`WsWireChoice.UNDETERMINED`."""

    var last_error: String
    """Per-connection-attempt failure reason.  Empty until
    :attr:`chosen_wire` transitions to :data:`WsWireChoice.FAILED`.
    """

    def __init__(out self, config: WsAutoClientConfig):
        self.config = config.copy()
        self.chosen_wire = WsWireChoice.UNDETERMINED
        self.last_error = String("")

    def url_scheme(self) -> String:
        """Return ``"ws"`` or ``"wss"`` -- the parsed scheme from
        ``config.url``.  Empty string when the URL doesn't start
        with one of those two schemes (caller-supplied bug)."""
        var bytes = self.config.url.as_bytes()
        if len(bytes) >= 6:
            if (
                bytes[0] == UInt8(0x77)
                and bytes[1] == UInt8(0x73)
                and bytes[2] == UInt8(0x73)
                and bytes[3] == UInt8(0x3A)
                and bytes[4] == UInt8(0x2F)
                and bytes[5] == UInt8(0x2F)
            ):
                return String("wss")
        if len(bytes) >= 5:
            if (
                bytes[0] == UInt8(0x77)
                and bytes[1] == UInt8(0x73)
                and bytes[2] == UInt8(0x3A)
                and bytes[3] == UInt8(0x2F)
                and bytes[4] == UInt8(0x2F)
            ):
                return String("ws")
        return String("")

    def connect(mut self) raises:
        """Run the connection sequence: TLS handshake, ALPN
        negotiation, h2 SETTINGS exchange, wire selection, then
        the per-wire bootstrap.

        Today raises pending the Track Q8 follow-up that wires
        :class:`flare.ws.WsClient` + :class:`flare.ws.WsOverH2Stream`
        through this carrier.
        """
        raise Error(
            "WsAutoClient.connect: ALPN-driven runtime dispatch"
            " not yet wired (Track Q8 follow-up commit). The"
            " decision logic + the carrier shape are in place;"
            " the runtime hand-off to WsClient / WsOverH2Stream"
            " lands once the ALPN-aware h2 client open path is"
            " plumbed through."
        )
