"""``flare.quic.server`` -- QUIC server reactor surface (Track Q3 scaffold).

Wraps the sans-I/O QUIC connection state machine
(:class:`flare.quic.state.Connection`) in a UDP listener +
per-connection dispatcher. The full reactor wiring (epoll
integration, ``sendmmsg`` + ``UDP_GRO`` + ECN, per-connection
PTO timers driven through :mod:`flare.runtime.timer_wheel`) lands
in a focused follow-up commit; this module ships the typed
boundary the H3 server (Track Q4) and ALPN dispatcher (Track Q5)
will build against.

## What ships here

- :class:`QuicServerConfig` -- bind configuration: host, port,
  rustls config carrier, congestion-controller choice, idle
  timeout, max packet size.
- :class:`QuicListener` -- factory that owns the UDP socket
  plus the per-connection dispatch table. Today it constructs
  cleanly but :meth:`QuicListener.run` raises pending the
  reactor wiring commit.
- :class:`QuicConnection` -- per-connection driver that
  composes the existing :class:`flare.quic.state.Connection`
  state machine with a :trait:`flare.quic.cc.CongestionController`
  carrier and the rustls QUIC session.
- :class:`QuicConnectionId` re-export from
  :mod:`flare.quic.packet` plus the small connection-id table
  carrier the reactor uses to route inbound datagrams to the
  right connection.

## What's deferred to follow-ups

- The actual UDP read loop + per-packet dispatch (needs the
  rustls binding from Track Q2 + the OpenSSL AEAD backend from
  Track Q1).
- ``sendmmsg`` + ``UDP_GRO`` + ECN tuning -- v0.5 direct-
  syscall FFI primitives exist but the QUIC fast path that
  exercises them ships once the handshake works.
- ``UDP_SEGMENT`` + GSO support -- separate commit, depends on
  kernel feature detection.

References:
- RFC 9000 §5 "Connections" -- Connection ID routing.
- RFC 9000 §10 "Connection Termination" -- idle / draining.
- RFC 9002 §6.2 "PTO and probe packets" -- PTO timer wiring.
"""

from std.collections import Dict, List, Optional

from flare.quic.cc import CcChoice
from flare.quic.crypto import QuicAead
from flare.quic.packet import ConnectionId
from flare.quic.state import Connection, new_connection
from flare.tls.rustls_quic import RustlsQuicConfig


# ── Configuration carrier ──────────────────────────────────────────────


struct QuicServerConfig(Copyable, Defaultable, Movable):
    """Bind-time configuration for the QUIC server reactor.

    Most fields have sensible production defaults; the user
    supplies a :class:`RustlsQuicConfig` (certificate + key + ALPN
    list) and optionally overrides the timeouts + CC choice.
    """

    var host: String
    """IPv4/IPv6 address to bind the UDP listener to. Default is
    ``"0.0.0.0"`` for IPv4 wildcard binding."""

    var port: UInt16
    """UDP port. Default 0 means "let the kernel pick" -- caller
    must read the resolved port back via :meth:`QuicListener.bound_port`
    after construction (deferred to the reactor follow-up)."""

    var rustls_config: RustlsQuicConfig
    """The rustls QUIC server configuration carrier. Provides the
    certificate chain, private key, ALPN list, and 0-RTT toggle."""

    var cc_choice: Int
    """Congestion controller selector
    (:data:`flare.quic.cc.CcChoice.CUBIC` for production,
    :data:`flare.quic.cc.CcChoice.RENO` for deterministic tests).
    Default: CUBIC."""

    var aead_choice: Int
    """AEAD selector codepoint (:class:`flare.quic.crypto.QuicAead`).
    Default: AES-128-GCM (the QUIC v1 mandatory-to-implement)."""

    var max_idle_timeout_ms: UInt64
    """RFC 9000 §10.1 max-idle-timeout in milliseconds. The server
    advertises this to clients; connections idle for longer get
    silently dropped. Default: 30_000 ms (30 s)."""

    var max_udp_payload_size: UInt64
    """RFC 9000 §18.2 max-udp-payload-size transport parameter --
    the largest UDP datagram payload the server is willing to
    receive. Default: 1452 bytes (Ethernet MTU 1500 minus IPv6 40
    byte header minus 8 byte UDP header)."""

    var initial_max_data: UInt64
    """RFC 9000 §4 connection-level flow-control limit -- total
    bytes the server is willing to receive across all streams
    before MAX_DATA is required. Default: 1 MiB."""

    var initial_max_streams_bidi: UInt64
    """RFC 9000 §4.6 client-initiated bidi streams limit. Default:
    100 -- matches the H3 server's working set (control + qpack-
    enc + qpack-dec + N request streams)."""

    var initial_max_streams_uni: UInt64
    """RFC 9000 §4.6 client-initiated uni streams limit. Default:
    3 -- H3 needs control + qpack-encoder + qpack-decoder."""

    def __init__(out self):
        self.host = String("0.0.0.0")
        self.port = UInt16(0)
        self.rustls_config = RustlsQuicConfig()
        self.cc_choice = CcChoice.CUBIC
        self.aead_choice = QuicAead.AES_128_GCM
        self.max_idle_timeout_ms = UInt64(30_000)
        self.max_udp_payload_size = UInt64(1452)
        self.initial_max_data = UInt64(1 << 20)  # 1 MiB
        self.initial_max_streams_bidi = UInt64(100)
        self.initial_max_streams_uni = UInt64(3)


# ── Per-connection driver ──────────────────────────────────────────────


struct QuicConnection(Copyable, Movable):
    """Per-connection driver wrapping :class:`flare.quic.state.Connection`.

    Owned by the reactor; one instance per active connection.
    Composes:

    - The sans-I/O :class:`flare.quic.state.Connection` state
      machine.
    - A :trait:`flare.quic.cc.CongestionController` carrier
      (CUBIC in production, Reno in deterministic tests).
    - A :class:`flare.tls.rustls_quic.RustlsQuicSession`
      carrying the per-encryption-level keys + handshake state.

    The reactor's per-packet hot path runs:

    1. Parse the long/short header out of the datagram
       (``flare.quic.packet``).
    2. Decrypt the protected payload via the rustls binding.
    3. Dispatch each frame in the decrypted payload through
       :func:`flare.quic.state.handle_frame_buf`, which advances
       the per-stream + per-connection state machines.
    4. Drive the CC controller with any newly-ACKed bytes.
    5. Build any reply packets the state machine queued and
       feed them to the rustls session for encryption.

    The current commit ships the carrier shape + the typed
    surface for steps 1, 3, 4. Steps 2 and 5 require the rustls
    Rust crate (Track Q2 follow-up) and the OpenSSL AEAD wiring
    (Track Q1 follow-up).
    """

    var conn: Connection
    """Sans-I/O connection state. Carries per-stream state +
    flow-control accounting + handshake-complete flag."""

    var local_cid: ConnectionId
    """The Connection ID the server chose for this connection
    (RFC 9000 §5.1). Routed-on by the reactor's CID->connection
    dispatch table."""

    var peer_cid: ConnectionId
    """The Connection ID the client picked for incoming
    server-to-client packets."""

    var cc_choice: Int
    """Which congestion controller this connection runs (RENO
    or CUBIC). Materialized monomorphically by the reactor at
    bind time."""

    var alive: Bool
    """Whether the connection is still in HANDSHAKE / ESTABLISHED
    state. Goes False once the state machine advances to CLOSING
    / DRAINING / CLOSED so the reactor's dispatch table can
    sweep the entry."""

    def __init__(
        out self,
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        cc_choice: Int = CcChoice.CUBIC,
        idle_timeout_us: UInt64 = UInt64(30_000_000),
        initial_max_data: UInt64 = UInt64(1 << 20),
    ):
        self.conn = new_connection(idle_timeout_us, initial_max_data)
        self.local_cid = local_cid.copy()
        self.peer_cid = peer_cid.copy()
        self.cc_choice = cc_choice
        self.alive = True


# ── Connection ID table ────────────────────────────────────────────────


struct ConnectionIdTable(Copyable, Defaultable, Movable, Sized):
    """Per-listener routing table from Connection ID to connection.

    QUIC routes inbound datagrams to the right connection via
    the Destination Connection ID in the packet header (RFC 9000
    §5.1). The table maps each issued CID (server-side: the
    local_cid from :class:`QuicConnection`; client-side: the
    Source Connection IDs the server sent in NEW_CONNECTION_ID
    frames) to the connection slot it belongs to.

    The carrier uses :class:`Dict[String, Int]` where the key is
    the lowercase-hex CID and the value is the slot index into
    the listener's connection slab. Tests pin the carrier shape;
    the full slab + concurrent-safe wiring lives in the reactor
    follow-up commit.
    """

    var cid_to_slot: Dict[String, Int]
    """CID (lowercase-hex of CID bytes) -> slot index. Empty
    string is invalid; a connection can have up to
    `active_connection_id_limit` (RFC 9000 §18.2) CIDs at once,
    each pointing at the same slot."""

    def __init__(out self):
        self.cid_to_slot = Dict[String, Int]()

    def register(mut self, cid_hex: String, slot: Int):
        """Add a CID -> slot mapping. Idempotent: overwriting
        an existing mapping is allowed (the server may reissue
        CIDs after migration)."""
        self.cid_to_slot[cid_hex] = slot

    def lookup(self, cid_hex: String) raises -> Int:
        """Look up the slot for a CID. Returns -1 if absent.
        The reactor uses -1 to gate the Initial packet path
        (no slot -> potentially new connection -> run the
        accept-handshake state machine)."""
        if cid_hex in self.cid_to_slot:
            return self.cid_to_slot[cid_hex]
        return -1

    def retire(mut self, cid_hex: String) raises:
        """Drop a CID -> slot mapping. Called when the connection
        retires a CID via RETIRE_CONNECTION_ID (RFC 9000 §19.16)
        or when the connection itself closes."""
        if cid_hex in self.cid_to_slot:
            _ = self.cid_to_slot.pop(cid_hex)

    def __len__(self) -> Int:
        return len(self.cid_to_slot)


# ── Listener ───────────────────────────────────────────────────────────


struct QuicListener(Movable):
    """UDP listener + per-connection dispatcher.

    Long-lived. One instance per QUIC server bind. The reactor
    drives the listener via :meth:`run` (deferred to the
    follow-up commit).
    """

    var config: QuicServerConfig
    var cid_table: ConnectionIdTable
    var _bound: Bool

    def __init__(out self, config: QuicServerConfig):
        self.config = config.copy()
        self.cid_table = ConnectionIdTable()
        self._bound = False

    def bound(self) -> Bool:
        """Whether the listener has bound the UDP socket. False
        in the scaffold (the UDP bind path lands with the
        reactor follow-up)."""
        return self._bound

    def run(self) raises:
        """Run the listener's event loop. Blocks the calling
        thread; the reactor handles the per-datagram dispatch
        internally.

        Today raises because the rustls binding + the AEAD
        backend are scaffolds. The follow-up commit implements
        the UDP socket bind + epoll registration + per-datagram
        decrypt + state-machine dispatch.
        """
        raise Error(
            "QuicListener.run: reactor wiring not yet implemented."
            " Track Q3 follow-up commit lands the UDP socket bind"
            " plus the per-datagram dispatch loop. The rustls"
            " QUIC binding (Track Q2) and OpenSSL AEAD backend"
            " (Track Q1) must be in place first."
        )
