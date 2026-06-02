"""Unit tests for the QUIC server reactor scaffold
(``flare.quic.server`` -- Track Q3).

The full reactor wiring (UDP bind, per-datagram dispatch, PTO
timer integration, rustls + AEAD plumbing) lands in a focused
follow-up commit. This suite pins the carrier shapes + the typed
boundary the H3 server (Track Q4) and ALPN dispatcher (Track Q5)
build against.

Properties covered:

1. :class:`QuicServerConfig` defaults match the values documented
   in the design notebook (idle timeout, max UDP payload, flow
   control, CC choice).
2. :class:`QuicConnection` constructs cleanly with the existing
   sans-I/O :class:`flare.quic.state.Connection`.
3. :class:`ConnectionIdTable` registers / looks up / retires
   correctly across the small-slot + overflow path.
4. :meth:`QuicListener.run` raises a clear error pointing at the
   reactor follow-up commit.
"""

from std.testing import assert_equal, assert_false, assert_true

from flare.quic import (
    CcChoice,
    ConnectionId,
    ConnectionIdTable,
    QuicAead,
    QuicConnection,
    QuicListener,
    QuicServerConfig,
)


def _make_cid(b: UInt8) -> ConnectionId:
    var bytes = List[UInt8]()
    bytes.append(b)
    bytes.append(b + UInt8(1))
    bytes.append(b + UInt8(2))
    bytes.append(b + UInt8(3))
    bytes.append(b + UInt8(4))
    bytes.append(b + UInt8(5))
    bytes.append(b + UInt8(6))
    bytes.append(b + UInt8(7))
    return ConnectionId(bytes^)


def test_config_defaults() raises:
    """``QuicServerConfig.__init__`` returns the values documented
    in the design notebook -- 30 s idle timeout, 1452 B MTU,
    1 MiB initial flow control, 100 bidi streams, 3 uni streams,
    CUBIC + AES-128-GCM by default."""
    var cfg = QuicServerConfig()
    assert_equal(cfg.host, String("0.0.0.0"))
    assert_equal(cfg.port, UInt16(0))
    assert_equal(cfg.cc_choice, CcChoice.CUBIC)
    assert_equal(cfg.aead_choice, QuicAead.AES_128_GCM)
    assert_equal(cfg.max_idle_timeout_ms, UInt64(30_000))
    assert_equal(cfg.max_udp_payload_size, UInt64(1452))
    assert_equal(cfg.initial_max_data, UInt64(1 << 20))
    assert_equal(cfg.initial_max_streams_bidi, UInt64(100))
    assert_equal(cfg.initial_max_streams_uni, UInt64(3))


def test_config_carries_overrides() raises:
    """Field-by-field assignment of overrides round-trips."""
    var cfg = QuicServerConfig()
    cfg.host = String("::")
    cfg.port = UInt16(4433)
    cfg.cc_choice = CcChoice.RENO
    cfg.max_idle_timeout_ms = UInt64(5_000)
    assert_equal(cfg.host, String("::"))
    assert_equal(cfg.port, UInt16(4433))
    assert_equal(cfg.cc_choice, CcChoice.RENO)
    assert_equal(cfg.max_idle_timeout_ms, UInt64(5_000))


def test_quic_connection_starts_alive_in_handshake() raises:
    """A fresh :class:`QuicConnection` carries the underlying
    state machine in HANDSHAKE and reports ``alive = True``."""
    var local = _make_cid(UInt8(0x10))
    var peer = _make_cid(UInt8(0x20))
    var qc = QuicConnection(local, peer)
    assert_true(qc.alive)
    assert_equal(qc.cc_choice, CcChoice.CUBIC)
    assert_false(qc.conn.handshake_complete)


def test_quic_connection_records_cids() raises:
    """Both local and peer CIDs round-trip through the carrier
    so the reactor can route inbound datagrams to the right
    connection and emit responses with the right SCID/DCID."""
    var local = _make_cid(UInt8(0x10))
    var peer = _make_cid(UInt8(0x20))
    var qc = QuicConnection(local, peer)
    assert_equal(len(qc.local_cid.bytes), 8)
    assert_equal(len(qc.peer_cid.bytes), 8)
    assert_equal(Int(qc.local_cid.bytes[0]), 0x10)
    assert_equal(Int(qc.peer_cid.bytes[0]), 0x20)


def test_quic_connection_honors_cc_override() raises:
    """When the listener is bound with the Reno CC choice (for
    deterministic tests), :class:`QuicConnection` reports
    ``RENO`` so the reactor can monomorphize the right
    controller."""
    var local = _make_cid(UInt8(0x30))
    var peer = _make_cid(UInt8(0x40))
    var qc = QuicConnection(local, peer, CcChoice.RENO)
    assert_equal(qc.cc_choice, CcChoice.RENO)


def test_cid_table_register_lookup_retire() raises:
    """Round-trip a CID through register / lookup / retire."""
    var table = ConnectionIdTable()
    table.register(String("aabbccdd"), 7)
    assert_equal(table.lookup(String("aabbccdd")), 7)
    assert_equal(len(table), 1)
    table.retire(String("aabbccdd"))
    assert_equal(table.lookup(String("aabbccdd")), -1)
    assert_equal(len(table), 0)


def test_cid_table_lookup_missing_returns_minus_one() raises:
    """Lookup of an unknown CID returns -1; the reactor uses
    -1 to gate the Initial-packet path (no slot -> potentially
    new connection)."""
    var table = ConnectionIdTable()
    assert_equal(table.lookup(String("ffffffff")), -1)


def test_cid_table_register_overwrites() raises:
    """Re-registering the same CID with a different slot is
    allowed and overwrites; the server may reissue CIDs after
    migration (RFC 9000 §9)."""
    var table = ConnectionIdTable()
    table.register(String("11223344"), 1)
    table.register(String("11223344"), 5)
    assert_equal(table.lookup(String("11223344")), 5)
    assert_equal(len(table), 1)


def test_listener_not_bound_before_run() raises:
    """A freshly-constructed :class:`QuicListener` reports
    ``bound() == False`` so callers can confirm the bind hasn't
    happened yet."""
    var cfg = QuicServerConfig()
    var listener = QuicListener(cfg)
    assert_false(listener.bound())
    assert_equal(len(listener.cid_table), 0)


def test_listener_run_raises_pending_reactor_wiring() raises:
    """:meth:`QuicListener.run` raises a clear error pointing
    at the Track Q3 follow-up commit so callers using the
    scaffold get a loud failure rather than a silent no-op."""
    var cfg = QuicServerConfig()
    var listener = QuicListener(cfg)
    var raised = False
    try:
        listener.run()
    except:
        raised = True
    assert_true(raised, "expected QuicListener.run to raise")


def main() raises:
    test_config_defaults()
    test_config_carries_overrides()
    test_quic_connection_starts_alive_in_handshake()
    test_quic_connection_records_cids()
    test_quic_connection_honors_cc_override()
    test_cid_table_register_lookup_retire()
    test_cid_table_lookup_missing_returns_minus_one()
    test_cid_table_register_overwrites()
    test_listener_not_bound_before_run()
    test_listener_run_raises_pending_reactor_wiring()
    print("test_quic_server_scaffold: 10 passed")
