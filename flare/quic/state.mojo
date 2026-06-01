"""QUIC connection + stream state machines (RFC 9000 §3 + §13).

Pure sans-I/O state model for a QUIC connection. The reactor
(later Phase D commit) wraps this in UDP I/O + crypto; the codec
layer here just walks the state machines as packets / frames /
timer ticks arrive.

Public surface:

* :class:`StreamState` -- the 7-state RFC 9000 §3.1 / §3.2 stream
  state machine (IDLE / OPEN / HALF_CLOSED_LOCAL / HALF_CLOSED_
  REMOTE / RESET_SENT / RESET_RECVD / CLOSED).
* :class:`Stream` -- one bidi or uni stream's state, including
  send/recv high-water-marks for flow control.
* :class:`ConnectionState` -- the connection-level state
  (HANDSHAKE / ESTABLISHED / CLOSING / DRAINING / CLOSED) per
  RFC 9000 §10.
* :class:`Connection` -- top-level container holding
  - per-side keying state (handshake_complete flag),
  - flow-control limits + cwnd via :class:`CcState`,
  - per-stream :class:`Stream` instances keyed by stream-id,
  - the timer-driven idle / pto / loss-detection deadlines.
* :func:`handle_frame` -- per-frame ingestion entry point. Takes
  one parsed :class:`flare.quic.frame.Frame` and advances the
  connection + stream state machines without emitting any wire
  bytes (the connection's outbox is filled by the caller via
  helpers like :func:`emit_ack` / :func:`emit_max_data` / ...).
* :class:`ConnectionEvents` -- the value the driver returns from
  one tick: bytes the caller should send, the next deadline at
  which to call back, plus connection-level events (handshake
  done, stream finished, connection closed).

The state-machine layer is intentionally sans-I/O: there are no
sockets, no TLS handshake, no time source. The caller passes
``now_us`` into every entry point and receives
:class:`ConnectionEvents` carrying the next deadline; the timer
shape lives in the reactor wrapper.

References:
- RFC 9000 §3 "Stream States" + §10 "Connection Termination".
- RFC 9000 §13 "Packetization and Reliability".
"""

from std.collections import List, Optional, Dict
from std.memory import Span

from .frame import (
    AckFrame,
    AckRange,
    ConnectionCloseFrame,
    CryptoFrame,
    Frame,
    FRAME_TYPE_ACK,
    FRAME_TYPE_ACK_ECN,
    FRAME_TYPE_CONNECTION_CLOSE_APPLICATION,
    FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT,
    FRAME_TYPE_CRYPTO,
    FRAME_TYPE_HANDSHAKE_DONE,
    FRAME_TYPE_MAX_DATA,
    FRAME_TYPE_MAX_STREAM_DATA,
    FRAME_TYPE_PADDING,
    FRAME_TYPE_PING,
    FRAME_TYPE_RESET_STREAM,
    FRAME_TYPE_STOP_SENDING,
    FRAME_TYPE_STREAM_BASE,
    StreamFrame,
)


# ── Stream state machine (RFC 9000 §3) ─────────────────────────────────────


comptime STREAM_STATE_IDLE: Int = 0
comptime STREAM_STATE_OPEN: Int = 1
comptime STREAM_STATE_HALF_CLOSED_LOCAL: Int = 2
comptime STREAM_STATE_HALF_CLOSED_REMOTE: Int = 3
comptime STREAM_STATE_RESET_SENT: Int = 4
comptime STREAM_STATE_RESET_RECVD: Int = 5
comptime STREAM_STATE_CLOSED: Int = 6


@fieldwise_init
struct Stream(Copyable, ImplicitlyCopyable, Movable):
    """Per-stream state for one bidi or uni QUIC stream.

    The state field uses the seven STREAM_STATE_* constants;
    transitions are driven by frames (STREAM with FIN, RESET_STREAM,
    STOP_SENDING) routed through :func:`handle_frame`. Send and
    receive high-water-marks are tracked separately so flow control
    can advance independently per direction.
    """

    var id: UInt64
    var state: Int
    var send_offset: UInt64
    var recv_offset: UInt64
    var max_send_data: UInt64
    var max_recv_data: UInt64
    var fin_sent: Bool
    var fin_received: Bool


def new_stream(id: UInt64, max_data: UInt64) -> Stream:
    """Build a fresh :class:`Stream` in the OPEN state."""
    return Stream(
        id=id,
        state=STREAM_STATE_OPEN,
        send_offset=UInt64(0),
        recv_offset=UInt64(0),
        max_send_data=max_data,
        max_recv_data=max_data,
        fin_sent=False,
        fin_received=False,
    )


# ── Connection state machine (RFC 9000 §10) ────────────────────────────────


comptime CONN_STATE_HANDSHAKE: Int = 0
comptime CONN_STATE_ESTABLISHED: Int = 1
comptime CONN_STATE_CLOSING: Int = 2
comptime CONN_STATE_DRAINING: Int = 3
comptime CONN_STATE_CLOSED: Int = 4


@fieldwise_init
struct ConnectionEvents(Copyable, Movable):
    """Per-tick output of the connection state machine.

    The driver calls :func:`handle_frame` (one or more times) with
    parsed frames, then reads :class:`ConnectionEvents` to discover
    what state has changed:

    * ``handshake_done`` -- TLS handshake completed this tick.
    * ``connection_closed`` -- the peer closed the connection or
      we did; ``error_code`` carries the reason.
    * ``finished_streams`` -- streams whose recv side reached FIN
      this tick (the caller delivers them up to the application).
    * ``new_streams`` -- streams created by an inbound STREAM
      frame that the local side hadn't seen before.
    * ``next_deadline_us`` -- earliest absolute time the driver
      should call back (for idle / PTO / loss detection); ``0``
      means "no scheduled timer".
    """

    var handshake_done: Bool
    var connection_closed: Bool
    var error_code: UInt64
    var finished_streams: List[UInt64]
    var new_streams: List[UInt64]
    var next_deadline_us: UInt64


def empty_events() -> ConnectionEvents:
    return ConnectionEvents(
        handshake_done=False,
        connection_closed=False,
        error_code=UInt64(0),
        finished_streams=List[UInt64](),
        new_streams=List[UInt64](),
        next_deadline_us=UInt64(0),
    )


@fieldwise_init
struct Connection(Copyable, Movable):
    """Top-level connection state.

    Holds the connection-level state, the per-stream map, and the
    timer-shape fields the driver uses to schedule the next tick.
    The CC state lives in :mod:`flare.quic.cc` and is owned by the
    reactor wrapper; the connection here only tracks the data-plane
    state machines.

    Uses :class:`Dict` for the stream map so the driver can look
    up by stream id in O(1); RFC 9000 caps stream ids at 2**62-1
    so the key space is wide enough that stream-id overflow is a
    non-concern.
    """

    var state: Int
    var handshake_complete: Bool
    var idle_timeout_us: UInt64
    var last_activity_us: UInt64
    var max_data_send: UInt64
    var max_data_recv: UInt64
    var bytes_in_flight: UInt64
    var streams: Dict[UInt64, Stream]
    var ack_pending: Bool
    var largest_received_packet: UInt64
    var close_error_code: UInt64
    var close_reason: List[UInt8]


def new_connection(
    idle_timeout_us: UInt64 = UInt64(30_000_000),
    initial_max_data: UInt64 = UInt64(1 << 20),
) -> Connection:
    """Build a fresh :class:`Connection` in the HANDSHAKE state."""
    return Connection(
        state=CONN_STATE_HANDSHAKE,
        handshake_complete=False,
        idle_timeout_us=idle_timeout_us,
        last_activity_us=UInt64(0),
        max_data_send=initial_max_data,
        max_data_recv=initial_max_data,
        bytes_in_flight=UInt64(0),
        streams=Dict[UInt64, Stream](),
        ack_pending=False,
        largest_received_packet=UInt64(0),
        close_error_code=UInt64(0),
        close_reason=List[UInt8](),
    )


# ── Frame ingestion ────────────────────────────────────────────────────────


def _on_stream_frame(
    mut conn: Connection,
    sf: StreamFrame,
    mut events: ConnectionEvents,
) raises:
    var sid = sf.stream_id
    var existing = conn.streams.get(sid)
    var s: Stream
    if Bool(existing):
        s = existing.value()
    else:
        s = new_stream(sid, conn.max_data_recv)
        events.new_streams.append(sid)
    var end = sf.offset + UInt64(len(sf.data))
    if end > s.max_recv_data:
        raise Error(
            "quic state: stream " + String(sid) + " flow-control violation"
        )
    if end > s.recv_offset:
        s.recv_offset = end
    if sf.fin and not s.fin_received:
        s.fin_received = True
        events.finished_streams.append(sid)
        if s.state == STREAM_STATE_OPEN:
            s.state = STREAM_STATE_HALF_CLOSED_REMOTE
        elif s.state == STREAM_STATE_HALF_CLOSED_LOCAL:
            s.state = STREAM_STATE_CLOSED
    conn.streams[sid] = s


def _on_ack_frame(mut conn: Connection, ack: AckFrame):
    """Apply an ACK frame to the connection-level bookkeeping.

    The codec-layer state machine only tracks bytes_in_flight at
    a coarse granularity; the reactor wrapper threads the precise
    packet-level RTT samples into :func:`flare.quic.cc.on_ack_received`.
    The largest acknowledged packet number is stored so the
    reactor can advance its packet-number ack tracker.
    """
    if ack.largest_acknowledged > conn.largest_received_packet:
        conn.largest_received_packet = ack.largest_acknowledged


def _on_close_frame(
    mut conn: Connection,
    cc: ConnectionCloseFrame,
    mut events: ConnectionEvents,
):
    conn.state = CONN_STATE_DRAINING
    conn.close_error_code = cc.error_code
    var reason = List[UInt8]()
    for i in range(len(cc.reason_phrase)):
        reason.append(cc.reason_phrase[i])
    conn.close_reason = reason^
    events.connection_closed = True
    events.error_code = cc.error_code


def handle_frame(
    mut conn: Connection,
    frame: Frame,
    now_us: UInt64,
    mut events: ConnectionEvents,
) raises:
    """Apply one parsed frame to the connection state machines.

    Updates ``last_activity_us`` for the idle timer, flips
    ``ack_pending`` for ack-eliciting frame types (everything
    except ACK / PADDING / CONNECTION_CLOSE per RFC 9002 §2),
    and dispatches per-frame state transitions.

    The caller batches per-packet frame iteration: for each
    received packet, decode its frames with
    :func:`flare.quic.frame.parse_frame` and call this function
    per frame, accumulating events in the same
    :class:`ConnectionEvents` carrier. After the packet is
    drained the caller reads the events back.
    """
    if conn.state == CONN_STATE_CLOSED:
        return
    conn.last_activity_us = now_us
    var k = frame.kind
    var ack_eliciting = not (
        k == FRAME_TYPE_ACK
        or k == FRAME_TYPE_ACK_ECN
        or k == FRAME_TYPE_PADDING
        or k == FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT
        or k == FRAME_TYPE_CONNECTION_CLOSE_APPLICATION
    )
    if ack_eliciting:
        conn.ack_pending = True
    if k == FRAME_TYPE_PADDING or k == FRAME_TYPE_PING:
        return
    if k == FRAME_TYPE_ACK or k == FRAME_TYPE_ACK_ECN:
        _on_ack_frame(conn, frame.ack)
        return
    if k == FRAME_TYPE_CRYPTO:
        # Crypto stream is opaque at this layer; the reactor
        # forwards its bytes to the TLS handshake adapter, then
        # later signals handshake completion via
        # :func:`mark_handshake_complete`.
        return
    if k == FRAME_TYPE_STREAM_BASE:
        _on_stream_frame(conn, frame.stream, events)
        return
    if k == FRAME_TYPE_HANDSHAKE_DONE:
        conn.handshake_complete = True
        conn.state = CONN_STATE_ESTABLISHED
        events.handshake_done = True
        return
    if (
        k == FRAME_TYPE_CONNECTION_CLOSE_TRANSPORT
        or k == FRAME_TYPE_CONNECTION_CLOSE_APPLICATION
    ):
        _on_close_frame(conn, frame.connection_close, events)
        return
    if k == FRAME_TYPE_MAX_DATA:
        if frame.max_data.maximum_data > conn.max_data_send:
            conn.max_data_send = frame.max_data.maximum_data
        return
    if k == FRAME_TYPE_MAX_STREAM_DATA:
        var sid = frame.max_stream_data.stream_id
        var s_opt = conn.streams.get(sid)
        if Bool(s_opt):
            var s = s_opt.value()
            if frame.max_stream_data.maximum_stream_data > s.max_send_data:
                s.max_send_data = frame.max_stream_data.maximum_stream_data
            conn.streams[sid] = s
        return
    if k == FRAME_TYPE_RESET_STREAM:
        var sid = frame.reset_stream.stream_id
        var s_opt = conn.streams.get(sid)
        if Bool(s_opt):
            var s = s_opt.value()
            s.state = STREAM_STATE_RESET_RECVD
            conn.streams[sid] = s
        return
    if k == FRAME_TYPE_STOP_SENDING:
        var sid = frame.stop_sending.stream_id
        var s_opt = conn.streams.get(sid)
        if Bool(s_opt):
            var s = s_opt.value()
            s.state = STREAM_STATE_RESET_SENT
            conn.streams[sid] = s
        return
    # Other frame types (NEW_TOKEN, NEW_CONNECTION_ID, PATH_*,
    # MAX_STREAMS, *_BLOCKED, RETIRE_CONNECTION_ID) advance
    # connection bookkeeping the reactor handles directly; the
    # codec-layer state machine treats them as no-ops here.


def mark_handshake_complete(
    mut conn: Connection, now_us: UInt64, mut events: ConnectionEvents
):
    """Explicit hook the TLS handshake adapter calls when its key
    schedule reaches HANDSHAKE_DONE. Mirrors the
    :data:`FRAME_TYPE_HANDSHAKE_DONE` path so the connection state
    advances regardless of which side the signal came from.
    """
    if conn.state == CONN_STATE_HANDSHAKE:
        conn.handshake_complete = True
        conn.state = CONN_STATE_ESTABLISHED
        events.handshake_done = True
        conn.last_activity_us = now_us


def is_idle_timeout_expired(conn: Connection, now_us: UInt64) -> Bool:
    """Whether the idle timeout has elapsed since ``last_activity_us``.

    Returns ``False`` if no traffic has been observed yet (the
    handshake hasn't started); the reactor uses this to retire
    stalled connections per RFC 9000 §10.1.
    """
    if conn.last_activity_us == UInt64(0):
        return False
    if conn.idle_timeout_us == UInt64(0):
        return False
    return (now_us - conn.last_activity_us) >= conn.idle_timeout_us


def connection_close(
    mut conn: Connection,
    error_code: UInt64,
    reason: String,
    application: Bool = False,
):
    """Mark the connection as closing with the given error code +
    reason. The driver later emits a CONNECTION_CLOSE frame and
    transitions to DRAINING.
    """
    if (
        conn.state == CONN_STATE_CLOSING
        or conn.state == CONN_STATE_DRAINING
        or conn.state == CONN_STATE_CLOSED
    ):
        return
    conn.state = CONN_STATE_CLOSING
    conn.close_error_code = error_code
    var bytes = List[UInt8]()
    for c in reason.as_bytes():
        bytes.append(c)
    conn.close_reason = bytes^
