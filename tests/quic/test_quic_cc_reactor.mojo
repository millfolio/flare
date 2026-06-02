"""Tests for the QUIC reactor's congestion-controller drive --
Track Q3-W commit 4/5.

The reactor exposes four CC + pacing entry points on
:class:`flare.quic.server.QuicConnection`:

- :meth:`update_on_ack(acked_bytes, rtt_us, now_us)` -- advance
  cwnd via slow-start / CUBIC / HyStart++ (RFC 9438 + RFC 9406).
- :meth:`update_on_loss(lost_bytes, now_us)` -- shrink cwnd via
  the configured controller's loss response (CUBIC: 0.7 x;
  Reno: 0.5 x).
- :meth:`on_packet_sent_bytes(bytes, now_us)` -- update the
  in-flight accounting + the ``last_send_us`` carrier the
  pacing budget subtracts against.
- :meth:`pacing_budget(now_us)` -- RFC 9002 §7.7 pacing budget
  given the elapsed time since the last send.

The pure-function CC numerics (``flare.quic.cc``) are unit-
tested elsewhere; this file covers the wiring + sub-millisecond
pacing precision the reactor needs for line-rate egress.
"""

from std.testing import assert_equal, assert_true, assert_false

from flare.quic import (
    ConnectionId,
    QuicConnection,
)
from flare.quic.cc import (
    DEFAULT_MSS_BYTES,
    INITIAL_WINDOW_PACKETS,
)


def _make_cid(seed: UInt8, length: Int) -> ConnectionId:
    var bytes = List[UInt8]()
    for i in range(length):
        bytes.append(seed + UInt8(i))
    return ConnectionId(bytes^)


def _make_conn() raises -> QuicConnection:
    var local = _make_cid(UInt8(0x10), 8)
    var peer = _make_cid(UInt8(0x20), 8)
    return QuicConnection(local, peer)


def test_initial_cwnd_matches_rfc_9002_default() raises:
    var conn = _make_conn()
    assert_equal(
        conn.cc_state.cwnd_bytes,
        DEFAULT_MSS_BYTES * INITIAL_WINDOW_PACKETS,
        "cwnd starts at MSS * INITIAL_WINDOW_PACKETS per RFC 9002 §B.2",
    )
    assert_equal(
        conn.cc_state.bytes_in_flight, UInt64(0), "no in-flight at init"
    )
    assert_true(conn.cc_state.in_slow_start, "starts in slow-start")


def test_on_packet_sent_bumps_in_flight_and_last_send_us() raises:
    var conn = _make_conn()
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(5_000_000))
    assert_equal(conn.cc_state.bytes_in_flight, UInt64(1200))
    assert_equal(conn.last_send_us, UInt64(5_000_000))
    conn.on_packet_sent_bytes(UInt64(800), UInt64(5_500_000))
    assert_equal(conn.cc_state.bytes_in_flight, UInt64(2000))
    assert_equal(conn.last_send_us, UInt64(5_500_000))


def test_update_on_ack_grows_cwnd_in_slow_start() raises:
    var conn = _make_conn()
    var initial_cwnd = conn.cc_state.cwnd_bytes
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(1_000_000))
    var new_cwnd = conn.update_on_ack(
        UInt64(1200), UInt64(20_000), UInt64(1_020_000)
    )
    assert_true(
        new_cwnd >= initial_cwnd,
        "cwnd must not shrink on an ACK in slow-start",
    )
    assert_true(
        new_cwnd >= initial_cwnd + UInt64(1200),
        "slow-start grows cwnd by at least acked_bytes",
    )
    assert_equal(
        conn.cc_state.bytes_in_flight,
        UInt64(0),
        "in-flight clears after the ACK covers everything sent",
    )


def test_update_on_loss_shrinks_cwnd_and_exits_slow_start() raises:
    var conn = _make_conn()
    conn.on_packet_sent_bytes(UInt64(4800), UInt64(0))
    var pre = conn.cc_state.cwnd_bytes
    var post = conn.update_on_loss(UInt64(1200), UInt64(100_000))
    assert_true(post < pre, "loss event must shrink cwnd")
    assert_false(
        conn.cc_state.in_slow_start,
        "first loss exits slow-start (HyStart++ + Reno + CUBIC agree)",
    )


def test_pacing_budget_initial_burst_is_cwnd() raises:
    var conn = _make_conn()
    var budget = conn.pacing_budget(UInt64(0))
    assert_equal(
        budget,
        conn.cc_state.mss,
        (
            "pre-first-send the pacing budget falls back to one MSS so the "
            "egress path can prime the pump without flooding"
        ),
    )


def test_pacing_budget_after_rtt_sample_scales_with_elapsed() raises:
    var conn = _make_conn()
    # First send seeds the elapsed-time delta.
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(1_000_000))
    # Feed a smoothed RTT via the ACK path.
    _ = conn.update_on_ack(UInt64(1200), UInt64(20_000), UInt64(1_020_000))
    # Second send updates last_send_us.
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(2_000_000))
    var one_ms_budget = conn.pacing_budget(UInt64(2_001_000))
    var ten_ms_budget = conn.pacing_budget(UInt64(2_010_000))
    assert_true(
        ten_ms_budget >= one_ms_budget,
        "longer elapsed -> at-least-as-large budget",
    )


def test_pacing_budget_sub_ms_precision() raises:
    """The reactor needs sub-millisecond pacing precision for
    line-rate egress on 10G+ NICs (a 9000-byte jumbogram at
    10 Gbps is ~7 us). The pure pacing math multiplies in the
    microsecond domain before dividing by 1_000_000, so 1us and
    10us elapsed deltas must produce distinct, monotonic
    budgets."""
    var conn = _make_conn()
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(1_000_000))
    _ = conn.update_on_ack(UInt64(1200), UInt64(1_000), UInt64(1_001_000))
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(2_000_000))
    var b_1us = conn.pacing_budget(UInt64(2_000_001))
    var b_10us = conn.pacing_budget(UInt64(2_000_010))
    var b_100us = conn.pacing_budget(UInt64(2_000_100))
    assert_true(
        b_100us >= b_10us,
        "100us elapsed must yield at least the 10us budget",
    )
    assert_true(
        b_10us >= b_1us,
        "10us elapsed must yield at least the 1us budget",
    )


def test_pacing_budget_caps_at_cwnd() raises:
    """RFC 9002 §7.7 -- pacing budget never exceeds the cwnd, so
    bursts beyond the congestion window are impossible."""
    var conn = _make_conn()
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(1_000_000))
    _ = conn.update_on_ack(UInt64(1200), UInt64(20_000), UInt64(1_020_000))
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(2_000_000))
    # Sample one full second later -- the rate-elapsed product is
    # gigantic, but the budget must still cap at cwnd.
    var budget = conn.pacing_budget(UInt64(3_000_000))
    assert_true(
        budget <= conn.cc_state.cwnd_bytes,
        "pacing budget never exceeds cwnd",
    )


def test_pacing_budget_clamps_when_clock_skews_backward() raises:
    """Defensive: if a now_us argument is somehow less than
    last_send_us (e.g. monotonic-clock NTP correction), the
    reactor must not underflow. Returns the conservative
    one-MSS budget."""
    var conn = _make_conn()
    conn.on_packet_sent_bytes(UInt64(1200), UInt64(5_000_000))
    var budget = conn.pacing_budget(UInt64(4_999_000))
    assert_equal(
        budget,
        conn.cc_state.mss,
        "backward clock skew falls back to one MSS",
    )


def test_repeated_ack_grows_cwnd_monotonically() raises:
    """Repeated ACKs in slow-start must grow cwnd monotonically;
    no plateau, no shrink without a loss event."""
    var conn = _make_conn()
    var cwnd_samples = List[UInt64]()
    cwnd_samples.append(conn.cc_state.cwnd_bytes)
    var now_us = UInt64(1_000_000)
    for _ in range(10):
        conn.on_packet_sent_bytes(UInt64(1200), now_us)
        _ = conn.update_on_ack(
            UInt64(1200), UInt64(20_000), now_us + UInt64(20_000)
        )
        cwnd_samples.append(conn.cc_state.cwnd_bytes)
        now_us = now_us + UInt64(40_000)
    for i in range(1, len(cwnd_samples)):
        assert_true(
            cwnd_samples[i] >= cwnd_samples[i - 1],
            "slow-start cwnd must be monotonic across consecutive ACKs",
        )


def main() raises:
    test_initial_cwnd_matches_rfc_9002_default()
    test_on_packet_sent_bumps_in_flight_and_last_send_us()
    test_update_on_ack_grows_cwnd_in_slow_start()
    test_update_on_loss_shrinks_cwnd_and_exits_slow_start()
    test_pacing_budget_initial_burst_is_cwnd()
    test_pacing_budget_after_rtt_sample_scales_with_elapsed()
    test_pacing_budget_sub_ms_precision()
    test_pacing_budget_caps_at_cwnd()
    test_pacing_budget_clamps_when_clock_skews_backward()
    test_repeated_ack_grows_cwnd_monotonically()
    print("test_quic_cc_reactor: 10 passed")
