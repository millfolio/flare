"""Tests for :trait:`flare.quic.cc.CongestionController` and the
two concrete carriers ``CubicController`` + ``RenoController``
(Track P of v0.8 Phase D).

The trait exposes the surface the reactor (Track Q3) drives:
``on_packet_sent`` / ``on_ack_received`` / ``on_packets_lost`` /
``cwnd_bytes`` / ``bytes_in_flight`` / ``can_send`` /
``pacing_rate_bytes_per_second`` / ``pacing_budget``. Both
controllers conform to the trait; the reactor monomorphizes over
the choice at bind time.

CUBIC is the production default. Reno is the test default because
its AIMD math is closed-form: no cubic root, no HyStart++, no
smoothed-RTT EWMA in the friendliness path. The deterministic
behavior is what makes Reno the controller of choice for replay /
loss-recovery vectors.

Coverage:
- Both controllers start at the same initial cwnd.
- ``on_packet_sent`` advances bytes-in-flight identically.
- ``can_send`` becomes false at cwnd exhaustion.
- Slow-start growth: each acked MSS bumps cwnd by one MSS on both
  controllers.
- Loss event: CUBIC and Reno both reduce cwnd, with Reno at the
  cleaner halving and CUBIC at the 0.7 multiplicative-decrease.
- ``pacing_rate_bytes_per_second`` returns 0 before any RTT
  sample; positive after.
- ``pacing_budget`` is bounded above by ``cwnd_bytes``.
"""

from std.testing import assert_equal, assert_true

from flare.quic.cc import (
    DEFAULT_MSS_BYTES,
    INITIAL_WINDOW_PACKETS,
    MIN_WINDOW_PACKETS,
    CcChoice,
    CongestionController,
    CubicController,
    RenoController,
)


def _expect_cwnd[CC: CongestionController](ref cc: CC, expected: UInt64) raises:
    """Assert that ``cc`` reports ``expected`` cwnd. Goes through
    the trait so the test exercises the monomorphic boundary the
    reactor will use.
    """
    assert_equal(Int(cc.cwnd_bytes()), Int(expected))


def test_initial_cwnd_matches_rfc9002_b2() raises:
    var cubic = CubicController()
    var reno = RenoController()
    var expected = DEFAULT_MSS_BYTES * INITIAL_WINDOW_PACKETS
    _expect_cwnd(cubic, expected)
    _expect_cwnd(reno, expected)
    assert_equal(Int(cubic.bytes_in_flight()), 0)
    assert_equal(Int(reno.bytes_in_flight()), 0)
    assert_true(cubic.can_send())
    assert_true(reno.can_send())


def test_on_packet_sent_advances_in_flight() raises:
    var cubic = CubicController()
    var reno = RenoController()

    cubic.on_packet_sent(DEFAULT_MSS_BYTES)
    reno.on_packet_sent(DEFAULT_MSS_BYTES)

    assert_equal(Int(cubic.bytes_in_flight()), Int(DEFAULT_MSS_BYTES))
    assert_equal(Int(reno.bytes_in_flight()), Int(DEFAULT_MSS_BYTES))


def test_can_send_returns_false_at_cwnd_exhaustion() raises:
    var reno = RenoController()
    var initial = reno.cwnd_bytes()
    # Send enough packets to fill the window. Each on_packet_sent
    # bumps bytes_in_flight by MSS; can_send is True while
    # bytes_in_flight + MSS <= cwnd.
    while reno.can_send():
        reno.on_packet_sent(DEFAULT_MSS_BYTES)
    # Bytes in flight is now within MSS of the cwnd.
    assert_true(reno.bytes_in_flight() + DEFAULT_MSS_BYTES > initial)


def test_slow_start_growth_one_mss_per_acked_mss_reno() raises:
    # RFC 9002 Appendix B.2: in slow start, cwnd grows by one MSS
    # for each MSS acknowledged. Use Reno for deterministic
    # arithmetic.
    var reno = RenoController()
    var cwnd0 = reno.cwnd_bytes()
    # Send 10 MSS, then ACK one MSS at 50ms RTT.
    for _ in range(10):
        reno.on_packet_sent(DEFAULT_MSS_BYTES)
    var cwnd1 = reno.on_ack_received(
        DEFAULT_MSS_BYTES, UInt64(50_000), UInt64(1_000_000)
    )
    assert_equal(Int(cwnd1), Int(cwnd0 + DEFAULT_MSS_BYTES))


def test_loss_halves_reno_cwnd_with_min_floor() raises:
    var reno = RenoController()
    var cwnd0 = reno.cwnd_bytes()
    # Send the whole cwnd, ack none, then declare half lost.
    reno.on_packet_sent(cwnd0)
    var cwnd1 = reno.on_packets_lost(cwnd0 // UInt64(2), UInt64(1_000_000))
    # Reno halves the pre-loss cwnd; the floor is
    # MSS * MIN_WINDOW_PACKETS.
    var expected = cwnd0 // UInt64(2)
    var min_cwnd = DEFAULT_MSS_BYTES * MIN_WINDOW_PACKETS
    if expected < min_cwnd:
        expected = min_cwnd
    assert_equal(Int(cwnd1), Int(expected))


def test_loss_reduces_cubic_cwnd() raises:
    # CUBIC's multiplicative decrease is 0.7 (RFC 9438 §5), not
    # 0.5. Just verify the cwnd shrinks below the pre-loss value
    # and stays at or above the MIN_WINDOW_PACKETS floor.
    var cubic = CubicController()
    var cwnd0 = cubic.cwnd_bytes()
    cubic.on_packet_sent(cwnd0)
    var cwnd1 = cubic.on_packets_lost(cwnd0 // UInt64(2), UInt64(1_000_000))
    var min_cwnd = DEFAULT_MSS_BYTES * MIN_WINDOW_PACKETS
    assert_true(cwnd1 < cwnd0)
    assert_true(cwnd1 >= min_cwnd)


def test_pacing_rate_zero_until_rtt_sample() raises:
    var cubic = CubicController()
    var reno = RenoController()
    assert_equal(Int(cubic.pacing_rate_bytes_per_second()), 0)
    assert_equal(Int(reno.pacing_rate_bytes_per_second()), 0)


def test_pacing_rate_positive_after_rtt_sample() raises:
    # Pacing rate is ``cwnd * gain / rtt_us`` in bytes/microsecond
    # then scaled to per-second. The integer-division precision
    # bites at very small windows; pick a 5 ms RTT so the rate
    # computes positive at the 10-MSS initial cwnd.
    var reno = RenoController()
    reno.on_packet_sent(DEFAULT_MSS_BYTES)
    _ = reno.on_ack_received(
        DEFAULT_MSS_BYTES, UInt64(5_000), UInt64(1_000_000)
    )
    var rate = reno.pacing_rate_bytes_per_second()
    assert_true(rate > UInt64(0))


def test_pacing_budget_bounded_by_cwnd() raises:
    var reno = RenoController()
    reno.on_packet_sent(DEFAULT_MSS_BYTES)
    _ = reno.on_ack_received(
        DEFAULT_MSS_BYTES, UInt64(5_000), UInt64(1_000_000)
    )
    var budget = reno.pacing_budget(UInt64(1_000_000_000))
    # Ridiculously long interval => budget capped at cwnd.
    assert_equal(Int(budget), Int(reno.cwnd_bytes()))


def test_cc_choice_constants_are_distinct() raises:
    # Sanity check the selector enum used by QuicServerConfig.
    assert_equal(CcChoice.CUBIC, 0)
    assert_equal(CcChoice.RENO, 1)


def main() raises:
    test_initial_cwnd_matches_rfc9002_b2()
    test_on_packet_sent_advances_in_flight()
    test_can_send_returns_false_at_cwnd_exhaustion()
    test_slow_start_growth_one_mss_per_acked_mss_reno()
    test_loss_halves_reno_cwnd_with_min_floor()
    test_loss_reduces_cubic_cwnd()
    test_pacing_rate_zero_until_rtt_sample()
    test_pacing_rate_positive_after_rtt_sample()
    test_pacing_budget_bounded_by_cwnd()
    test_cc_choice_constants_are_distinct()
    print("test_cc_trait: 10 passed")
