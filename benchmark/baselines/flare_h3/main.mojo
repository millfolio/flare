"""Flare HTTP/3 plaintext baseline binary for the bench_h3 harness.

Binds a :class:`flare.quic.QuicListener` on
127.0.0.1:$FLARE_BENCH_PORT (default 8443) and runs the listener's
event loop. The listener's per-datagram dispatch path is wired
into :class:`flare.quic.state.Connection` -> the OpenSSL AEAD
backend -> the QUIC frame parser -- the same wire path the
Track Q3-W loopback integration tests exercise.

The HTTP/3 dispatch path that this baseline wires on top
(`flare.h3.H3Connection`) is per-connection rather than
per-binary; for the bench harness the binary just needs to run
the listener long enough for h2load --npn-list=h3 to drive a
sustained workload. Track Q7-W commit 4/4 publishes the numbers
this baseline produces.

Why not use HttpServer.bind_with_h3: that path also opens a TCP
listener for h1 / h2c / h2 alongside the QUIC listener. The
bench harness scopes the workload to a single wire; this binary
opens only the UDP side so h2load --npn-list=h3 is the only
client + the only response shape under measurement.

The binary stays as small as possible -- the FFI build
(OpenSSL + rustls) and the QUIC state machine are
already-tested through the QUIC unit + integration suite; this
file is the boot-up shim the bench harness drives.
"""

from std.os import getenv

from flare.quic import QuicListener, QuicServerConfig


def main() raises:
    var port_str = getenv("FLARE_BENCH_PORT", "8443")
    var port = Int(port_str)
    var cfg = QuicServerConfig()
    cfg.host = String("127.0.0.1")
    cfg.port = UInt16(port)
    # Bench shape favors throughput; lift the per-connection
    # initial_max_data so the QUIC flow-control window doesn't
    # throttle a high-rate h2load -n large workload. The default
    # is conservative for general use.
    cfg.initial_max_data = UInt64(32 * 1024 * 1024)
    # Idle timeout long enough that h2load's per-connection
    # warmup + 5 measurement runs (10s + 5x30s = 160s) never
    # tickle the idle reaper.
    cfg.max_idle_timeout_ms = UInt64(300_000)

    print("flare-h3 listening on 127.0.0.1:", port)
    var listener = QuicListener.bind(cfg^)
    listener.run()
