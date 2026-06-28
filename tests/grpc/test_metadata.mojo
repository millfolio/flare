"""Unit tests for the gRPC metadata carrier."""

from std.testing import assert_equal, assert_true, assert_false

from flare.grpc import GrpcMetadata, GrpcMetadataEntry


def test_append_text_round_trip() raises:
    var m = GrpcMetadata()
    m.append_text(String("trace-id"), String("abc123"))
    m.append_text(String("user-agent"), String("flare/0.8"))
    assert_equal(m.len(), 2)
    var trace = m.get_text(String("trace-id"))
    assert_true(trace.__bool__())
    assert_equal(trace.unsafe_take(), String("abc123"))
    var ua = m.get_text(String("user-agent"))
    assert_true(ua.__bool__())
    assert_equal(ua.unsafe_take(), String("flare/0.8"))


def test_append_binary_round_trip() raises:
    var m = GrpcMetadata()
    var raw = List[UInt8]()
    raw.append(UInt8(0xDE))
    raw.append(UInt8(0xAD))
    raw.append(UInt8(0xBE))
    raw.append(UInt8(0xEF))
    m.append(String("trace-bin"), raw^)
    assert_equal(m.len(), 1)
    var got = m.get_binary(String("trace-bin"))
    assert_true(got.__bool__())
    var bytes = got.unsafe_take()
    assert_equal(len(bytes), 4)
    assert_equal(Int(bytes[0]), 0xDE)
    assert_equal(Int(bytes[3]), 0xEF)


def test_rejects_reserved_grpc_prefix() raises:
    """Application writes to ``grpc-status`` / ``grpc-message``
    etc. must be rejected; only the framework emits these
    trailers."""
    var m = GrpcMetadata()
    var raised = False
    try:
        m.append_text(String("grpc-status"), String("0"))
    except _:
        raised = True
    assert_true(raised)


def test_rejects_text_for_binary_key() raises:
    """Append_text() refuses to accept a key ending in -bin;
    callers must use append() with the raw bytes."""
    var m = GrpcMetadata()
    var raised = False
    try:
        m.append_text(String("trace-bin"), String("would-be-misencoded"))
    except _:
        raised = True
    assert_true(raised)


def test_missing_key_returns_none() raises:
    var m = GrpcMetadata()
    var got = m.get_text(String("absent"))
    assert_false(got.__bool__())


def test_text_vs_binary_get_mismatch_raises() raises:
    var m = GrpcMetadata()
    var raw = List[UInt8]()
    raw.append(UInt8(0xFF))
    m.append(String("trace-bin"), raw^)
    # get_text on a binary key must raise rather than return
    # mis-typed data.
    var raised = False
    try:
        _ = m.get_text(String("trace-bin"))
    except _:
        raised = True
    assert_true(raised)


def test_insertion_order_preserved() raises:
    """Trailers like ``set-cookie`` (rare in gRPC but legal) must
    round-trip with their original sequence."""
    var m = GrpcMetadata()
    m.append_text(String("h-1"), String("a"))
    m.append_text(String("h-2"), String("b"))
    m.append_text(String("h-1"), String("c"))  # duplicate key
    var entries = m.entries()
    assert_equal(len(entries), 3)
    assert_equal(entries[0].key, String("h-1"))
    assert_equal(entries[1].key, String("h-2"))
    assert_equal(entries[2].key, String("h-1"))


def main() raises:
    test_append_text_round_trip()
    test_append_binary_round_trip()
    test_rejects_reserved_grpc_prefix()
    test_rejects_text_for_binary_key()
    test_missing_key_returns_none()
    test_text_vs_binary_get_mismatch_raises()
    test_insertion_order_preserved()
    print("test_grpc_metadata: OK")
