"""Round-trip test: H3 response writer feeds the H3 request reader.

The writer emits HEADERS + DATA + trailing HEADERS bytes; the
reader (reused as a generic frame parser) confirms the bytes
parse back into the same field sets. This is a coarse codec
contract -- per-field-set tests live under tests/qpack and
tests/h3/test_request_reader.
"""

from std.collections import List
from std.memory import Span
from std.testing import assert_equal, assert_true

from flare.h3 import (
    H3_REQUEST_EVENT_DATA,
    H3_REQUEST_EVENT_HEADERS,
    H3_REQUEST_EVENT_TRAILERS,
    H3RequestReader,
    encode_response_data,
    encode_response_headers,
    encode_response_trailers,
    feed,
)
from flare.qpack import QpackHeader


def test_status_only() raises:
    var bytes = encode_response_headers(200, List[QpackHeader]())
    var r = H3RequestReader.new()
    var ev = feed(r, Span[UInt8, _](bytes))
    assert_equal(ev.kind, H3_REQUEST_EVENT_HEADERS)
    # Pseudo-header :status MUST be present.
    assert_equal(ev.headers[0].name, ":status")
    assert_equal(ev.headers[0].value, "200")


def test_status_with_application_headers() raises:
    var hs = List[QpackHeader]()
    hs.append(QpackHeader("Content-Type", "application/json"))
    hs.append(QpackHeader("X-Trace-ID", "abc"))
    var bytes = encode_response_headers(200, hs)
    var r = H3RequestReader.new()
    var ev = feed(r, Span[UInt8, _](bytes))
    assert_equal(ev.kind, H3_REQUEST_EVENT_HEADERS)
    # Headers come back lowercased per RFC 9114 §4.2 lowercase
    # mandate -- the writer normalises before QPACK encoding.
    var found_ct = False
    var found_trace = False
    for i in range(len(ev.headers)):
        if ev.headers[i].name == "content-type":
            found_ct = True
            assert_equal(ev.headers[i].value, "application/json")
        if ev.headers[i].name == "x-trace-id":
            found_trace = True
    assert_true(found_ct)
    assert_true(found_trace)


def test_invalid_status_raises() raises:
    var raised = False
    try:
        var _ = encode_response_headers(99, List[QpackHeader]())
    except:
        raised = True
    assert_true(raised)


def test_pseudo_header_in_application_headers_raises() raises:
    var hs = List[QpackHeader]()
    hs.append(QpackHeader(":scheme", "https"))
    var raised = False
    try:
        var _ = encode_response_headers(200, hs)
    except:
        raised = True
    assert_true(raised)


def test_data_frame_round_trip() raises:
    var hbytes = encode_response_headers(200, List[QpackHeader]())
    var payload = List[UInt8]()
    for c in String("hello").as_bytes():
        payload.append(c)
    var dbytes = encode_response_data(Span[UInt8, _](payload))
    var stream = List[UInt8]()
    for i in range(len(hbytes)):
        stream.append(hbytes[i])
    for i in range(len(dbytes)):
        stream.append(dbytes[i])
    var r = H3RequestReader.new()
    var ev1 = feed(r, Span[UInt8, _](stream))
    assert_equal(ev1.kind, H3_REQUEST_EVENT_HEADERS)
    var rest = List[UInt8]()
    for i in range(ev1.consumed, len(stream)):
        rest.append(stream[i])
    var ev2 = feed(r, Span[UInt8, _](rest))
    assert_equal(ev2.kind, H3_REQUEST_EVENT_DATA)
    assert_equal(len(ev2.data), 5)
    assert_equal(ev2.data[0], UInt8(ord("h")))


def test_trailers_round_trip() raises:
    var hbytes = encode_response_headers(200, List[QpackHeader]())
    var payload = List[UInt8]()
    payload.append(UInt8(0x41))
    var dbytes = encode_response_data(Span[UInt8, _](payload))
    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader("X-Sum", "deadbeef"))
    var tbytes = encode_response_trailers(trailers)
    var stream = List[UInt8]()
    for i in range(len(hbytes)):
        stream.append(hbytes[i])
    for i in range(len(dbytes)):
        stream.append(dbytes[i])
    for i in range(len(tbytes)):
        stream.append(tbytes[i])
    var r = H3RequestReader.new()
    var ev1 = feed(r, Span[UInt8, _](stream))
    var rest1 = List[UInt8]()
    for i in range(ev1.consumed, len(stream)):
        rest1.append(stream[i])
    var ev2 = feed(r, Span[UInt8, _](rest1))
    var rest2 = List[UInt8]()
    for i in range(ev2.consumed, len(rest1)):
        rest2.append(rest1[i])
    var ev3 = feed(r, Span[UInt8, _](rest2))
    assert_equal(ev3.kind, H3_REQUEST_EVENT_TRAILERS)
    assert_equal(len(ev3.headers), 1)
    assert_equal(ev3.headers[0].name, "x-sum")
    assert_equal(ev3.headers[0].value, "deadbeef")


def test_pseudo_header_in_trailers_raises() raises:
    var trailers = List[QpackHeader]()
    trailers.append(QpackHeader(":path", "/x"))
    var raised = False
    try:
        var _ = encode_response_trailers(trailers)
    except:
        raised = True
    assert_true(raised)


def main() raises:
    test_status_only()
    test_status_with_application_headers()
    test_invalid_status_raises()
    test_pseudo_header_in_application_headers_raises()
    test_data_frame_round_trip()
    test_trailers_round_trip()
    test_pseudo_header_in_trailers_raises()
    print("test_h3_response_writer: 7 passed")
