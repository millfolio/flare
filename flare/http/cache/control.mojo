"""``Cache-Control`` header parser (RFC 9111 §5.2).

The ``Cache-Control`` header carries a comma-separated list of
directives. Each directive is either a bare token (e.g.
``no-cache``, ``no-store``, ``public``, ``private``) or a
token=value pair (e.g. ``max-age=3600``, ``s-maxage=300``,
``stale-while-revalidate=60``).

Tokens are case-insensitive; this parser normalises to lowercase.
Unknown directives are surfaced through ``unknown_directives`` so
middleware can decide whether to honour or skip them (e.g.
``immutable`` is RFC 8246, not RFC 9111).

Reference:
- RFC 9111 §5.2 "Cache-Control".
- RFC 8246 (``immutable``).
"""

from std.collections import List, Optional


@fieldwise_init
struct CacheControl(Copyable, Defaultable, Movable):
    """Parsed Cache-Control directive set.

    Boolean directives are True when present; numeric directives
    are Optional[Int] (None when absent, ``Some(seconds)`` when
    present with a value). Negative or unparseable numeric values
    are silently dropped per RFC 9111 §5.2 ("If the value is
    invalid, it should be treated as if it were not present").
    """

    var no_cache: Bool
    var no_store: Bool
    var no_transform: Bool
    var public: Bool
    var private: Bool
    var must_revalidate: Bool
    var proxy_revalidate: Bool
    var immutable: Bool
    var max_age: Optional[Int]
    var s_maxage: Optional[Int]
    var stale_while_revalidate: Optional[Int]
    var stale_if_error: Optional[Int]
    var unknown_directives: List[String]

    def __init__(out self):
        self.no_cache = False
        self.no_store = False
        self.no_transform = False
        self.public = False
        self.private = False
        self.must_revalidate = False
        self.proxy_revalidate = False
        self.immutable = False
        self.max_age = Optional[Int]()
        self.s_maxage = Optional[Int]()
        self.stale_while_revalidate = Optional[Int]()
        self.stale_if_error = Optional[Int]()
        self.unknown_directives = List[String]()


def _lower(s: String) -> String:
    var out = String()
    var p = s.unsafe_ptr()
    for i in range(s.byte_length()):
        var c = p[i]
        if c >= UInt8(ord("A")) and c <= UInt8(ord("Z")):
            out += chr(Int(c) + 32)
        else:
            out += chr(Int(c))
    return out^


def _trim(s: String) -> String:
    var n = s.byte_length()
    if n == 0:
        return s
    var p = s.unsafe_ptr()
    var lo = 0
    while lo < n and (
        p[lo] == UInt8(ord(" "))
        or p[lo] == UInt8(ord("\t"))
        or p[lo] == UInt8(ord("\r"))
        or p[lo] == UInt8(ord("\n"))
    ):
        lo += 1
    var hi = n
    while hi > lo and (
        p[hi - 1] == UInt8(ord(" "))
        or p[hi - 1] == UInt8(ord("\t"))
        or p[hi - 1] == UInt8(ord("\r"))
        or p[hi - 1] == UInt8(ord("\n"))
    ):
        hi -= 1
    var out = String()
    for i in range(lo, hi):
        out += chr(Int(p[i]))
    return out^


def _parse_int(s: String) -> Optional[Int]:
    var n = s.byte_length()
    if n == 0:
        return Optional[Int]()
    var p = s.unsafe_ptr()
    var acc = 0
    for i in range(n):
        var c = p[i]
        if c < UInt8(ord("0")) or c > UInt8(ord("9")):
            return Optional[Int]()
        acc = acc * 10 + (Int(c) - ord("0"))
    return Optional[Int](acc)


def _split_directives(value: String) -> List[String]:
    """Split a Cache-Control value on commas, honouring quoted-
    string boundaries so values like ``private="X-Foo, X-Bar"``
    don't get bisected mid-quotes."""
    var out = List[String]()
    var p = value.unsafe_ptr()
    var n = value.byte_length()
    var i = 0
    var start = 0
    var in_quotes = False
    while i < n:
        var c = p[i]
        if c == UInt8(ord('"')) and (i == 0 or p[i - 1] != UInt8(ord("\\"))):
            in_quotes = not in_quotes
        elif c == UInt8(ord(",")) and not in_quotes:
            var piece = String()
            for j in range(start, i):
                piece += chr(Int(p[j]))
            out.append(_trim(piece))
            start = i + 1
        i += 1
    if start < n:
        var piece = String()
        for j in range(start, n):
            piece += chr(Int(p[j]))
        out.append(_trim(piece))
    return out^


def parse_cache_control(value: String) -> CacheControl:
    """Parse a Cache-Control header value into a structured
    directive set.

    The parser is permissive per RFC 9111 §5.2: malformed numeric
    values silently drop, unknown directives are surfaced through
    ``unknown_directives`` rather than rejected. Callers that
    want strict behaviour can inspect ``unknown_directives``
    after the fact.
    """
    var cc = CacheControl()
    var pieces = _split_directives(value)
    for i in range(len(pieces)):
        var directive = pieces[i]
        if directive.byte_length() == 0:
            continue
        # Split on '=' (first occurrence only; values may contain '=').
        var eq_at = -1
        var p = directive.unsafe_ptr()
        var n = directive.byte_length()
        for j in range(n):
            if p[j] == UInt8(ord("=")):
                eq_at = j
                break
        var name: String
        var val: String
        if eq_at == -1:
            name = _lower(_trim(directive))
            val = String()
        else:
            var k = String()
            for j in range(eq_at):
                k += chr(Int(p[j]))
            name = _lower(_trim(k))
            var v = String()
            for j in range(eq_at + 1, n):
                v += chr(Int(p[j]))
            val = _trim(v)
            # Strip surrounding quotes on the value, if any.
            if val.byte_length() >= 2:
                var vp = val.unsafe_ptr()
                if vp[0] == UInt8(ord('"')) and vp[
                    val.byte_length() - 1
                ] == UInt8(ord('"')):
                    var unq = String()
                    for j in range(1, val.byte_length() - 1):
                        unq += chr(Int(vp[j]))
                    val = unq^
        if name == String("no-cache"):
            cc.no_cache = True
        elif name == String("no-store"):
            cc.no_store = True
        elif name == String("no-transform"):
            cc.no_transform = True
        elif name == String("public"):
            cc.public = True
        elif name == String("private"):
            cc.private = True
        elif name == String("must-revalidate"):
            cc.must_revalidate = True
        elif name == String("proxy-revalidate"):
            cc.proxy_revalidate = True
        elif name == String("immutable"):
            cc.immutable = True
        elif name == String("max-age"):
            cc.max_age = _parse_int(val)
        elif name == String("s-maxage"):
            cc.s_maxage = _parse_int(val)
        elif name == String("stale-while-revalidate"):
            cc.stale_while_revalidate = _parse_int(val)
        elif name == String("stale-if-error"):
            cc.stale_if_error = _parse_int(val)
        else:
            cc.unknown_directives.append(name)
    return cc^
