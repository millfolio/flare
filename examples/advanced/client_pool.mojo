"""HTTP/1.1 client connection pooling.

Run:

    pixi run example-client-pool

Two GETs to the same origin reuse a single TCP connection thanks to
``HttpClient.with_pool()``. ``c.idle_count()`` reports the number of
idle fds the pool is currently parking.
"""

from flare.prelude import *
from flare.testing import fork_server, kill_forked_server


def hello(req: Request) raises -> Response:
    return ok("pool-hello")


def main() raises:
    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = UInt16(srv.local_addr().port)
    var pid = fork_server(srv^, hello)

    var url = String("http://127.0.0.1:") + String(Int(port)) + String("/")
    try:
        with HttpClient().with_pool() as c:
            var r1 = c.get(url)
            print("first  status:", r1.status, " body:", r1.text())
            print("idle after request 1:", c.idle_count())
            var r2 = c.get(url)
            print("second status:", r2.status, " body:", r2.text())
            print("idle after request 2:", c.idle_count())
    finally:
        kill_forked_server(pid)
