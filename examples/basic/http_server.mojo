"""HTTP/1.1 server example: bind on a real port, drive it with the real client.

The smallest possible end-to-end demo of ``flare.http.HttpServer``:
parent forks a child that runs ``HttpServer.serve(handler)``, the
parent uses ``HttpClient`` to hit each route, prints the
responses, and SIGKILLs the child on cleanup.

Under the hood ``serve`` runs a single-threaded event loop on
``kqueue`` (macOS) or ``epoll`` (Linux) with per-connection state
machines: nginx-style architecture, no thread-per-connection.
For ``num_workers >= 2`` it spawns N pthread workers behind
per-worker ``SO_REUSEPORT`` listeners. See ``docs/benchmark.md``
for the head-to-head numbers vs nginx / actix_web / hyper /
axum / Go on plaintext throughput, both single- and 4-worker.

The fork / wait / kill ceremony lives in
``flare.testing.fork_server`` so the example body stays focused
on the surface it's actually demonstrating.

Run:
    pixi run example-http-server
"""

from flare.prelude import *
from flare.http import HttpClient
from flare.testing import fork_server, kill_forked_server


def hello(req: Request) -> Response:
    return ok("Hello from flare!")


def json_payload(req: Request) -> Response:
    return ok_json('{"greeting": "hello", "from": "flare"}')


def echo(req: Request) raises -> Response:
    return Response(status=Status.OK, reason="OK", body=req.body.copy())


def whoami(req: Request) -> Response:
    return ok("peer=" + String(req.peer.ip) + ":" + String(req.peer.port))


def main() raises:
    print("=== flare HTTP server example ===")

    var r = Router()
    r.get("/hello", hello)
    r.get("/json", json_payload)
    r.post("/echo", echo)
    r.get("/whoami", whoami)

    var srv = HttpServer.bind(SocketAddr.localhost(0))
    var port = srv.local_addr().port
    print("[server] listening on 127.0.0.1:" + String(port))

    var pid = fork_server(srv^, r^)

    var base = "http://127.0.0.1:" + String(port)
    with HttpClient(base_url=base) as c:
        var r1 = c.get("/hello")
        print("GET  /hello   ->", r1.status, r1.text())

        var r2 = c.get("/json")
        print("GET  /json    ->", r2.status, r2.text())

        var r3 = c.post("/echo", "hello")
        print("POST /echo    ->", r3.status, r3.text())

        var r4 = c.get("/whoami")
        print("GET  /whoami  ->", r4.status, r4.text())

        var r5 = c.get("/nope")
        print("GET  /nope    ->", r5.status)

    kill_forked_server(pid)
    print("=== done ===")
