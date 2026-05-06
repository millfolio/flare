"""flare.testing -- helpers for examples and integration tests.

The cookbook-style examples and many integration tests want to
demo a real end-to-end flow: bind a port, accept connections,
drive them with the real client. ``HttpServer.serve(handler)``
blocks the calling thread, so a single-process example can't
both serve and drive itself. The standard Unix workaround is
``fork(2)`` -- 50 LoC of ``external_call`` boilerplate
(fork/waitpid/_exit/kill/usleep) at the top of every
multi-process example.

``flare.testing`` ships small helpers that hide the ceremony so
the example body stays focused on the surface it's actually
demonstrating. Nothing in this module is part of the runtime hot
path; it lives next to the cookbook because that's where it's
used.

Currently provides:

* :func:`fork_server` -- fork, run ``HttpServer.serve(handler)``
  in the child, wait briefly for the listener to be ready, return
  the child PID to the parent.
* :func:`kill_forked_server` -- SIGKILL + ``waitpid`` the child.
"""

from .fork_server import fork_server, kill_forked_server
