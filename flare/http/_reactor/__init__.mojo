"""``flare.http._reactor`` -- per-connection state-machine sub-package.

This sub-package owns the per-connection halves of the reactor-backed
HTTP server. It is deliberately split from
``flare.http._server_reactor_impl`` so the per-connection code path
lives in a focused module that stays under the 1,000-line boundary
and the I/O-bearing pieces -- reactor entry-point loops,
``Pool[ConnHandle]`` glue, io_uring buffer-ring scaffolding -- stay
in the sister module.

This first decomposition pass extracts:

* The state-constant trio (``STATE_READING`` / ``STATE_WRITING`` /
  ``STATE_CLOSING``).
* ``StepResult`` -- the typed return shape from every event handler.
* The byte-level helpers ``ConnHandle`` and the reactor loops both
  consult during parse / serialize / keep-alive policy decisions.
* The local h2c upgrade detector that exists pending the eventual
  promotion to ``flare.http.proto.h2c_upgrade``.

A follow-up commit moves ``ConnHandle`` itself into
``conn_handle.mojo`` alongside the helpers. Until then ``ConnHandle``
stays in ``flare.http._server_reactor_impl`` and consumes the helpers
re-exported from this sub-package.

Internal namespace: nothing here is part of the public ``flare`` API.
Every public symbol is re-exported via
``flare.http._server_reactor_impl`` for back-compat with existing
imports across ``flare/http/``, ``flare/http2/``, ``flare/runtime/``,
the test suite, and the fuzz corpus.
"""

from .conn_handle import (
    STATE_READING,
    STATE_WRITING,
    STATE_CLOSING,
    StepResult,
    _detect_h2c_upgrade_inline,
    _monotonic_ms,
    _is_content_length,
    _is_date,
    _is_connection,
    _connection_is_keepalive,
    _connection_is_close,
    _compact_read_buf_drop_prefix,
    _compute_close_after,
    _wants_close,
)
