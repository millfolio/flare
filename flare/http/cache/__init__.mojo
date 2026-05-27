"""``flare.http.cache`` — RFC 9111 HTTP cache primitives.

This package ships the data model + in-memory store layer that a
cache middleware composes on top of. The full RFC 9111 conformance
surface (Vary header negotiation, stale-while-revalidate /
stale-if-error refresh policy, validator-driven conditional
revalidation) is staged across multiple commits; this commit
opens the package with:

- :class:`CacheControl` — parsed ``Cache-Control`` directive set.
- :func:`parse_cache_control` — header parser.
- :class:`CacheKey` — request → cache lookup key derivation.
- :class:`InMemoryCacheStore` — minimal LRU-bounded store.

The middleware shim that *uses* this layer (``Cache[Inner, S]``)
lands once the store + key derivation surface stabilises.
"""

from .control import (
    CacheControl,
    parse_cache_control,
)
from .key import CacheKey, derive_cache_key
from .store import (
    CacheEntry,
    CacheStore,
    InMemoryCacheStore,
)
