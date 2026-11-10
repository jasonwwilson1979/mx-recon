"""Per-client-IP fixed-window rate limiting backed by Django's cache framework.

The default cache backend is a shared file-based cache so the counter is
common across all Gunicorn workers in the container. Swap in Redis via the
DJANGO_CACHE_* settings for strict multi-node correctness.
"""
from __future__ import annotations

import time

from django.core.cache import cache

__all__ = ["check_rate_limit"]


def check_rate_limit(key: str, limit: int, window_seconds: int) -> bool:
    """Count one hit for `key` in the current fixed window.

    Returns True when the hit is within `limit` per `window_seconds`,
    False when the caller should be throttled.
    """
    bucket = int(time.time() // max(1, window_seconds))
    cache_key = f"mx-recon:rl:{key}:{bucket}"
    try:
        count = cache.incr(cache_key)
    except ValueError:
        cache.set(cache_key, 1, timeout=window_seconds + 2)
        count = 1
    return count <= max(1, limit)
