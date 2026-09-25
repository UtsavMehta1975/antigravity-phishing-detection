"""
Rate Limiting Middleware for the Detection Platform.

Implements a sliding-window in-memory rate limiter (no Redis dependency needed for
the hackathon demo). Uses a per-IP token bucket approach.

Limits:
  - Scan endpoints (/api/scan/*): 15 requests / minute
  - AI Copilot (/api/ai/*):      20 requests / minute
  - Health / general endpoints:  120 requests / minute

Returns HTTP 429 with Retry-After header when limit is exceeded.
"""
import time
import threading
from collections import defaultdict, deque
from typing import Callable, Dict, Deque, Tuple

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware


# ---------------------------------------------------------------------------
# Rate limit rules: (path_prefix, max_requests, window_seconds)
# Evaluated in order; first match wins.
# ---------------------------------------------------------------------------
RATE_LIMIT_RULES: list[Tuple[str, int, int]] = [
    ("/api/scan",      15, 60),   # 15 scans / 60 sec
    ("/api/ai",        20, 60),   # 20 AI queries / 60 sec
    ("/api/feedback",  30, 60),   # 30 feedback posts / 60 sec
    ("/api",          120, 60),   # General API cap
]


class SlidingWindowRateLimiter:
    """Thread-safe sliding window rate limiter."""

    def __init__(self):
        # {(ip, path_prefix): deque of timestamps}
        self._windows: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_allowed(self, ip: str, path_prefix: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
        """
        Returns (allowed: bool, retry_after_seconds: int).
        retry_after_seconds is 0 when allowed=True.
        """
        key = (ip, path_prefix)
        now = time.monotonic()
        cutoff = now - window_seconds

        with self._lock:
            dq = self._windows[key]
            # Remove expired timestamps
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= max_requests:
                # Time until the oldest request expires
                retry_after = int(window_seconds - (now - dq[0])) + 1
                return False, retry_after

            dq.append(now)
            return True, 0


_limiter = SlidingWindowRateLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI/Starlette middleware that enforces per-IP rate limits."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Determine client IP (respect X-Forwarded-For for reverse proxies)
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        client_ip = forwarded_for.split(",")[0].strip() if forwarded_for else (
            request.client.host if request.client else "unknown"
        )

        path = request.url.path

        for path_prefix, max_req, window_sec in RATE_LIMIT_RULES:
            if path.startswith(path_prefix):
                allowed, retry_after = _limiter.is_allowed(
                    client_ip, path_prefix, max_req, window_sec
                )
                if not allowed:
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "Rate limit exceeded",
                            "detail": (
                                f"Too many requests to {path_prefix}. "
                                f"Limit: {max_req} requests per {window_sec}s per IP."
                            ),
                            "retry_after_seconds": retry_after
                        },
                        headers={
                            "Retry-After": str(retry_after),
                            "X-RateLimit-Limit": str(max_req),
                            "X-RateLimit-Window": f"{window_sec}s"
                        }
                    )
                break  # First matching rule wins

        response = await call_next(request)
        return response
