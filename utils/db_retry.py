import time

import httpx


def run_with_retry(fn, attempts=3, delay=0.4):
    """Run a Supabase call again when Windows reports a transient socket error.

    Retries only transport/OS errors (for example WinError 10035). Any other
    exception, such as a bad query or a 4xx response, is raised immediately.
    """
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except (httpx.TransportError, OSError) as exc:
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(delay * (attempt + 1))
    raise last_exc