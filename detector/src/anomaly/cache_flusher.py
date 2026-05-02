"""Cache flusher for confirmed poisoned DNS entries.

Invokes unbound-control flush <domain> when ENABLE_CACHE_FLUSH=1.
When disabled (default), records log_only status so the alert still
reflects what action would have been taken.

Follows TCPMitigator pattern: dependency-injected callable, per-domain
cooldown, structured result dict, never raises to the caller.
"""
import logging
import subprocess
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def _default_flusher(domain: str, host: str, port: int) -> None:
    subprocess.run(
        ["unbound-control", "-s", f"{host}@{port}", "flush", domain],
        check=True,
        timeout=5,
        capture_output=True,
    )


class CacheFlusher:
    def __init__(
        self,
        enabled: bool,
        control_host: str,
        control_port: int,
        cooldown_seconds: int,
        flusher=_default_flusher,
    ) -> None:
        self.enabled = enabled
        self.control_host = control_host
        self.control_port = control_port
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.flusher = flusher
        self.recent_flushes: dict[str, datetime] = {}

    def flush(self, domain: str) -> dict[str, object]:
        now = datetime.now(timezone.utc)

        last = self.recent_flushes.get(domain)
        if last is not None and now - last <= self.cooldown:
            return {"action": "cache_flush", "status": "skipped_cooldown", "domain": domain}

        if not self.enabled:
            return {"action": "cache_flush", "status": "log_only", "domain": domain}

        try:
            self.flusher(domain, self.control_host, self.control_port)
            self.recent_flushes[domain] = now
            logger.info("cache_flush: flushed domain=%s", domain)
            return {"action": "cache_flush", "status": "flushed", "domain": domain}
        except Exception as exc:
            logger.exception("cache_flush: failed for domain=%s", domain)
            return {
                "action": "cache_flush",
                "status": "failed",
                "domain": domain,
                "error": str(exc),
            }
