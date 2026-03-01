# core/stealth.py
"""
Stealth Mode / Rate Limiter
----------------------------
Adds randomized delays between HTTP requests to avoid WAF detection.

Three profiles:
  normal     → 0.1–0.4s   fast, basic WAF bypass
  stealth    → 0.8–2.5s   human-like, evades most WAFs
  aggressive → 3.0–7.0s   near-invisible, very slow

Usage in any scanner (add these 2 lines before every request):
    from core.stealth import stealth
    stealth.wait()
"""

import time
import random
import threading

# ── Global config (updated from Flask route) ──────────────────────
_config = {
    "enabled": False,
    "mode":    "stealth",   # "normal" | "stealth" | "aggressive"
}
_lock = threading.Lock()


def set_stealth(enabled: bool, mode: str = "stealth"):
    """Called by Flask route to toggle stealth on/off."""
    with _lock:
        _config["enabled"] = enabled
        _config["mode"]    = mode if mode in ("normal", "stealth", "aggressive") else "stealth"
    print(f"[STEALTH] Mode set → enabled={enabled}, profile={mode}")


def is_enabled() -> bool:
    return _config["enabled"]


def get_mode() -> str:
    return _config["mode"]


# ── Delay profiles ─────────────────────────────────────────────────
PROFILES = {
    "normal":     {"min": 0.1, "max": 0.4},
    "stealth":    {"min": 0.8, "max": 2.5},
    "aggressive": {"min": 3.0, "max": 7.0},
}


class StealthManager:
    """
    Drop-in rate limiter. Call stealth.wait() before every HTTP request.
    If stealth is disabled it returns instantly — zero overhead.
    """

    def __init__(self):
        self._request_count = 0
        self._total_delay   = 0.0
        self._start_time    = time.time()

    def wait(self):
        """Sleep for a random duration based on the active profile."""
        if not _config["enabled"]:
            return

        profile = PROFILES.get(_config["mode"], PROFILES["stealth"])
        delay   = round(random.uniform(profile["min"], profile["max"]), 3)

        self._request_count += 1
        self._total_delay   += delay

        print(f"[STEALTH] ⏳ req #{self._request_count} — waiting {delay}s ({_config['mode']} mode)")
        time.sleep(delay)

    def stats(self) -> dict:
        return {
            "requests":    self._request_count,
            "total_delay": round(self._total_delay, 2),
            "elapsed":     round(time.time() - self._start_time, 2),
            "mode":        _config["mode"],
            "enabled":     _config["enabled"],
        }


# ── Singleton — import this everywhere ───────────────────────────
stealth = StealthManager()