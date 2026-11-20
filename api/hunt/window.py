"""Incident time windows: from 30 minutes before the first sign to 30 after the last."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

PAD = timedelta(minutes=30)
_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M")


def parse(value) -> datetime | None:
    s = str(value or "").strip().replace(" UTC", "").replace("Z", "")[:19]
    for fmt in _FORMATS:
        try:
            return datetime.strptime(s[:len(datetime(2000, 1, 1).strftime(fmt))], fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def around(times) -> tuple[int, int] | None:
    """Epoch (start, end) padded around these times, or None if none parse."""
    parsed = [t for t in (parse(v) for v in times) if t]
    if not parsed:
        return None
    return int((min(parsed) - PAD).timestamp()), int((max(parsed) + PAD).timestamp())


def label(window: tuple[int, int]) -> str:
    a, b = (datetime.fromtimestamp(x, tz=timezone.utc) for x in window)
    end = b.strftime("%H:%M") if a.date() == b.date() else b.strftime("%b %d %H:%M")
    return f"{a:%b %d %H:%M} to {end} UTC"


def for_splunk(spl: str, window: tuple[int, int]) -> str:
    """The vetted search, minus our row cap, pinned to the window for pasting into Splunk."""
    body = spl.removesuffix(" | head 200").removeprefix("search ")
    return f"search earliest={window[0]} latest={window[1]} {body}"
