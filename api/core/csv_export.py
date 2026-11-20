"""CSV exports that are safe to open in Excel or Sheets (CWE-1236)."""
from __future__ import annotations

import csv
import io
import re
import tempfile
from collections.abc import Awaitable, Callable, Iterable
from datetime import datetime, timezone

from fastapi.responses import Response, StreamingResponse

# A cell starting with one of these is treated as a formula by spreadsheet apps
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
_SAFE_NAME = re.compile(r"[^A-Za-z0-9_.-]+")


def safe_cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value)
    if text.startswith(_FORMULA_START):
        return "'" + text  # leading quote makes the app show it as plain text
    return text


_CHUNK = 2000
_SPOOL = 16 * 1024 * 1024  # kept in memory up to this, then spills to a temp file


def _headers(filename: str) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    name = f"{_SAFE_NAME.sub('-', filename)[:80]}-{stamp}.csv"
    return {"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"}


def csv_response(filename: str, header: list[str], rows: Iterable[Iterable]) -> Response:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([safe_cell(v) for v in row])
    return Response(content=buf.getvalue(), media_type="text/csv; charset=utf-8", headers=_headers(filename))


async def csv_paged_response(filename: str, header: list[str],
                             fetch: Callable[[int, int], Awaitable[list[list]]]) -> StreamingResponse:
    """Export every row, no cap: fetch(offset, limit) is called until it returns a short page."""
    spool = tempfile.SpooledTemporaryFile(max_size=_SPOOL, mode="w+b")
    text = io.TextIOWrapper(spool, encoding="utf-8", newline="", write_through=True)
    writer = csv.writer(text, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(header)
    offset = 0
    try:
        while True:
            rows = await fetch(offset, _CHUNK)
            for row in rows:
                writer.writerow([safe_cell(v) for v in row])
            offset += len(rows)
            if len(rows) < _CHUNK:
                break
    except BaseException:
        spool.close()
        raise
    text.detach()
    spool.seek(0)

    def stream():
        try:
            while chunk := spool.read(256 * 1024):
                yield chunk
        finally:
            spool.close()

    headers = _headers(filename)
    headers["X-Export-Rows"] = str(offset)
    return StreamingResponse(stream(), media_type="text/csv; charset=utf-8", headers=headers)
