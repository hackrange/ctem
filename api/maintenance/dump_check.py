#!/usr/bin/env python3
"""open-ctem restore check: refuse a database dump that would run more than a schema and its rows.
Author: Tim Rice <tim.j.rice@hackrange.com>
"""
# pg_restore runs every statement in a dump as the database superuser, so a dump built by hand can run
# COPY ... FROM PROGRAM, LOAD a library, or read files. A backup handed to the web page may come from anyone,
# so before anything changes this reads the dump's table of contents (the SQL pg_restore will run) and allows
# only what pg_dump writes for open-ctem: extensions it uses, tables, types, sequences, indexes, constraints,
# comments and plain COPY rows. It is a strict filter, not a sandbox: it narrows what a dump can do.
from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
from backup_archive import BackupError, _password, entries  # noqa: E402

MAX_ENTRIES = 200_000
MAX_STR = 16 << 20
EXTENSIONS = ("timescaledb", "pgstattuple")
_ID = r'(?:[a-z_][a-z0-9_$]*|"(?:[^"\'\0]|"")+")'
_QUAL = rf"{_ID}\.{_ID}"
EXACT = {
    "ENCODING": re.compile(r"SET client_encoding = 'UTF8';\n"),
    "STDSTRINGS": re.compile(r"SET standard_conforming_strings = 'on';\n"),
    "SEARCHPATH": re.compile(r"SELECT pg_catalog\.set_config\('search_path', '', false\);\n"),
    "SEQUENCE SET": re.compile(rf"SELECT pg_catalog\.setval\('{_QUAL}', -?\d+, (?:true|false)\);\n"),
}
COPY_RE = re.compile(rf"COPY {_QUAL} (?:\({_ID}(?:, {_ID})*\) )?FROM stdin;\n")
SCHEMA_RE = re.compile(rf"CREATE SCHEMA {_ID};\n")   # CREATE SCHEMA can carry GRANTs, views and triggers
EXT_RE = re.compile(r"CREATE EXTENSION IF NOT EXISTS ([a-z_]+) WITH SCHEMA public;\n")
# The statements each kind of entry may hold (first words, lower case)
LEADS = {
    "SCHEMA": ("create schema",), "TYPE": ("create type",), "COMMENT": ("comment on",),
    "TABLE": ("create table", "create unlogged table", "alter table"),
    "SEQUENCE": ("create sequence", "alter table", "alter sequence"), "SEQUENCE OWNED BY": ("alter sequence",),
    "DEFAULT": ("alter table",), "CONSTRAINT": ("alter table",), "FK CONSTRAINT": ("alter table",),
    "CHECK CONSTRAINT": ("alter table",), "INDEX": ("create index", "create unique index", "alter index"),
    "INDEX ATTACH": ("alter index",),
}
SKIPPED = ("ACL", "DEFAULT ACL", "DATABASE", "DATABASE PROPERTIES")  # never run: restore.sh passes --no-acl, not --create
# Reserved words a table or index never needs (a query, a DO block), and built-in functions that run SQL text,
# touch files or the server; only bare words count, since pg_dump quotes a name that is a reserved word
BAD_WORDS = {"select", "values", "lateral", "do", "authorization"}
BAD_CALL = re.compile(r"^(?:query_to_xml\w*|cursor_to_xml\w*|database_to_xml\w*|schema_to_xml\w*|table_to_xml\w*"
                      r"|ts_stat|ts_rewrite|lo_\w+|pg_read_\w+|pg_ls_\w+|pg_stat_file|pg_file_\w+|set_config"
                      r"|pg_reload_conf|pg_terminate_backend|pg_cancel_backend|pg_create_\w+|pg_drop_\w+"
                      r"|pg_replication_\w+|pg_logical_\w+|pg_backup_\w+|pg_switch_wal|pg_promote|pg_sleep\w*"
                      r"|pg_advisory\w*|dblink\w*|add_job|add_\w+_policy|alter_job|run_job|delete_job"
                      r"|_timescaledb\w*|timescaledb\w*)$")


class DumpRefused(Exception):
    pass


class _Stream:
    def __init__(self, blocks):
        self._it, self._buf = iter(blocks), b""

    def read(self, n: int) -> bytes:
        while len(self._buf) < n:
            nxt = next(self._it, None)
            if nxt is None:
                raise DumpRefused("the database dump is cut short")
            self._buf += nxt
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def read_toc(read) -> list[dict]:
    """The custom-format header and table of contents, read the way pg_restore 16 reads them."""
    if read(5) != b"PGDMP":
        raise DumpRefused("the database dump is not a PostgreSQL custom-format dump")
    vmaj, vmin, _rev, isize, osize, fmt = read(6)
    if (vmaj, vmin) not in ((1, 14), (1, 15)) or isize != 4 or osize != 8 or fmt != 1:
        raise DumpRefused("the database dump has an unexpected format or version")

    def rint() -> int:
        sign, raw = read(1)[0], read(isize)
        val = int.from_bytes(raw, "little")
        return -val if sign else val

    def rstr() -> str | None:
        n = rint()
        if n < 0:
            return None
        if n > MAX_STR:
            raise DumpRefused("the database dump has an oversized entry")
        return read(n).decode("latin-1")

    if vmin >= 15:
        read(1)          # compression algorithm
    else:
        rint()           # compression level
    for _ in range(7):   # creation time
        rint()
    rstr(), rstr(), rstr()  # database name, server version, pg_dump version
    count = rint()
    if not 0 <= count <= MAX_ENTRIES:
        raise DumpRefused("the database dump's table of contents is damaged")
    toc = []
    for _ in range(count):
        e = {"id": rint(), "data": rint()}
        rstr(), rstr()                                   # catalog id
        e["tag"], e["desc"] = rstr(), rstr()
        rint()                                           # section
        e["defn"], e["drop"], e["copy"] = rstr(), rstr(), rstr()
        e["schema"], e["space"], e["am"], e["owner"] = rstr(), rstr(), rstr(), rstr()
        rstr()                                           # "false" (with oids)
        while rstr() is not None:                        # dependencies
            pass
        if read(1)[0] not in (1, 2, 3):                  # data offset flag, then the offset
            raise DumpRefused("the database dump's table of contents is damaged")
        read(osize)
        toc.append(e)
    return toc


_TOKEN = re.compile(r"""\s+|--[^\n\r]*|(?P<word>[A-Za-z_][A-Za-z0-9_$]*)|"(?:[^"]|"")*"|(?P<semi>;)|(?P<open>\()
                    |'(?:[^']|'')*'|\$(?P<tag>[A-Za-z_][A-Za-z0-9_]*)?\$|[0-9.]+|::|[^\sA-Za-z0-9_'"$;(]""", re.X)


def _tokens(sql: str) -> list[tuple[str, str]]:
    """Words, quoted names, ';' and '(' outside literals and comments; anything unusual is refused."""
    out, i = [], 0
    if re.search(r"(?i)\bu&|/\*|\be'", sql):
        raise DumpRefused("escaped names, block comments and escape strings are not expected")
    while i < len(sql):
        m = _TOKEN.match(sql, i)
        if not m:
            raise DumpRefused("unterminated quote")
        if m.group("tag") is not None or m.group(0) == "$$":
            end = sql.find(m.group(0), m.end())
            if end < 0:
                raise DumpRefused("unterminated quote")
            i = end + len(m.group(0))
            continue
        tok = m.group(0)
        if not tok.startswith(("'", '"')) and any(ord(c) > 0x7F or (ord(c) < 0x20 and c not in " \t\n") for c in tok):
            # Postgres takes these bytes as part of a name (and a following $x$ would then start a quote the
            # tokenizer misreads): outside a quoted literal or name, open-ctem's dumps are plain ASCII
            raise DumpRefused("non-ASCII text outside a quoted name or string")
        if m.group("word"):
            out.append(("w", m.group("word").lower()))
        elif m.group(0).startswith('"'):
            out.append(("q", m.group(0)[1:-1].replace('""', '"').lower()))
        elif m.group("semi"):
            out.append((";", ";"))
        elif m.group("open"):
            out.append(("(", "("))
        i = m.end()
    return out


def _check_sql(desc: str, sql: str) -> None:
    toks, starts = _tokens(sql), [0]
    for n, (kind, word) in enumerate(toks):
        if kind == "w" and word in BAD_WORDS:
            raise DumpRefused(f"'{word.upper()}' in a {desc} entry")
        if kind in "wq" and n + 1 < len(toks) and toks[n + 1][0] == "(" and BAD_CALL.match(word):
            raise DumpRefused(f"a call to {word} in a {desc} entry")
        if kind == ";":
            starts.append(n + 1)
    for s in starts:
        words = []
        for kind, word in toks[s:s + 3]:
            if kind != "w":
                break
            words.append(word)
        if not words and s >= len(toks):
            continue
        lead = " ".join(words)
        if not any(lead == ok or lead.startswith(ok + " ") for ok in LEADS[desc]):
            raise DumpRefused(f"a {desc} entry runs '{lead.upper() or '?'}'")
        if lead.startswith(("create table", "create unlogged table")):
            # a table is only ever a column list: never AS (a copy of another table), OF a type, or a PARTITION OF
            for kind, word in toks[s:]:
                if kind in "(;":
                    break
                if kind == "w" and word in ("as", "of", "partition"):
                    raise DumpRefused(f"a table created {word.upper()} something else")


def check_entry(e: dict) -> None:
    desc, defn, copy = e["desc"] or "", e["defn"] or "", e["copy"] or ""
    for field in ("tag", "desc", "schema", "space", "am", "owner"):
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in e.get(field) or ""):
            raise DumpRefused(f"a control character in an entry's {field}")   # pg_restore prints these into SQL comments
    if e["data"] and desc != "TABLE DATA":
        raise DumpRefused(f"a {desc} entry carries data")
    if desc == "TABLE DATA":
        if defn or not e["data"] or not COPY_RE.fullmatch(copy):
            raise DumpRefused(f"table data for {e['tag']} is not a plain COPY")
        return
    if copy:
        raise DumpRefused(f"a {desc} entry runs a COPY")
    if desc in EXACT:
        if not EXACT[desc].fullmatch(defn):
            raise DumpRefused(f"unexpected {desc} setting")
    elif desc == "SCHEMA":
        if not SCHEMA_RE.fullmatch(defn):
            raise DumpRefused("a schema entry does more than create the schema")
    elif desc == "EXTENSION":
        m = EXT_RE.fullmatch(defn)
        if not m or m.group(1) != e["tag"] or m.group(1) not in EXTENSIONS:
            raise DumpRefused(f"extension {e['tag']} is not one open-ctem uses")
    elif desc in LEADS:
        _check_sql(desc, defn)
    elif desc not in SKIPPED:
        raise DumpRefused(f"a {desc} entry ({e['tag']}); open-ctem's dumps have none")


def check_dump(blocks) -> int:
    """Raise DumpRefused unless every entry in the dump is one open-ctem's own dumps contain."""
    toc = read_toc(_Stream(blocks).read)
    for e in toc:
        check_entry(e)
    # pg_restore takes quoting rules from these entries, and assumes backslash escapes when STDSTRINGS is missing:
    # every check above assumes standard strings and UTF-8, so both must be there, once
    for desc in ("ENCODING", "STDSTRINGS"):
        if sum(1 for e in toc if e["desc"] == desc) != 1:
            raise DumpRefused(f"the dump must set {desc.lower()} exactly once")
    return len(toc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dump_check")
    ap.add_argument("--in", dest="src", required=True)
    ap.add_argument("--name", required=True)
    a = ap.parse_args(argv)
    try:
        n = None
        for name, blocks in entries(a.src, _password()):
            if name == a.name:
                if n is not None:   # the restore would read both, one after the other: only one is checked
                    raise DumpRefused(f"the backup holds {a.name} twice")
                n = check_dump(blocks)
            for _ in blocks:
                pass
        if n is None:
            print(f"{a.name} is not in this backup.", file=sys.stderr)
            return 3
        print(f"The database dump holds only tables, rows and indexes ({n} entries).")
        return 0
    except DumpRefused as exc:
        print(f"Refusing this database dump: {exc}.", file=sys.stderr)
        return 4
    except BackupError as exc:
        print(f"Backup error: {exc}.", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 -- out of memory, a damaged file: the restore stops, with a plain reason
        print(f"The database dump could not be checked ({type(exc).__name__}), so it was not restored.", file=sys.stderr)
        return 5


if __name__ == "__main__":
    sys.exit(main())
