"""Boot-time schema evolution must survive a column or index that already exists."""
from sqlalchemy import Column, Index, Integer, MetaData, String, Table, create_engine, inspect, text


def test_evolve_adds_missing_and_tolerates_existing(tmp_path):
    from api.core.db import _evolve

    eng = create_engine(f"sqlite:///{tmp_path / 'evolve.db'}")
    with eng.begin() as conn:
        conn.execute(text("CREATE TABLE widgets (id INTEGER PRIMARY KEY, name VARCHAR(10))"))
        conn.execute(text("CREATE INDEX ix_widgets_name ON widgets (name)"))
    md = MetaData()
    Table("widgets", md, Column("id", Integer, primary_key=True), Column("name", String(10)),
          Column("count", Integer, server_default="0", nullable=False),
          Index("ix_widgets_name", "name"), Index("ix_widgets_count", "count"))
    for _ in range(2):  # second run: everything exists already, nothing may blow up
        with eng.begin() as conn:
            _evolve(conn, md)
    insp = inspect(eng)
    assert "count" in {c["name"] for c in insp.get_columns("widgets")}
    assert {"ix_widgets_name", "ix_widgets_count"} <= {i["name"] for i in insp.get_indexes("widgets")}
