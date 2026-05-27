"""Read-only SQLite access for the postcode dataset."""

from __future__ import annotations

import sqlite3
import unicodedata
from pathlib import Path
from typing import Any

# Path resolution: the SQLite is at /usr/src/app/data/ when running in the Apify
# container, and at <project>/data/ when running locally via `apify run`.
_DB_PATH_CANDIDATES = [
    Path("/usr/src/app/data/hu_postcodes.sqlite"),
    Path(__file__).resolve().parent.parent / "data" / "hu_postcodes.sqlite",
]


def _find_db() -> Path:
    for p in _DB_PATH_CANDIDATES:
        if p.exists():
            return p
    raise FileNotFoundError(
        f"hu_postcodes.sqlite not found. Tried: {[str(p) for p in _DB_PATH_CANDIDATES]}"
    )


def _connect() -> sqlite3.Connection:
    db = _find_db()
    # Open read-only via URI mode for safety
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def normalize(s: str | None) -> str:
    """NFKD-strip diacritics + lowercase for fuzzy match. Must match build_db.py."""
    if not s:
        return ""
    return "".join(
        c for c in unicodedata.normalize("NFKD", s).lower() if not unicodedata.combining(c)
    ).strip()


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


# ── Query helpers ──────────────────────────────────────────────────────────


def find_by_postcode(postcode: int) -> list[dict[str, Any]]:
    """All postcode rows matching the exact postcode."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT postcode, settlement, settlement_part, county, jaras_neve, ksh_code "
            "FROM postcodes WHERE postcode = ? "
            "ORDER BY settlement, settlement_part",
            (postcode,),
        )
        return [row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def find_by_city(city: str) -> list[dict[str, Any]]:
    """All rows matching the city/settlement name (diacritic-insensitive)."""
    conn = _connect()
    try:
        norm = normalize(city)
        if not norm:
            return []
        cur = conn.execute(
            "SELECT postcode, settlement, settlement_part, county, jaras_neve, ksh_code "
            "FROM postcodes WHERE settlement_normalized = ? "
            "ORDER BY postcode",
            (norm,),
        )
        return [row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def find_by_county(county_name: str) -> list[dict[str, Any]]:
    """All postcodes in a given county. Exact county name match (case-insensitive)."""
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT postcode, settlement, settlement_part, county, jaras_neve, ksh_code "
            "FROM postcodes WHERE LOWER(county) = LOWER(?) "
            "ORDER BY postcode, settlement",
            (county_name,),
        )
        return [row_to_dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def bp_district_for_postcode(postcode: int) -> str | None:
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT district FROM bp_districts WHERE postcode = ?",
            (postcode,),
        )
        row = cur.fetchone()
        return row["district"] if row else None
    finally:
        conn.close()


def bp_postcodes_for_district(district: str) -> list[int]:
    """Given a district roman numeral (with or without trailing '.'), return
    all Budapest postcodes in that district."""
    d = district.strip().rstrip(".") + "."
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT postcode FROM bp_districts WHERE district = ? ORDER BY postcode",
            (d,),
        )
        return [r["postcode"] for r in cur.fetchall()]
    finally:
        conn.close()


def all_counties() -> list[str]:
    conn = _connect()
    try:
        cur = conn.execute(
            "SELECT DISTINCT county FROM postcodes WHERE county IS NOT NULL ORDER BY county"
        )
        return [r["county"] for r in cur.fetchall()]
    finally:
        conn.close()
