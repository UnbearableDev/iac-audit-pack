"""The 5 MCP tool functions for hu-postcode-validator.

Each is async, returns a dict shaped {type, text, structuredContent}.
Apify charging is wired in main.py at registration time so tools stay
free of platform coupling (cleaner for testing).
"""

from __future__ import annotations

from typing import Any

from postcode import db

# Roman numerals → int for Budapest districts (I..XXIII)
_ROMAN = {
    "I": 1, "II": 2, "III": 3, "IV": 4, "V": 5, "VI": 6, "VII": 7, "VIII": 8,
    "IX": 9, "X": 10, "XI": 11, "XII": 12, "XIII": 13, "XIV": 14, "XV": 15,
    "XVI": 16, "XVII": 17, "XVIII": 18, "XIX": 19, "XX": 20, "XXI": 21,
    "XXII": 22, "XXIII": 23,
}
_INT_TO_ROMAN = {v: k for k, v in _ROMAN.items()}


def _err(msg: str, **ctx: Any) -> dict[str, Any]:
    return {
        "type": "text",
        "text": f"Error: {msg}",
        "structuredContent": {"error": msg, **ctx},
    }


def _ok(text: str, **data: Any) -> dict[str, Any]:
    return {"type": "text", "text": text, "structuredContent": data}


# ── Tool implementations ───────────────────────────────────────────────────


async def lookup_postcode(postcode: int | str) -> dict[str, Any]:
    """Return settlement(s) and county for a Hungarian postcode.

    Args:
        postcode: 4-digit Hungarian postcode (int or string of digits).
    """
    try:
        pc_int = int(str(postcode).strip())
    except (TypeError, ValueError):
        return _err(f"postcode must be a 4-digit integer, got {postcode!r}")
    if not (1011 <= pc_int <= 9999):
        return _err(f"postcode out of valid HU range (1011-9999): {pc_int}")

    rows = db.find_by_postcode(pc_int)
    bp_district = db.bp_district_for_postcode(pc_int)

    if not rows:
        return _ok(
            f"No settlement found for postcode {pc_int}.",
            postcode=pc_int,
            found=False,
            matches=[],
        )

    primary = rows[0]
    summary = f"{pc_int} → {primary['settlement']}"
    if primary.get("settlement_part"):
        summary += f", {primary['settlement_part']}"
    if primary.get("county"):
        summary += f" ({primary['county']} county)"

    return _ok(
        summary,
        postcode=pc_int,
        found=True,
        match_count=len(rows),
        matches=rows,
        budapest_district=bp_district,
    )


async def lookup_city(city: str) -> dict[str, Any]:
    """Return all postcodes for a Hungarian city/settlement (diacritic-insensitive).

    Args:
        city: Hungarian settlement name (e.g. 'Szeged', 'Gyor', 'Budapest').
    """
    if not city or not city.strip():
        return _err("city must be a non-empty string")

    rows = db.find_by_city(city)
    if not rows:
        return _ok(
            f"No postcodes found for city '{city}'.",
            city=city,
            found=False,
            matches=[],
        )

    postcodes = sorted({r["postcode"] for r in rows})
    return _ok(
        f"{city}: {len(postcodes)} postcode{'s' if len(postcodes) != 1 else ''} "
        f"({postcodes[0]}{('-' + str(postcodes[-1])) if len(postcodes) > 1 else ''})",
        city=city,
        found=True,
        postcode_count=len(postcodes),
        postcodes=postcodes,
        matches=rows,
    )


async def validate_address(postcode: int | str, city: str) -> dict[str, Any]:
    """Validate that postcode and city are a valid Hungarian pairing.

    Args:
        postcode: 4-digit HU postcode.
        city: Settlement name.
    """
    try:
        pc_int = int(str(postcode).strip())
    except (TypeError, ValueError):
        return _err(f"postcode must be a 4-digit integer, got {postcode!r}")
    if not city or not city.strip():
        return _err("city must be a non-empty string")

    rows = db.find_by_postcode(pc_int)
    if not rows:
        return _ok(
            f"Invalid: postcode {pc_int} does not exist in the HU postal catalog.",
            valid=False,
            reason="postcode_not_found",
            postcode=pc_int,
            city=city,
        )

    city_norm = db.normalize(city)
    settlements_at_pc = {db.normalize(r["settlement"]) for r in rows}
    if city_norm in settlements_at_pc:
        return _ok(
            f"Valid: postcode {pc_int} matches city '{city}'.",
            valid=True,
            postcode=pc_int,
            city=city,
            matched_settlement=rows[0]["settlement"],
            county=rows[0].get("county"),
        )

    expected = sorted({r["settlement"] for r in rows})
    return _ok(
        f"Invalid: postcode {pc_int} is assigned to {expected}, not '{city}'.",
        valid=False,
        reason="city_mismatch",
        postcode=pc_int,
        city=city,
        expected_settlements=expected,
    )


async def list_postcodes_in_county(county_name: str) -> dict[str, Any]:
    """List all postcodes in a given Hungarian county (vármegye).

    Args:
        county_name: County name, e.g. 'Pest', 'Csongrád-Csanád', 'Budapest'.
    """
    if not county_name or not county_name.strip():
        return _err(
            "county_name must be a non-empty string",
            valid_counties=db.all_counties(),
        )

    rows = db.find_by_county(county_name)
    if not rows:
        return _ok(
            f"No postcodes found for county '{county_name}'.",
            county=county_name,
            found=False,
            valid_counties=db.all_counties(),
            matches=[],
        )

    unique_pcs = sorted({r["postcode"] for r in rows})
    return _ok(
        f"{county_name}: {len(rows)} entries across {len(unique_pcs)} unique postcodes.",
        county=county_name,
        found=True,
        unique_postcode_count=len(unique_pcs),
        entry_count=len(rows),
        postcodes=unique_pcs,
        matches=rows,
    )


async def budapest_district_lookup(district_number: int | str) -> dict[str, Any]:
    """Return Budapest postcodes for a district (I-XXIII or 1-23).

    Args:
        district_number: District as int (1-23) or roman numeral string ('X', 'XIV').
    """
    # Accept int or roman string
    if isinstance(district_number, int):
        n = district_number
    else:
        s = str(district_number).strip().upper().rstrip(".")
        if s in _ROMAN:
            n = _ROMAN[s]
        else:
            try:
                n = int(s)
            except ValueError:
                return _err(
                    f"district_number must be 1-23 or roman I-XXIII, got {district_number!r}"
                )

    if not (1 <= n <= 23):
        return _err(f"district out of range (1-23): {n}")

    roman = _INT_TO_ROMAN[n]
    postcodes = db.bp_postcodes_for_district(roman)

    if not postcodes:
        return _ok(
            f"No postcodes registered for Budapest district {roman}.",
            district=roman,
            district_number=n,
            found=False,
            postcodes=[],
        )

    return _ok(
        f"Budapest {roman}. kerület: {len(postcodes)} postcodes "
        f"({postcodes[0]}-{postcodes[-1]})",
        district=roman,
        district_number=n,
        found=True,
        postcode_count=len(postcodes),
        postcodes=postcodes,
    )
