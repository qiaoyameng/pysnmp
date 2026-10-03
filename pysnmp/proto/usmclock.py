"""Portable representation of authenticated remote USM clock state."""

import time
from collections.abc import Callable, Sequence

FORMAT_VERSION = 1
TIME_WINDOW = 150
MAX_ENGINE_BOOTS = 2147483647

_CLOCK_KEYS = frozenset(
    (
        "securityEngineId",
        "engineBoots",
        "engineTime",
        "latestReceivedEngineTime",
        "savedAt",
    )
)
_TRANSPORT_KEYS = frozenset(("domain", "address", "contextEngineId", "contextName"))
_ENGINE_KEYS = frozenset(("securityEngineId", "savedAt", "transport"))


def serialize_octets(value):
    return bytes(value).hex()


def deserialize_octets(value, field):
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a hexadecimal string")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{field} must be a hexadecimal string") from exc
    if not 5 <= len(result) <= 32:
        raise ValueError(f"{field} must be between 5 and 32 octets")
    return result


def _integer(value, field, *, minimum=0, maximum=MAX_ENGINE_BOOTS):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{field} is out of range")
    return value


def serialize_transport(domain, address, context_engine_id, context_name):
    return {
        "domain": list(domain),
        "address": list(address),
        "contextEngineId": serialize_octets(context_engine_id),
        "contextName": bytes(context_name).hex(),
    }


def normalize_transport(value):
    if not isinstance(value, dict):
        raise ValueError("transport must be an object or null")
    if set(value) != _TRANSPORT_KEYS:
        raise ValueError("transport has an invalid set of fields")

    domain = value["domain"]
    address = value["address"]
    if not isinstance(domain, list) or not domain or not all(
        isinstance(part, int)
        and not isinstance(part, bool)
        and 0 <= part <= 4294967295
        for part in domain
    ):
        raise ValueError("transport.domain must be a non-empty list of OID arcs")
    if domain[0] > 2:
        raise ValueError("transport.domain has an invalid first OID arc")

    if not isinstance(address, list) or not 2 <= len(address) <= 4:
        raise ValueError("transport.address must identify a network endpoint")
    if not isinstance(address[0], str) or not address[0]:
        raise ValueError("transport.address must contain a host name")
    _integer(address[1], "transport.address port", maximum=65535)
    for extra in address[2:]:
        if not isinstance(extra, int) or isinstance(extra, bool):
            raise ValueError("transport.address contains an invalid scope value")

    context_engine_id = deserialize_octets(
        value["contextEngineId"], "transport.contextEngineId"
    )
    context_name_hex = value["contextName"]
    if not isinstance(context_name_hex, str):
        raise ValueError("transport.contextName must be a hexadecimal string")
    try:
        context_name = bytes.fromhex(context_name_hex)
    except ValueError as exc:
        raise ValueError(
            "transport.contextName must be a hexadecimal string"
        ) from exc
    if len(context_name) > 32:
        raise ValueError("transport.contextName is too long")
    return {
        "domain": tuple(domain),
        "address": tuple(address),
        "contextEngineId": context_engine_id,
        "contextName": context_name,
    }


def normalize_clock_fields(entry):
    if not isinstance(entry, dict):
        raise ValueError("remote clock entry must be an object")

    if set(entry) != _CLOCK_KEYS:
        raise ValueError("remote clock entry has an invalid set of fields")

    engine_id = deserialize_octets(entry["securityEngineId"], "securityEngineId")
    boots = _integer(
        entry["engineBoots"], "engineBoots", maximum=MAX_ENGINE_BOOTS - 1
    )
    engine_time = _integer(entry["engineTime"], "engineTime")
    latest = _integer(
        entry["latestReceivedEngineTime"], "latestReceivedEngineTime"
    )
    saved_at = _integer(entry["savedAt"], "savedAt", maximum=2**63 - 1)
    if latest < engine_time:
        raise ValueError("latestReceivedEngineTime must not precede engineTime")
    if boots == 0 and (engine_time or latest):
        raise ValueError("engine time must be zero before the first engine boot")

    return {
        "securityEngineId": engine_id,
        "engineBoots": boots,
        "engineTime": engine_time,
        "latestReceivedEngineTime": latest,
        "savedAt": saved_at,
    }


def normalize_engine_fields(entry):
    if not isinstance(entry, dict):
        raise ValueError("remote engine entry must be an object")
    if set(entry) != _ENGINE_KEYS:
        raise ValueError("remote engine entry has an invalid set of fields")

    engine_id = deserialize_octets(entry["securityEngineId"], "securityEngineId")
    saved_at = _integer(entry["savedAt"], "savedAt", maximum=2**63 - 1)
    transport = normalize_transport(entry["transport"])
    return {
        "securityEngineId": engine_id,
        "savedAt": saved_at,
        "transport": transport,
    }


def validate_snapshot(snapshot):
    if not isinstance(snapshot, dict):
        raise ValueError("remote clock snapshot must be an object")
    if set(snapshot) != {"version", "entries"}:
        raise ValueError("remote clock snapshot has an invalid set of fields")
    if snapshot["version"] != FORMAT_VERSION:
        raise ValueError("unsupported remote clock snapshot version")
    if not isinstance(snapshot["entries"], list):
        raise ValueError("remote clock snapshot entries must be a list")
    return snapshot["entries"]


def make_snapshot(entries: Sequence[dict]):
    return {"version": FORMAT_VERSION, "entries": list(entries)}


def is_continuous_clock(candidate, existing):
    if existing is None:
        return True
    boots, _engine_time, latest, saved_at = existing
    candidate_boots = candidate["engineBoots"]
    candidate_latest = candidate["latestReceivedEngineTime"]
    candidate_saved_at = candidate["savedAt"]
    return (
        candidate_boots > boots
        or candidate_boots == boots
        and (
            candidate_latest > latest
            or candidate_latest == latest and candidate_saved_at >= saved_at
        )
    )


def is_fresh_clock(candidate, now):
    age = now - candidate["savedAt"]
    return 0 <= age <= TIME_WINDOW


def current_time(clock: Callable[[], float | int] | None):
    return int((clock or time.time)())
