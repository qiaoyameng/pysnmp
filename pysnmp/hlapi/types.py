#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof deceased
#
"""Shared type definitions for the pysnmp high-level API.

These types are used across the sync and asyncio HLAPI surfaces to
provide consistent return-type annotations for SNMP command results.
"""

from typing import Any, NamedTuple

__all__ = ["MISSING_CELL", "MissingCell", "SnmpResponse", "SnmpTableResponse"]


class MissingCell:
    """Marker for a table cell that was absent from the agent's response.

    The singleton :data:`MISSING_CELL` is distinct from SNMP exception values
    such as ``noSuchInstance``. It means no value for this row and column has
    been observed, so callers must not treat it as a value copied from another
    row or from a neighbouring column.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self):
        return "MISSING_CELL"

    def __bool__(self):
        return False


MISSING_CELL = MissingCell()


class SnmpResponse(NamedTuple):
    """Result of an SNMP command (GET / SET / NEXT / BULK / notification).

    This is a ``NamedTuple`` subclass of ``tuple``, so existing code that
    unpacks the 4-tuple positionally continues to work unchanged::

        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(...)

    Attributes
    ----------
    errorIndication
        ``None`` on success, or an error-indication object/string on
        SNMP engine error.
    errorStatus
        ``0`` / ``None`` on success, or a truthy value indicating a
        protocol-level PDU error.
    errorIndex
        ``0`` when no error, otherwise a 1-based index into *varBinds*
        referring to the variable that caused the error.
    varBinds
        A sequence of resolved var-bind pairs (typically
        :class:`~pysnmp.smi.rfc1902.ObjectType` instances).
    """

    errorIndication: Any
    errorStatus: Any
    errorIndex: Any
    varBinds: Any


class SnmpTableResponse(NamedTuple):
    """One conceptual MIB table row assembled from independently walked columns.

    ``indices`` contains the typed INDEX values decoded using the row's MIB
    definition. ``varBinds`` is ordered by the requested columns; a missing cell
    contains :data:`MISSING_CELL` rather than a value borrowed from another
    binding.
    """

    errorIndication: Any
    errorStatus: Any
    errorIndex: Any
    indices: Any
    varBinds: Any
