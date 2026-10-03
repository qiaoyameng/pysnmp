#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof deceased
# License: https://github.com/pysnmp/pysnmp/blob/main/LICENSE.rst
#
"""Assemble independent GETBULK column walks into conceptual MIB table rows."""

from dataclasses import dataclass
from typing import Any

from pyasn1.error import PyAsn1Error
from pyasn1.type.univ import Null

from pysnmp.hlapi.types import MISSING_CELL, SnmpTableResponse
from pysnmp.proto import errind
from pysnmp.proto.rfc1905 import endOfMibView
from pysnmp.smi import error as smi_error
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

__all__ = ["tableOptions"]


@dataclass(frozen=True)
class _Column:
    position: int
    name: tuple[int, ...]


@dataclass(frozen=True)
class _TableDefinition:
    mib_builder: Any
    row: Any
    columns: tuple[_Column, ...]


def tableOptions(options: dict[str, Any]) -> tuple[bool, int, int]:
    """Read options used by row assembly; request options remain in *options*."""
    ignore_non_increasing = options.pop("ignoreNonIncreasingOid", False)
    max_calls = options.pop("maxCalls", 0)
    max_pending_rows = options.pop("maxRows", 0) or options.pop("maxPendingRows", 0)
    return ignore_non_increasing, max_calls, max_pending_rows


def _accessible(column: Any) -> bool:
    return column.getMaxAccess() in ("readonly", "readwrite", "readcreate")


def _load_definition(vb_processor: Any, snmp_engine: Any, var_bind: Any) -> _TableDefinition:
    mib_view = vb_processor.getMibViewController(snmp_engine)
    mib_builder = mib_view.mibBuilder
    mib_table, mib_table_row = mib_builder.importSymbols(
        "SNMPv2-SMI", "MibTable", "MibTableRow"
    )
    node = var_bind[0].getMibNode()

    if isinstance(node, mib_table):
        rows = sorted(
            (
                symbol
                for symbols in mib_builder.mibSymbols.values()
                for symbol in symbols.values()
                if isinstance(symbol, mib_table_row)
                and symbol.name[:-1] == node.name
            ),
            key=lambda symbol: symbol.name,
        )
        if not rows:
            raise smi_error.SmiError(
                f"MIB table {tuple(node.name)!r} contains no row definitions"
            )
        index_names = rows[0].getIndexNames()
        if any(candidate.getIndexNames() != index_names for candidate in rows[1:]):
            raise smi_error.SmiError(
                f"MIB table {tuple(node.name)!r} contains rows with different INDEX definitions"
            )
        row = rows[0]
    elif isinstance(node, mib_table_row):
        row = node
    else:
        raise smi_error.SmiError(
            f"MIB object {tuple(node.name)!r} is neither a table nor a table row"
        )

    if not row.getIndexNames():
        raise smi_error.SmiError(f"MIB table row {tuple(row.name)!r} has no INDEX")

    table_rows = rows if isinstance(node, mib_table) else [row]
    readable_columns = {}
    for table_row in table_rows:
        for _, _, column in table_row.getColumns():
            if _accessible(column):
                readable_columns[column.name] = column
    readable_columns = list(readable_columns.values())
    readable_columns.sort(key=lambda column: column.name)
    request_var_binds = vb_processor.makeVarBinds(
        snmp_engine,
        [
            ObjectType(ObjectIdentity(tuple(column.name)), Null(""))
            for column in readable_columns
        ],
    )

    if not request_var_binds:
        raise smi_error.SmiError(f"MIB table row {tuple(row.name)!r} has no readable columns")

    columns = tuple(
        _Column(position, tuple(column.name))
        for position, column in enumerate(readable_columns)
    )
    return _TableDefinition(mib_builder, row, columns)


def _decode_indices(definition: _TableDefinition, suffix: tuple[int, ...]) -> tuple[Any, ...]:
    indices: list[Any] = []
    remaining = suffix
    try:
        for implied, module_name, symbol_name in definition.row.getIndexNames():
            (index_node,) = definition.mib_builder.importSymbols(module_name, symbol_name)
            value, remaining = definition.row.setFromName(
                index_node.syntax, remaining, implied, indices
            )
            indices.append(value)
        if remaining:
            raise smi_error.SmiError(
                f"Excessive instance identifier sub-OIDs left: {remaining}"
            )
    except (PyAsn1Error, smi_error.SmiError) as exc:
        raise errind.TableIndexError(
            f"Could not decode table index suffix {suffix!r}: {exc}"
        ) from exc

    return tuple(indices)


async def assemble_bulk_table(
    *,
    bulk_cmd: Any,
    vb_processor: Any,
    snmp_engine: Any,
    auth_data: Any,
    transport_target: Any,
    context_data: Any,
    non_repeaters: int,
    max_repetitions: int,
    table_var_bind: Any,
    options: dict[str, Any],
) -> Any:
    """Yield conceptual rows from independently progressing GETBULK columns."""
    if non_repeaters != 0:
        raise ValueError("bulk_table_cmd requires nonRepeaters to be 0")
    if max_repetitions <= 0:
        raise ValueError("bulk_table_cmd requires a positive maxRepetitions")

    ignore_non_increasing, max_calls, max_pending_rows = tableOptions(options)
    definition = _load_definition(vb_processor, snmp_engine, table_var_bind)
    active = list(definition.columns)
    cursors = {column.position: column.name for column in definition.columns}
    cells = {column.position: {} for column in definition.columns}
    decoded_indices = {}
    ended: set[int] = set()
    stale_calls = {column.position: 0 for column in definition.columns}
    request_cursors = dict(cursors)
    calls = 0

    def flush_ready(final: bool) -> list[SnmpTableResponse]:
        pending_keys = set()
        for column_cells in cells.values():
            pending_keys.update(column_cells)
        if not pending_keys:
            return []

        if final:
            keys = sorted(pending_keys)
        else:
            active_positions = {column.position for column in active}
            if not active_positions or any(
                not cells[position] for position in active_positions
            ):
                return []
            frontiers = [
                min(column_cells)
                for position, column_cells in cells.items()
                if position in active_positions
            ]
            frontier = min(frontiers)
            keys = sorted(key for key in pending_keys if key <= frontier)

        responses = []
        for key in keys:
            row_var_binds = tuple(
                cells[column.position].pop(key, MISSING_CELL)
                for column in definition.columns
            )
            responses.append(
                SnmpTableResponse(
                    None, 0, 0, decoded_indices.get(key, ()), row_var_binds
                )
            )

        remaining_keys = set()
        for column_cells in cells.values():
            remaining_keys.update(column_cells)
        for key in list(decoded_indices):
            if key not in remaining_keys:
                del decoded_indices[key]

        return responses

    while active:
        request_columns = list(active)
        request_var_binds = [
            (request_cursors[column.position], Null(""))
            for column in request_columns
        ]
        error_indication, error_status, error_index, var_bind_table = await bulk_cmd(
            snmp_engine,
            auth_data,
            transport_target,
            context_data,
            0,
            max_repetitions,
            *request_var_binds,
            **options,
        )
        calls += 1

        if error_indication or error_status:
            for response in flush_ready(True):
                yield response
            yield SnmpTableResponse(error_indication, error_status, error_index, (), ())
            return

        if not var_bind_table:
            if ignore_non_increasing:
                if max_calls and calls >= max_calls:
                    return
                continue
            yield SnmpTableResponse(
                errind.TableNoProgressError("GETBULK returned no variable bindings"),
                0,
                0,
                (),
                (),
            )
            return

        if any(len(response_row) != len(request_columns) for response_row in var_bind_table):
            yield SnmpTableResponse(
                errind.DataMismatch("GETBULK response width does not match request"),
                0,
                0,
                (),
                (),
            )
            return

        progressed = {column.position: False for column in request_columns}
        first_index_error = None
        repeated_positions = set()

        for response_row in var_bind_table:
            for slot, var_bind in enumerate(response_row):
                column = request_columns[slot]
                position = column.position
                name, value = var_bind
                name = tuple(name)

                if value is endOfMibView:
                    ended.add(position)
                    continue
                if name[: len(column.name)] != column.name:
                    ended.add(position)
                    continue

                suffix = name[len(column.name) :]
                if not suffix:
                    ended.add(position)
                    continue
                if name == cursors[position]:
                    repeated_positions.add(position)
                    progressed[position] = True
                    continue
                if name < cursors[position]:
                    yield SnmpTableResponse(
                        errind.OidNotIncreasing(f"Column {tuple(column.name)!r} went backwards"),
                        0,
                        position + 1,
                        (),
                        (),
                    )
                    return

                try:
                    indices = _decode_indices(definition, suffix)
                except errind.TableIndexError as exc:
                    if first_index_error is None:
                        first_index_error = exc
                    continue

                progressed[position] = True
                cursors[position] = name
                cells[position][suffix] = var_bind
                decoded_indices[suffix] = indices

        active = [column for column in active if column.position not in ended]
        for column in active:
            if column.position not in repeated_positions:
                request_cursors[column.position] = cursors[column.position]

        if first_index_error is not None:
            yield SnmpTableResponse(first_index_error, 0, 0, (), ())
            return

        pending_keys = set()
        for column_cells in cells.values():
            pending_keys.update(column_cells)
        if active and max_pending_rows and len(pending_keys) > max_pending_rows:
            yield SnmpTableResponse(
                errind.TableRowLimitError(
                    f"More than {max_pending_rows} rows are waiting for missing columns"
                ),
                0,
                0,
                (),
                (),
            )
            return

        active_positions = {column.position for column in active}
        for column in definition.columns:
            position = column.position
            if position not in active_positions:
                continue
            if position in repeated_positions:
                stale_calls[position] += 1
            elif progressed.get(position):
                stale_calls[position] = 0
            else:
                stale_calls[position] += 1

        if any(stale_calls[position] > 1 for position in active_positions):
            if not ignore_non_increasing:
                for response in flush_ready(True):
                    yield response
                stalled_column = next(
                    column
                    for column in active
                    if stale_calls[column.position] > 1
                )
                yield SnmpTableResponse(
                    errind.OidNotIncreasing(
                        f"Column {tuple(stalled_column.name)!r} did not advance"
                    ),
                    0,
                    stalled_column.position + 1,
                    (),
                    (),
                )
                return

        if active:
            for response in flush_ready(False):
                yield response
        else:
            for response in flush_ready(True):
                yield response

        if max_calls and calls >= max_calls:
            return
