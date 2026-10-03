#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof deceased
# License: https://github.com/pysnmp/pysnmp/blob/main/LICENSE.rst
#
"""Assembling MIB table rows out of a column walk, shared bookkeeping.

GETBULK walks columns independently: every response row carries one binding
per column, and the instances those bindings name only line up while the
columns happen to hold the same number of rows. A monitoring caller wants
table rows -- one business index, the cell of every column at that index --
so the bindings have to be re-aligned on the index the MIB's INDEX clause
says they share. That alignment lives here, once, so the async front end
stays a thin driver.
"""

from typing import Any, NamedTuple

from pyasn1.error import PyAsn1Error

from pysnmp.proto.rfc1905 import EndOfMibView, NoSuchInstance, NoSuchObject
from pysnmp.smi import error

__all__ = [
    "MISSING_CELL",
    "TableRow",
    "TableRowAssembler",
    "TooManyPendingRows",
    "findTableRow",
]


class _MissingCell:
    """The marker a row carries where its column never delivered a cell.

    A distinct singleton rather than ``None`` or a neighbour's value, so a
    caller can tell "the agent has no such cell" from "the cell is there and
    empty" -- and so a missing cell can never be mistaken for data carried
    over from the previous row or the adjacent column.
    """

    def __repr__(self) -> str:
        """The marker's name, so a row holding it reads clearly."""
        return "MISSING_CELL"

    def __bool__(self) -> bool:
        """Missing is falsy, like the absence of a value it marks."""
        return False


#: Singleton marking a cell the walk never saw. Compare with ``is``.
MISSING_CELL = _MissingCell()


class TableRow(NamedTuple):
    """One assembled row of a MIB table.

    `indices` holds the row's INDEX values, decoded per the table's INDEX
    clause -- composite indexes come out as one typed value per component.
    `cells` holds one value per column of the table's entry, in the order
    :py:meth:`pysnmp.smi.mibs.SNMPv2-SMI.MibTableRow.getColumns` reports
    them (column id ascending); a column that produced no cell for this
    index is :py:data:`MISSING_CELL`.
    """

    indices: tuple
    cells: tuple


class TooManyPendingRows(error.SmiError):
    """More rows are waiting for a lagging column than the caller allowed.

    Rows stay pending while some column has not yet reached their index --
    normally a brief skew between columns of one response. A column that
    never delivers (a hole the agent keeps skipping, a suffix this side
    cannot decode) would otherwise keep later rows pending without bound,
    so crossing `maxPendingRows` fails the walk explicitly instead of
    waiting on a column that is never coming.
    """


def findTableRow(snmpEngine: Any, tableOid: tuple) -> Any:
    """The ``MibTableRow`` whose table or entry OID is `tableOid`.

    Accepts either the table's OID (``ifTable``) or the entry's
    (``ifEntry``) -- the entry is the table's only child, so both spellings
    land on the same row. Raises :py:class:`pysnmp.smi.error.SmiError` when
    no loaded MIB module defines a table there.
    """
    mibBuilder = snmpEngine.getMibBuilder()
    (MibTableRow,) = mibBuilder.importSymbols("SNMPv2-SMI", "MibTableRow")

    matches = [
        symbol
        for module in mibBuilder.mibSymbols.values()
        for symbol in module.values()
        if isinstance(symbol, MibTableRow)
        and (symbol.name == tableOid or symbol.name[:-1] == tableOid)
    ]
    if not matches:
        raise error.SmiError(
            f"OID {tableOid} is not a table or entry of any loaded MIB module"
        )
    # The entry OID is unique across modules; an exact match wins over a
    # table-prefix one should both ever show up.
    for symbol in matches:
        if symbol.name == tableOid:
            return symbol
    return matches[0]


class TableRowAssembler:
    """Re-align walked column bindings into rows, keyed by the table's INDEX.

    Fed one ``(name, value)`` binding at a time -- in whatever interleaving
    the walk produces -- and hands back the rows that just became complete.
    A row is complete once every column has either delivered its cell for
    the row's index, moved past it (the cell does not exist), or ended
    (left its subtree or answered ``endOfMibView``); columns that ended
    early never hold the others back.
    """

    def __init__(self, rowNode: Any, maxPendingRows: int = 1000) -> None:
        """Bind the assembler to a table row and a pending-row budget."""
        if maxPendingRows < 1:
            raise error.SmiError(
                f"maxPendingRows must be a positive number, got {maxPendingRows!r}"
            )
        self.rowNode = rowNode
        #: ``(colId, colName, colNode)`` per column, column id ascending --
        #: the order :py:class:`TableRow` cells come in.
        self.columns = rowNode.getColumns()
        self.maxPendingRows = maxPendingRows
        # How far each column has walked, as the last instance suffix seen.
        self._position: dict[tuple, tuple | None] = {
            colName: None for _colId, colName, _colNode in self.columns
        }
        self._ended: set[tuple] = set()
        # suffix -> [indices, {colName: value}] for rows still open.
        self._rows: dict[tuple, list] = {}
        # Largest index already handed to the caller. Rows close in index
        # order and the closing threshold never retreats, so a binding
        # naming an index at or below this -- a repeated OID, say -- is a
        # straggler for a row already reported, not a new row.
        self._emittedUpTo: "tuple | None" = None

    def _columnFor(self, name: tuple) -> "tuple | None":
        """The column whose subtree `name` falls under, if any."""
        for _colId, colName, _colNode in self.columns:
            if colName == name[: len(colName)]:
                return colName
        return None

    def _decodeIndices(self, suffix: tuple) -> "tuple | None":
        """The row's INDEX values for `suffix`, or None when it is not one.

        Decoding follows the INDEX clause, so composite indexes, variable-
        length strings and IMPLIED components all come apart here. A suffix
        that does not parse -- or parses but does not re-encode to itself
        -- belongs to no row and is dropped rather than guessed at.
        """
        try:
            indices = self.rowNode.getIndicesFromInstId(suffix)
            if tuple(self.rowNode.getInstIdFromIndices(*indices)) != tuple(suffix):
                return None
        except (error.SmiError, PyAsn1Error, ValueError, TypeError, IndexError):
            return None
        return indices

    def feed(self, name: tuple, value: Any) -> list[TableRow]:
        """Take one walked binding, return the rows it completed.

        Bindings outside every column of the table (unknown columns) are
        ignored, and so are exception values other than ``endOfMibView`` --
        they carry no cell. A repeated binding is idempotent: recorded
        again while its row is still open, ignored once the row has been
        reported.
        """
        name = tuple(name)
        colName = self._columnFor(name)
        if colName is None:
            return []

        if isinstance(value, EndOfMibView):
            # This column left its subtree or the agent said it is done;
            # the remaining columns walk on without it.
            self._ended.add(colName)
            return self._complete()

        suffix = name[len(colName) :]
        if not suffix:
            return []

        position = self._position[colName]
        if position is None or suffix > position:
            self._position[colName] = suffix

        if isinstance(value, (NoSuchObject, NoSuchInstance)):
            # No cell at this instance -- the position moved, that is all
            # the binding says.
            return self._complete()

        if self._emittedUpTo is not None and suffix <= self._emittedUpTo:
            # A repeated or out-of-order binding for a row the caller
            # already has. Recording it would resurrect the row and report
            # it twice.
            return self._complete()

        indices = self._decodeIndices(suffix)
        if indices is None:
            # An index the table's INDEX clause cannot explain. The column
            # still moved past this suffix, so rows below it can close.
            return self._complete()

        row = self._rows.get(suffix)
        if row is None:
            row = self._rows[suffix] = [indices, {}]
        row[1][colName] = value

        return self._complete()

    def _complete(self) -> list[TableRow]:
        openPositions = [
            self._position[colName]
            for _colId, colName, _colNode in self.columns
            if colName not in self._ended
        ]
        if not openPositions:
            threshold = None  # every column ended: all remaining rows close
        elif None in openPositions:
            return []  # some column has not produced anything yet
        else:
            threshold = min(openPositions)

        completed = []
        for suffix in sorted(self._rows):
            if threshold is not None and suffix > threshold:
                continue
            indices, cells = self._rows.pop(suffix)
            self._emittedUpTo = suffix
            completed.append(
                TableRow(
                    indices,
                    tuple(
                        cells.get(colName, MISSING_CELL)
                        for _colId, colName, _colNode in self.columns
                    ),
                )
            )

        if len(self._rows) > self.maxPendingRows:
            raise TooManyPendingRows(
                f"more than {self.maxPendingRows} rows pending on columns that "
                f"have not caught up at {self.rowNode.name!r}"
            )
        return completed

    def finish(self) -> list[TableRow]:
        """Close every row still open, in index order.

        Called when the walk is over: whatever a column never delivered for
        these indexes is not coming, so the cells are :py:data:`MISSING_CELL`.
        """
        rows = [
            TableRow(
                indices,
                tuple(
                    cells.get(colName, MISSING_CELL)
                    for _colId, colName, _colNode in self.columns
                ),
            )
            for suffix, (indices, cells) in sorted(self._rows.items())
        ]
        self._rows.clear()
        return rows
