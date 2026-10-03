"""Assembling independently progressing GETBULK columns into MIB table rows."""

import pytest

from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi.asyncio import MISSING_CELL, bulk_table_cmd
from pysnmp.hlapi.asyncio import cmdgen as async_cmdgen
from pysnmp.hlapi.types import SnmpTableResponse
from pysnmp.proto import errind
from pysnmp.proto.rfc1902 import Integer, Integer32, OctetString
from pysnmp.proto.rfc1905 import endOfMibView
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

BASE = (9, 9, 9, 1)
ROW = BASE + (1,)
COL_A = ROW + (2,)
COL_B = ROW + (3,)
COL_C = ROW + (4,)
PAST_COLUMN = ROW + (5, 0)
UNKNOWN_OID = (8, 8, 8, 8)

I_AB = (1, 97, 98)
I_AC = (2, 99)
I_X = (3, 120)
BAD_INDEX = (3,)


@pytest.fixture
def engine():
    engine = SnmpEngine()
    builder = engine.getMibBuilder()
    MibTable, MibTableRow, MibTableColumn, schema_integer = builder.importSymbols(
        "SNMPv2-SMI", "MibTable", "MibTableRow", "MibTableColumn", "Integer32"
    )
    schema_octets = builder.importSymbols("ASN1", "OctetString")[0]

    table = MibTable(BASE)
    row = MibTableRow(ROW).setIndexNames(
        (0, "TEST-TABLE-MIB", "testIndex"),
        (1, "TEST-TABLE-MIB", "testImpliedName"),
    )
    index_integer = MibTableColumn(
        (9, 9, 9, 0, 1), schema_integer()
    ).setMaxAccess("notaccessible")
    index_octets = MibTableColumn(
        (9, 9, 9, 0, 2), schema_octets()
    ).setMaxAccess("notaccessible")
    column_a = MibTableColumn(COL_A, OctetString()).setMaxAccess("readonly")
    column_b = MibTableColumn(COL_B, Integer32()).setMaxAccess("readonly")
    column_c = MibTableColumn(COL_C, OctetString()).setMaxAccess("readonly")
    not_accessible = MibTableColumn(
        ROW + (1,), Integer32()
    ).setMaxAccess("notaccessible")

    builder.exportSymbols(
        "TEST-TABLE-MIB",
        testTable=table,
        testEntry=row,
        testIndex=index_integer,
        testImpliedName=index_octets,
        testColumnA=column_a,
        testColumnB=column_b,
        testColumnC=column_c,
        testNotAccessible=not_accessible,
    )
    engine._testColumns = (COL_A, COL_B, COL_C)
    return engine


class ScriptedBulkAgent:
    """Returns a whole GETBULK response script, without a global OID cursor."""

    def __init__(self, scripts):
        self.scripts = scripts
        self.calls = []

    async def bulk_cmd(
        self,
        _engine,
        _auth,
        _target,
        _context,
        _non_repeaters,
        _max_repetitions,
        *request_var_binds,
        **_options,
    ):
        call = len(self.calls)
        self.calls.append([tuple(name) for name, _ in request_var_binds])
        if call >= len(self.scripts):
            raise AssertionError("bulk_table_cmd made an unexpected GETBULK request")

        response = self.scripts[call]
        if isinstance(response, tuple) and response and isinstance(response[0], str):
            return None, response[1], response[2], []

        table = []
        for scripted_row in response:
            response_row = []
            for request_name, _ in request_var_binds:
                request_name = tuple(request_name)
                def matches(column_name):
                    if len(request_name) >= len(column_name):
                        return request_name[: len(column_name)] == column_name
                    return column_name[: len(request_name)] == request_name

                slot = next(
                    (
                        index
                        for index, column_name in enumerate((COL_A, COL_B, COL_C))
                        if matches(column_name)
                    ),
                    None,
                )
                if slot is None or slot >= len(scripted_row):
                    response_row.append((request_name, endOfMibView))
                    continue

                cells = scripted_row[slot]
                if cells is None:
                    continue
                if cells == "stale":
                    response_row.append(
                        (tuple(request_name) + (9, 0), OctetString("stale"))
                    )
                    continue
                cell = next(
                    (item for item in cells if tuple(item[0]) >= request_name),
                    None,
                )
                if cell is None:
                    response_row.append((request_name, endOfMibView))
                else:
                    response_row.append(cell)
            table.append(response_row)
        return None, 0, 0, table


async def collect(monkeypatch, engine, scripts, *, maxRepetitions=3, **options):
    agent = ScriptedBulkAgent(scripts)
    monkeypatch.setattr(async_cmdgen, "bulk_cmd", agent.bulk_cmd)
    return (
        [
            response
            async for response in bulk_table_cmd(
                engine,
                None,
                None,
                None,
                0,
                maxRepetitions,
                ObjectType(ObjectIdentity("TEST-TABLE-MIB", "testTable")),
                **options,
            )
        ],
        agent,
    )


def cell_oid(row, column_position):
    return tuple(row.varBinds[column_position][0])


def cell_value(row, column_position):
    return row.varBinds[column_position][1]


class TestBulkTableAssembly:
    async def test_aligns_columns_and_keeps_independent_missing_cells(
        self, monkeypatch, engine
    ):
        scripts = [
            [
                [
                    [(COL_A + I_AB, OctetString("a-ab"))],
                    [(COL_B + I_AB, Integer(10))],
                    [(COL_C + I_AB, OctetString("c-ab"))],
                ]
            ],
            [
                [
                    [(COL_A + I_AC, OctetString("a-ac"))],
                    [(COL_B + I_AC, Integer(20))],
                    [(PAST_COLUMN, Integer(99))],
                ]
            ],
            [
                [
                    [(COL_A + I_X, OctetString("a-x"))],
                    [(COL_B + I_AC, Integer(20))],
                ]
            ],
            [[[], [(COL_B + I_X, Integer(30))]]],
            [[[], []]],
        ]

        rows, agent = await collect(
            monkeypatch, engine, scripts, maxRepetitions=1
        )
        assert len(rows) == 3
        assert all(isinstance(row, SnmpTableResponse) for row in rows)
        assert [
            (int(row.indices[0]), bytes(row.indices[1])) for row in rows
        ] == [(1, b"ab"), (2, b"c"), (3, b"x")]
        assert rows[0].indices[1].asOctets() == b"ab"
        assert cell_oid(rows[0], 0) == COL_A + I_AB
        assert cell_oid(rows[0], 1) == COL_B + I_AB
        assert cell_oid(rows[0], 2) == COL_C + I_AB
        assert cell_value(rows[0], 0).asOctets() == b"a-ab"
        assert int(cell_value(rows[0], 1)) == 10
        assert cell_value(rows[0], 2).asOctets() == b"c-ab"

        assert cell_oid(rows[1], 0) == COL_A + I_AC
        assert cell_oid(rows[1], 1) == COL_B + I_AC
        assert rows[1].varBinds[2] is MISSING_CELL

        assert cell_oid(rows[2], 0) == COL_A + I_X
        assert cell_oid(rows[2], 1) == COL_B + I_X
        assert rows[2].varBinds[2] is MISSING_CELL

        assert [len(request) for request in agent.calls] == [3, 3, 2, 2, 1]
        assert agent.calls[2][0] == COL_A + I_AC
        assert agent.calls[2][1] == COL_B + I_AC

    async def test_a_protocol_error_is_yielded_with_its_error_index(
        self, monkeypatch, engine
    ):
        scripts = [
            [
                [
                    [(COL_A + I_AB, OctetString("a-ab"))],
                    [(COL_B + I_AB, Integer(10))],
                    [(COL_C + I_AB, OctetString("c-ab"))],
                ]
            ],
            ("error", "genErr", 2),
        ]

        rows, _ = await collect(monkeypatch, engine, scripts)

        assert len(rows) == 2
        assert rows[0][0] is None
        assert rows[1].errorStatus == "genErr"
        assert rows[1].errorIndex == 2

    async def test_a_bad_index_fails_explicitly(self, monkeypatch, engine):
        scripts = [
            [
                [
                    [(COL_A + I_AB, OctetString("a-ab"))],
                    [(COL_B + BAD_INDEX, Integer(99))],
                    [(COL_C + I_AB, OctetString("c-ab"))],
                ]
            ]
        ]

        rows, _ = await collect(monkeypatch, engine, scripts)

        assert len(rows) == 1
        assert isinstance(rows[0].errorIndication, errind.TableIndexError)
        assert "Could not decode table index suffix" in str(rows[0].errorIndication)

    async def test_exceeding_pending_rows_fails_instead_of_waiting_forever(
        self, monkeypatch, engine
    ):
        scripts = [
            [
                [
                    [
                        (COL_A + I_AB, OctetString("a-ab")),
                        (COL_A + I_AC, OctetString("a-ac")),
                        (COL_A + I_X, OctetString("a-x")),
                    ],
                    "stale",
                    "stale",
                ]
            ]
        ]

        rows, _ = await collect(
            monkeypatch,
            engine,
            scripts,
            maxRepetitions=2,
            maxPendingRows=1,
        )

        assert len(rows) == 1
        assert isinstance(rows[0].errorIndication, errind.TableRowLimitError)
        assert "waiting for missing columns" in str(rows[0].errorIndication)

    async def test_unknown_response_binding_ends_only_that_column(
        self, monkeypatch, engine
    ):
        scripts = [
            [
                [
                    [(COL_A + I_AB, OctetString("a-ab"))],
                    [(COL_B + I_AB, Integer(10))],
                    [(UNKNOWN_OID, Integer(1))],
                ]
            ],
            [
                [
                    [(COL_A + I_AC, OctetString("a-ac"))],
                    [(COL_B + I_AC, Integer(20))],
                ],
                [
                    [],
                    [],
                ],
            ],
        ]

        rows, agent = await collect(monkeypatch, engine, scripts)

        assert len(rows) == 2
        assert rows[0].varBinds[2] is MISSING_CELL
        assert rows[1].varBinds[2] is MISSING_CELL
        assert [len(request) for request in agent.calls] == [3, 2]

    async def test_a_repeated_oid_fails_as_non_increasing(self, monkeypatch, engine):
        repeated = [(COL_B + I_AB, Integer(10))]
        scripts = [
            [
                [
                    [(COL_A + I_AB, OctetString("a-ab"))],
                    repeated,
                    [(COL_C + I_AB, OctetString("c-ab"))],
                ]
            ],
            [
                [
                    [(COL_A + I_AC, OctetString("a-ac"))],
                    repeated,
                    [(PAST_COLUMN, Integer(99))],
                ]
            ],
            [
                [
                    [(COL_A + I_X, OctetString("a-x"))],
                    repeated,
                ]
            ],
        ]

        rows, _ = await collect(
            monkeypatch, engine, scripts, maxRepetitions=1
        )

        assert rows[-1].errorIndication is not None
        assert isinstance(rows[-1].errorIndication, errind.OidNotIncreasing)
        assert rows[-1].errorIndex == 2

    async def test_non_repeaters_must_be_zero(self, engine):
        with pytest.raises(ValueError, match="nonRepeaters"):
            await anext(
                bulk_table_cmd(
                    engine,
                    None,
                    None,
                    None,
                    1,
                    3,
                    ObjectType(ObjectIdentity("TEST-TABLE-MIB", "testTable")),
                )
            )
