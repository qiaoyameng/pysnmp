"""Assembling MIB table rows out of a GETBULK column walk.

``bulk_walk_cmd`` hands back the rows of each response as they come -- one
binding per column, with no promise that the bindings in a row name the
same table entry. ``table_walk_cmd`` re-aligns those bindings on the
table's INDEX and yields whole entries. The edges pinned here are the ones
a monitoring collector trips over: columns that drift apart or end early,
cells that simply do not exist, indexes the MIB cannot explain, and a
column that never delivers.
"""

import pytest

from pysnmp.hlapi.asyncio import (
    MISSING_CELL,
    SnmpEngine,
    table_walk_cmd,
)
from pysnmp.hlapi.asyncio import cmdgen as async_cmdgen
from pysnmp.hlapi.asyncio._table import TableRowAssembler, TooManyPendingRows
from pysnmp.proto.rfc1902 import Integer, ObjectIdentifier, OctetString
from pysnmp.proto.rfc1905 import endOfMibView, noSuchInstance
from pysnmp.smi.error import SmiError
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

# ifEntry: one Integer32 index. ifDescr is column 2, ifType column 3.
IFENTRY = (1, 3, 6, 1, 2, 1, 2, 2, 1)
IFDESCR = IFENTRY + (2,)
IFTYPE = IFENTRY + (3,)

# usmUserEntry: two length-prefixed OCTET STRING indexes.
USM_SEC_NAME = (1, 3, 6, 1, 6, 3, 15, 1, 2, 2, 1, 3)

# snmpTargetAddrEntry: one IMPLIED OCTET STRING index.
TARGET_TDOMAIN = (1, 3, 6, 1, 6, 3, 12, 1, 2, 1, 2)


def string_suffix(text):
    """The instance suffix of a variable-length string index."""
    return (len(text),) + tuple(text.encode())


class ScriptedAgent:
    """Answers GETBULK from a script, one response row per call.

    Each script entry maps a column OID to the binding that column answers
    with in that call, so the script decides each column's pace
    independently. A column absent from the entry answers ``endOfMibView``
    -- what a column that ran out of instances looks like on the wire.
    Once the script runs out, every column answers ``endOfMibView``.
    """

    def __init__(self, script=(), errorIndication=None, errorAt=None):
        self.script = list(script)
        self.errorIndication = errorIndication
        self.errorAt = errorAt
        self.calls = 0
        self.columns = None

    async def bulk_cmd(
        self,
        _engine,
        _auth,
        _target,
        _context,
        _nonRepeaters,
        _maxRepetitions,
        *varBinds,
        **_options,
    ):
        self.calls += 1
        if self.columns is None:
            # The first request names the walked columns themselves; later
            # ones name instances under them, so positions are remembered.
            self.columns = [tuple(name) for name, _ in varBinds]
        if self.errorAt is not None and self.calls >= self.errorAt:
            return self.errorIndication, 0, 0, []
        step = self.script.pop(0) if self.script else {}
        row = []
        for position, (name, _value) in enumerate(varBinds):
            binding = step.get(self.columns[position])
            row.append(binding if binding is not None else (name, endOfMibView))
        return None, 0, 0, [row]


async def collect(agent, monkeypatch, table, **options):
    """Run ``table_walk_cmd`` against the scripted agent, gathering yields."""
    monkeypatch.setattr(async_cmdgen, "bulk_cmd", agent.bulk_cmd)
    return [
        item
        async for item in table_walk_cmd(
            SnmpEngine(), None, None, None, 0, 10, table, **options
        )
    ]


def ifTable():
    return ObjectType(ObjectIdentity("IF-MIB", "ifTable"))


class TestRowAssembly:
    """Columns drifting apart, and the holes that leaves in rows."""

    async def test_rows_align_columns_that_progress_at_different_paces(
        self, monkeypatch
    ):
        agent = ScriptedAgent(
            [
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                # ifType has no instance 2: it jumps straight to 3.
                {IFDESCR: (IFDESCR + (2,), OctetString("eth1")),
                 IFTYPE: (IFTYPE + (3,), Integer(24))},
                {IFDESCR: (IFDESCR + (3,), OctetString("eth2")),
                 IFTYPE: (IFTYPE + (3,), endOfMibView)},
            ]
        )

        responses = await collect(agent, monkeypatch, ifTable())

        assert [r.errorIndication for r in responses] == [None] * 3
        rows = [r.varBinds for r in responses]

        assert [tuple(int(i) for i in row.indices) for row in rows] == [
            (1,), (2,), (3,)
        ]
        # ifDescr is the 2nd column, ifType the 3rd.
        assert [row.cells[1] for row in rows] == [
            OctetString("eth0"), OctetString("eth1"), OctetString("eth2")
        ]
        assert rows[0].cells[2] == Integer(6)
        assert rows[2].cells[2] == Integer(24)

    async def test_a_missing_cell_is_marked_never_backfilled(self, monkeypatch):
        agent = ScriptedAgent(
            [
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                {IFDESCR: (IFDESCR + (2,), OctetString("eth1")),
                 IFTYPE: (IFTYPE + (3,), Integer(24))},
            ]
        )

        responses = await collect(agent, monkeypatch, ifTable())
        rows = [r.varBinds for r in responses]

        # The hole at index 2 is the marker itself -- not the value of the
        # previous row, and not the adjacent column's.
        hole = rows[1].cells[2]
        assert hole is MISSING_CELL
        assert hole != rows[0].cells[2]
        assert hole != rows[1].cells[1]
        # ifIndex is not-accessible: no instance of it is ever returned, so
        # every row carries the marker in the first position.
        assert all(row.cells[0] is MISSING_CELL for row in rows)
        # ... and so does every column the script never answered for.
        assert all(
            cell is MISSING_CELL for row in rows for cell in row.cells[3:]
        )

    async def test_a_column_ending_early_does_not_hold_the_others_back(
        self, monkeypatch
    ):
        agent = ScriptedAgent(
            [
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), endOfMibView)},
                {IFDESCR: (IFDESCR + (2,), OctetString("eth1"))},
                {IFDESCR: (IFDESCR + (3,), OctetString("eth2"))},
            ]
        )

        responses = await collect(agent, monkeypatch, ifTable())
        rows = [r.varBinds for r in responses]

        assert [tuple(int(i) for i in row.indices) for row in rows] == [
            (1,), (2,), (3,)
        ]
        assert all(row.cells[2] is MISSING_CELL for row in rows)


class TestIndexDecoding:
    """The INDEX clause drives how instance suffixes come apart."""

    async def test_composite_variable_length_string_index(self, monkeypatch):
        # SnmpEngineID is SIZE(5..32), so the engine id is five octets.
        suffix = string_suffix("eng01") + string_suffix("bob")
        agent = ScriptedAgent(
            [{USM_SEC_NAME: (USM_SEC_NAME + suffix, OctetString("bob"))}]
        )

        responses = await collect(
            agent,
            monkeypatch,
            ObjectType(ObjectIdentity("SNMP-USER-BASED-SM-MIB", "usmUserTable")),
        )

        (row,) = [r.varBinds for r in responses]
        engine_id, user_name = row.indices
        assert engine_id.asOctets() == b"eng01"
        assert user_name.asOctets() == b"bob"
        # usmUserSecurityName is the 3rd column of usmUserEntry.
        assert row.cells[2] == OctetString("bob")
        assert all(
            cell is MISSING_CELL
            for position, cell in enumerate(row.cells)
            if position != 2
        )

    async def test_implied_index_carries_no_length_prefix(self, monkeypatch):
        agent = ScriptedAgent(
            [
                {
                    TARGET_TDOMAIN: (
                        TARGET_TDOMAIN + tuple(b"web"),
                        ObjectIdentifier((1, 3, 6, 1, 4, 1)),
                    )
                }
            ]
        )

        responses = await collect(
            agent,
            monkeypatch,
            ObjectType(ObjectIdentity("SNMP-TARGET-MIB", "snmpTargetAddrTable")),
        )

        (row,) = [r.varBinds for r in responses]
        (name,) = row.indices
        assert name.asOctets() == b"web"
        assert row.cells[1] == ObjectIdentifier((1, 3, 6, 1, 4, 1))


class TestMisbehavingAgents:
    """Unknown columns, repeated OIDs, indexes that do not parse."""

    async def test_a_binding_under_no_known_column_is_ignored(self, monkeypatch):
        unknownColumn = IFENTRY + (99,)
        agent = ScriptedAgent(
            [
                # lexicographicMode lets bindings past the subtree boundary
                # through to the assembler, which must not claim them.
                {IFDESCR: (unknownColumn + (1,), OctetString("junk"))},
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
            ]
        )

        responses = await collect(
            agent, monkeypatch, ifTable(), lexicographicMode=True
        )

        (row,) = [r.varBinds for r in responses]
        assert tuple(int(i) for i in row.indices) == (1,)
        assert row.cells[1] == OctetString("eth0")

    async def test_a_repeated_oid_is_not_a_second_row(self, monkeypatch):
        agent = ScriptedAgent(
            [
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                # The exact same answer again, as a confused agent sends.
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                {IFDESCR: (IFDESCR + (2,), OctetString("eth1")),
                 IFTYPE: (IFTYPE + (2,), Integer(24))},
            ]
        )

        responses = await collect(agent, monkeypatch, ifTable())
        rows = [r.varBinds for r in responses]

        assert [tuple(int(i) for i in row.indices) for row in rows] == [
            (1,), (2,)
        ]

    async def test_an_index_the_mib_cannot_decode_is_skipped(self, monkeypatch):
        agent = ScriptedAgent(
            [
                # ifEntry has one Integer32 index: a three-sub-OID suffix
                # belongs to no row, however real the binding looks.
                {IFDESCR: (IFDESCR + (1, 2, 3), OctetString("weird")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                {IFDESCR: (IFDESCR + (2,), OctetString("eth1")),
                 IFTYPE: (IFTYPE + (2,), Integer(24))},
            ]
        )

        responses = await collect(agent, monkeypatch, ifTable())
        rows = [r.varBinds for r in responses]

        assert [tuple(int(i) for i in row.indices) for row in rows] == [
            (1,), (2,)
        ]
        assert rows[0].cells[1] is MISSING_CELL
        assert rows[0].cells[2] == Integer(6)
        assert rows[1].cells[1] == OctetString("eth1")

    async def test_a_cell_answered_no_such_instance_stays_missing(
        self, monkeypatch
    ):
        agent = ScriptedAgent(
            [
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), noSuchInstance)},
            ]
        )

        responses = await collect(agent, monkeypatch, ifTable())

        (row,) = [r.varBinds for r in responses]
        assert row.cells[1] == OctetString("eth0")
        assert row.cells[2] is MISSING_CELL


class TestPendingRowLimit:
    """A column that never delivers must fail the walk, not stall it."""

    async def test_too_many_pending_rows_fails_explicitly(self, monkeypatch):
        agent = ScriptedAgent(
            [
                {IFDESCR: (IFDESCR + (1,), OctetString("eth0")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                # ifType keeps replaying index 1 while ifDescr walks on:
                # every later row pends on a cell that is never coming.
                {IFDESCR: (IFDESCR + (2,), OctetString("eth1")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                {IFDESCR: (IFDESCR + (3,), OctetString("eth2")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
                {IFDESCR: (IFDESCR + (4,), OctetString("eth3")),
                 IFTYPE: (IFTYPE + (1,), Integer(6))},
            ]
        )

        responses = await collect(agent, monkeypatch, ifTable(), maxPendingRows=2)

        assert len(responses) == 2
        assert responses[0].errorIndication is None
        assert tuple(int(i) for i in responses[0].varBinds.indices) == (1,)
        assert isinstance(responses[1].errorIndication, TooManyPendingRows)

    def test_the_limit_must_be_positive(self):
        engine = SnmpEngine()
        engine.getMibBuilder().loadModules("IF-MIB")
        (row,) = engine.getMibBuilder().importSymbols("IF-MIB", "ifEntry")

        with pytest.raises(SmiError):
            TableRowAssembler(row, maxPendingRows=0)


class TestFailures:
    """What the caller sees when the walk itself cannot run."""

    async def test_an_agent_error_is_yielded_not_raised(self, monkeypatch):
        agent = ScriptedAgent(errorIndication="timeout", errorAt=1)

        responses = await collect(agent, monkeypatch, ifTable())

        assert len(responses) == 1
        assert responses[0].errorIndication == "timeout"

    async def test_a_non_table_is_rejected(self, monkeypatch):
        monkeypatch.setattr(async_cmdgen, "bulk_cmd", ScriptedAgent().bulk_cmd)

        with pytest.raises(SmiError):
            async for _response in table_walk_cmd(
                SnmpEngine(),
                None,
                None,
                None,
                0,
                10,
                ObjectType(ObjectIdentity("SNMPv2-MIB", "system")),
            ):
                pass

    async def test_more_than_one_table_is_rejected(self, monkeypatch):
        monkeypatch.setattr(async_cmdgen, "bulk_cmd", ScriptedAgent().bulk_cmd)

        with pytest.raises(SmiError):
            async for _response in table_walk_cmd(
                SnmpEngine(), None, None, None, 0, 10, ifTable(), ifTable()
            ):
                pass
