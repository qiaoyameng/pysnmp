"""Reading a received notification back against its NOTIFICATION-TYPE.

A trap arrives as a flat varbind list. ``structureNotification`` matches it
against the OBJECTS clause of the NOTIFICATION-TYPE the ``snmpTrapOID.0``
value names, so the application works with named fields instead of guessing
OIDs. What these tests pin down is the honesty of that reading: a scalar and
a table column are matched differently, two rows of one column stay two
candidates rather than one overwriting the other, a missing object is
reported missing, extras survive, and an unknown notification still comes
back whole.
"""

import pytest

from pysnmp.entity.engine import SnmpEngine
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.entity.rfc3413.notification import (
    NotificationField,
    structureNotification,
)
from pysnmp.proto.api import v2c
from pysnmp.proto.rfc1905 import SNMPv2TrapPDU
from pysnmp.proto.rfc1902 import OctetString
from pysnmp.smi.builder import MibBuilder
from pysnmp.smi.view import MibViewController

TEST_OID = (1, 3, 6, 1, 4, 1, 99999)
TEST_EVENT = TEST_OID + (1, 1)
TEST_SCALAR_0 = TEST_OID + (2, 1, 0)
TEST_COLUMN = TEST_OID + (2, 2, 1, 2)

SYS_UP_TIME_0 = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SNMP_TRAP_OID_0 = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)
SYS_DESCR_0 = (1, 3, 6, 1, 2, 1, 1, 1, 0)


def _exportTestMib(builder):
    """Give a MIB builder a TEST-MIB notification declaring a scalar and a column."""
    (
        MibIdentifier,
        MibScalar,
        MibTable,
        MibTableRow,
        MibTableColumn,
        NotificationType,
        Integer32,
    ) = builder.importSymbols(
        "SNMPv2-SMI",
        "MibIdentifier",
        "MibScalar",
        "MibTable",
        "MibTableRow",
        "MibTableColumn",
        "NotificationType",
        "Integer32",
    )

    testNotifications = MibIdentifier(TEST_OID + (1,))
    testObjects = MibIdentifier(TEST_OID + (2,))
    testScalar = MibScalar(TEST_OID + (2, 1), OctetString()).setMaxAccess("readonly")
    testTable = MibTable(TEST_OID + (2, 2))
    testEntry = MibTableRow(TEST_OID + (2, 2, 1)).setIndexNames(
        (0, "TEST-MIB", "testIndex")
    )
    testIndex = MibTableColumn(TEST_OID + (2, 2, 1, 1), Integer32()).setMaxAccess(
        "notaccessible"
    )
    testValue = MibTableColumn(TEST_OID + (2, 2, 1, 2), OctetString()).setMaxAccess(
        "readonly"
    )
    testEvent = NotificationType(TEST_EVENT).setObjects(
        ("TEST-MIB", "testScalar"), ("TEST-MIB", "testValue")
    )

    builder.loadModules("SNMPv2-MIB")
    builder.exportSymbols(
        "TEST-MIB",
        testNotifications=testNotifications,
        testObjects=testObjects,
        testScalar=testScalar,
        testTable=testTable,
        testEntry=testEntry,
        testIndex=testIndex,
        testValue=testValue,
        testEvent=testEvent,
    )


@pytest.fixture(scope="module")
def mibView():
    """A MIB view carrying TEST-MIB."""
    builder = MibBuilder()
    _exportTestMib(builder)
    return MibViewController(builder)


def _trap(*payload, trapOid=TEST_EVENT):
    """A well-formed v2 notification: uptime, trap OID, then the payload."""
    return [
        (SYS_UP_TIME_0, v2c.TimeTicks(12345)),
        (SNMP_TRAP_OID_0, v2c.ObjectIdentifier(trapOid)),
        *payload,
    ]


def _scalar(value):
    return (TEST_SCALAR_0, v2c.OctetString(value))


def _cell(index, value):
    return (TEST_COLUMN + (index,), v2c.OctetString(value))


class TestProtocolFields:
    def test_protocol_fields_are_lifted_out(self, mibView):
        notification = structureNotification(_trap(), mibView)

        assert notification.sysUpTime[0] == SYS_UP_TIME_0
        assert notification.sysUpTime[1] == v2c.TimeTicks(12345)
        assert notification.snmpTrapOID[0] == SNMP_TRAP_OID_0
        assert tuple(notification.snmpTrapOID[1]) == TEST_EVENT

    def test_notification_type_resolves(self, mibView):
        notification = structureNotification(_trap(), mibView)

        assert notification.known
        assert notification.notificationType == ("TEST-MIB", "testEvent")

    def test_raw_varbinds_are_preserved(self, mibView):
        varBinds = _trap(_scalar("up"))

        notification = structureNotification(varBinds, mibView)

        assert list(notification.varBinds) == varBinds


class TestDeclaredObjects:
    def test_scalar_and_column_resolve(self, mibView):
        notification = structureNotification(
            _trap(_scalar("up"), _cell(7, "seven")), mibView
        )

        scalar = notification.getField("testScalar")
        assert scalar.status == NotificationField.RESOLVED
        assert scalar.kind == NotificationField.KIND_SCALAR
        assert scalar.value == v2c.OctetString("up")

        column = notification.getField("testValue")
        assert column.status == NotificationField.RESOLVED
        assert column.kind == NotificationField.KIND_COLUMN
        assert column.value == v2c.OctetString("seven")

    def test_column_instance_index_is_decoded(self, mibView):
        notification = structureNotification(_trap(_cell(7, "seven")), mibView)

        binding = notification.getField("testValue").binding
        assert binding.row == ("TEST-MIB", "testEntry")
        assert len(binding.instance) == 1
        assert int(binding.instance[0]) == 7

    def test_two_rows_of_one_column_are_ambiguous(self, mibView):
        notification = structureNotification(
            _trap(_cell(3, "three"), _cell(5, "five")), mibView
        )

        column = notification.getField("testValue")
        assert column.status == NotificationField.AMBIGUOUS
        assert column in notification.ambiguous
        assert column.value is None
        # Both rows survive, each with its own value and decoded index.
        byIndex = {int(b.instance[0]): b.value for b in column.bindings}
        assert byIndex == {
            3: v2c.OctetString("three"),
            5: v2c.OctetString("five"),
        }

    def test_duplicate_scalar_oid_is_ambiguous_not_overwritten(self, mibView):
        notification = structureNotification(
            _trap(_scalar("first"), _scalar("second")), mibView
        )

        scalar = notification.getField("testScalar")
        assert scalar.status == NotificationField.AMBIGUOUS
        assert scalar.value is None
        assert [b.value for b in scalar.bindings] == [
            v2c.OctetString("first"),
            v2c.OctetString("second"),
        ]

    def test_missing_declared_object_is_reported(self, mibView):
        notification = structureNotification(_trap(_cell(1, "one")), mibView)

        scalar = notification.getField("testScalar")
        assert scalar.status == NotificationField.MISSING
        assert scalar in notification.missing
        assert scalar.value is None
        assert notification.getField("testValue").status == NotificationField.RESOLVED


class TestExtras:
    def test_undeclared_varbinds_are_kept(self, mibView):
        extra = ((1, 3, 6, 1, 4, 1, 55555, 9, 0), v2c.Integer(1))

        notification = structureNotification(_trap(_scalar("up"), extra), mibView)

        assert len(notification.extras) == 1
        assert notification.extras[0].oid == extra[0]
        assert notification.extras[0].value == extra[1]
        # Nothing claims it; the location is the nearest known symbol.
        assert notification.extras[0].module == "SNMPv2-SMI"
        assert notification.extras[0].symbol == "enterprises"
        assert notification.extras[0].suffix == (55555, 9, 0)

    def test_known_extra_oid_is_located(self, mibView):
        extra = (SYS_DESCR_0, v2c.OctetString("a router"))

        notification = structureNotification(_trap(extra), mibView)

        assert notification.extras[0].module == "SNMPv2-MIB"
        assert notification.extras[0].symbol == "sysDescr"
        assert notification.extras[0].suffix == (0,)


class TestUnknownNotification:
    def test_unknown_trap_oid_keeps_raw_structure(self, mibView):
        varBinds = _trap(_scalar("up"), trapOid=(1, 3, 6, 1, 4, 1, 77777, 1, 1))

        notification = structureNotification(varBinds, mibView)

        assert not notification.known
        assert notification.notificationType is None
        assert notification.fields == ()
        # Protocol fields still lift out, payload lands in extras untouched.
        assert notification.sysUpTime[1] == v2c.TimeTicks(12345)
        assert [e.oid for e in notification.extras] == [TEST_SCALAR_0]
        assert list(notification.varBinds) == varBinds

    def test_oid_that_is_not_a_notification_is_unknown(self, mibView):
        # sysDescr resolves in the MIB but is no NOTIFICATION-TYPE.
        varBinds = _trap(trapOid=(1, 3, 6, 1, 2, 1, 1, 1))

        notification = structureNotification(varBinds, mibView)

        assert not notification.known
        assert notification.fields == ()

    def test_missing_trap_oid_is_unknown(self, mibView):
        varBinds = [(SYS_UP_TIME_0, v2c.TimeTicks(1)), _scalar("up")]

        notification = structureNotification(varBinds, mibView)

        assert not notification.known
        assert notification.snmpTrapOID is None
        assert [e.oid for e in notification.extras] == [TEST_SCALAR_0]


class TestEndToEnd:
    """A trap through NotificationReceiver, structured inside the callback."""

    def test_trap_through_receiver_is_structured(self):
        engine = SnmpEngine()
        _exportTestMib(engine.getMibBuilder())

        received = []

        def cbFun(
            snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx
        ):
            received.append(structureNotification(varBinds, snmpEngine))

        receiver = ntfrcv.NotificationReceiver(engine, cbFun)

        pdu = SNMPv2TrapPDU()
        v2c.apiPDU.setDefaults(pdu)
        v2c.apiPDU.setVarBinds(
            pdu,
            [
                (SYS_UP_TIME_0, v2c.TimeTicks(12345)),
                (SNMP_TRAP_OID_0, v2c.ObjectIdentifier(TEST_EVENT)),
                (TEST_SCALAR_0, v2c.OctetString("up")),
                (TEST_COLUMN + (3,), v2c.OctetString("three")),
                (TEST_COLUMN + (5,), v2c.OctetString("five")),
                (SYS_DESCR_0, v2c.OctetString("a router")),
            ],
        )

        receiver.processPdu(
            engine,
            1,  # messageProcessingModel: v2c
            2,  # securityModel
            "security-name",
            "noAuthNoPriv",
            b"",  # contextEngineId
            b"",  # contextName
            1,  # pduVersion
            pdu,
            65535,  # maxSizeResponseScopedPDU
            None,  # stateReference
        )
        receiver.close(engine)

        assert len(received) == 1
        notification = received[0]
        assert notification.known
        assert notification.notificationType == ("TEST-MIB", "testEvent")
        assert notification.sysUpTime[1] == v2c.TimeTicks(12345)
        assert notification.getField("testScalar").value == v2c.OctetString("up")
        # Two rows of one column in a single notification stay two candidates.
        column = notification.getField("testValue")
        assert column.status == NotificationField.AMBIGUOUS
        byIndex = {int(b.instance[0]): b.value for b in column.bindings}
        assert byIndex == {3: v2c.OctetString("three"), 5: v2c.OctetString("five")}
        # The undeclared sysDescr.0 survives as a located extra.
        assert [e.symbol for e in notification.extras] == ["sysDescr"]
