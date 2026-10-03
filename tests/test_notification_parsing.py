"""Structured parsing of received notifications against their NOTIFICATION-TYPE.

Covers the cases an application actually has to judge: protocol fields kept
apart from payload, scalar ``.0`` instances versus table-column instances with
decoded indexes, columns arriving from two rows in one trap, repeated OIDs,
declared objects missing, undeclared/unknown OIDs kept verbatim, and a trap no
loaded MIB defines.
"""

from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi.notification import (
    ParsedNotification,
    parse_notification,
)
from pysnmp.proto import rfc1902


def oid(dotted):
    return tuple(int(x) for x in dotted.split("."))


# IF-MIB::linkDown OID and its columns
LINK_DOWN = "1.3.6.1.6.3.1.1.5.3"
IF_INDEX = "1.3.6.1.2.1.2.2.1.1"
IF_ADMIN = "1.3.6.1.2.1.2.2.1.7"
IF_OPER = "1.3.6.1.2.1.2.2.1.8"

SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
TRAP_OID = "1.3.6.1.6.3.1.1.4.1.0"
TRAP_ENTERPRISE = "1.3.6.1.6.3.1.1.4.3.0"


def trap_header(trap_oid=LINK_DOWN, uptime=12345, enterprise=None):
    binds = [
        (oid(SYS_UPTIME), rfc1902.TimeTicks(uptime)),
        (oid(TRAP_OID), rfc1902.ObjectIdentifier(oid(trap_oid))),
    ]
    if enterprise is not None:
        binds.append(
            (oid(TRAP_ENTERPRISE), rfc1902.ObjectIdentifier(oid(enterprise)))
        )
    return binds


class TestProtocolFields:
    def test_protocol_fields_are_kept_separate(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
            ],
            load_mibs=("IF-MIB",),
        )

        assert set(result.protocol_fields) == {"sysUpTime", "snmpTrapOID"}
        assert int(result.protocol_fields["sysUpTime"][1]) == 12345
        assert result.protocol_fields["snmpTrapOID"][1] == oid(LINK_DOWN)
        assert result.trap_oid == oid(LINK_DOWN)
        assert result.trap_name == "IF-MIB::linkDown"
        assert result.known_type
        # neither protocol OID leaked into payload structures
        assert not result.objects
        assert result.issues == []

    def test_v1_enterprise_field_is_retained(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header(enterprise="1.3.6.1.4.1.99999.1")
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
            ],
            load_mibs=("IF-MIB",),
        )
        assert "snmpTrapEnterprise" in result.protocol_fields
        assert result.protocol_fields["snmpTrapEnterprise"][1] == oid(
            "1.3.6.1.4.1.99999.1"
        )


class TestScalarAndColumnInstances:
    def test_scalar_dot_zero_binds_as_scalar(self):
        engine = SnmpEngine()
        # coldStart has no OBJECTS, so use a synthetic mix through linkDown
        # with a scalar carried as additional data.
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
                (oid("1.3.6.1.2.1.1.1.0"), rfc1902.OctetString(b"host")),
            ],
            load_mibs=("IF-MIB",),
        )
        extra = {b.name: b for b in result.additional}
        assert extra["SNMPv2-MIB::sysDescr"].scalar
        assert extra["SNMPv2-MIB::sysDescr"].instance_suffix == (0,)
        assert extra["SNMPv2-MIB::sysDescr"].native_value == b"host"

    def test_column_instance_index_is_decoded(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
            ],
            load_mibs=("IF-MIB",),
        )
        (row,) = result.rows
        assert row.raw_index == (7,)
        assert [int(x) for x in row.index] == [7]
        assert row.index_names == ("IF-MIB::ifIndex",)
        assert set(row.objects) == {
            "IF-MIB::ifIndex",
            "IF-MIB::ifAdminStatus",
            "IF-MIB::ifOperStatus",
        }
        assert all(obj.reliable for obj in row.objects.values())
        assert result.values() == {
            "IF-MIB::ifIndex": 7,
            "IF-MIB::ifAdminStatus": 1,
            "IF-MIB::ifOperStatus": 2,
        }

    def test_enum_named_value_renders_pretty_but_native_is_int(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
            ],
            load_mibs=("IF-MIB",),
        )
        oper = result.rows[0].objects["IF-MIB::ifOperStatus"].binding
        assert oper.native_value == 2
        assert oper.pretty_value == "down"


class TestAmbiguity:
    def test_columns_from_two_rows_stay_separate(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                # row 7 complete
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
                # row 9 missing ifOperStatus
                (oid(f"{IF_INDEX}.9"), rfc1902.Integer32(9)),
                (oid(f"{IF_ADMIN}.9"), rfc1902.Integer32(1)),
            ],
            load_mibs=("IF-MIB",),
        )
        rows = {row.raw_index: row for row in result.rows}
        assert set(rows) == {(7,), (9,)}
        assert set(rows[(7,)].objects) == {
            "IF-MIB::ifIndex",
            "IF-MIB::ifAdminStatus",
            "IF-MIB::ifOperStatus",
        }
        assert set(rows[(9,)].objects) == {
            "IF-MIB::ifIndex",
            "IF-MIB::ifAdminStatus",
        }
        # row 9 itself binds reliably; the missing column is a trap-level fact
        assert all(obj.reliable for obj in rows[(9,)].objects.values())
        assert any(
            "IF-MIB::ifOperStatus" in issue and "absent" in issue
            for issue in result.issues
        )

    def test_repeated_oid_is_reported_not_overwritten(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
            ],
            load_mibs=("IF-MIB",),
        )
        if_index = result.rows[0].objects["IF-MIB::ifIndex"]
        assert len(if_index.bindings) == 2
        assert if_index.ambiguous
        assert not if_index.reliable
        assert if_index.binding is None
        assert any("repeated OID" in issue for issue in result.issues)
        # same name from another row must not be affected
        assert result.rows[0].objects["IF-MIB::ifOperStatus"].reliable

    def test_missing_declared_object_is_reported(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
            ],
            load_mibs=("IF-MIB",),
        )
        assert any(
            "IF-MIB::ifOperStatus" in issue and "absent" in issue
            for issue in result.issues
        )
        row = result.rows[0]
        assert "IF-MIB::ifOperStatus" not in row.objects

    def test_extra_varbinds_are_retained_with_and_without_mib_names(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
                (oid("1.3.6.1.2.1.1.1.0"), rfc1902.OctetString(b"known extra")),
                (oid("1.3.6.1.4.1.99999.1.0"), rfc1902.OctetString(b"unknown extra")),
            ],
            load_mibs=("IF-MIB",),
        )
        by_oid = {b.oid: b for b in result.additional}
        assert by_oid[oid("1.3.6.1.2.1.1.1.0")].resolved
        assert by_oid[oid("1.3.6.1.2.1.1.1.0")].name == "SNMPv2-MIB::sysDescr"
        unknown = by_oid[oid("1.3.6.1.4.1.99999.1.0")]
        assert not unknown.resolved
        assert unknown.name is None
        assert unknown.native_value == b"unknown extra"
        assert result.issues == []

    def test_value_disagreeing_with_mib_syntax_is_flagged_but_kept(self):
        engine = SnmpEngine()
        bad = rfc1902.OctetString(b"not-an-int")
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), bad),
            ],
            load_mibs=("IF-MIB",),
        )
        oper = result.rows[0].objects["IF-MIB::ifOperStatus"]
        assert oper.value_type_mismatch
        assert not oper.reliable
        assert oper.binding.value is bad
        assert any("MIB syntax" in issue for issue in result.issues)


class TestUnknownNotifications:
    def test_unknown_trap_keeps_raw_structure(self):
        engine = SnmpEngine()
        vendor_varbinds = trap_header(trap_oid="1.3.6.1.4.1.99999.0.42") + [
            (oid("1.3.6.1.4.1.99999.1.0"), rfc1902.Integer32(7)),
        ]
        result = parse_notification(engine, vendor_varbinds, load_mibs=("IF-MIB",))

        assert isinstance(result, ParsedNotification)
        assert not result.known_type
        assert result.trap_name is None
        assert result.trap_oid == oid("1.3.6.1.4.1.99999.0.42")
        assert result.objects == {}
        assert result.rows == []
        assert len(result.additional) == 1
        assert result.additional[0].oid == oid("1.3.6.1.4.1.99999.1.0")
        # nothing dropped
        assert result.var_binds == vendor_varbinds
        assert "sysUpTime" in result.protocol_fields
        assert any("not a NOTIFICATION-TYPE" in issue for issue in result.issues)

    def test_missing_protocol_fields_are_reported(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            [(oid("1.3.6.1.4.1.99999.1.0"), rfc1902.Integer32(1))],
        )
        assert result.trap_oid is None
        assert any("snmpTrapOID" in issue for issue in result.issues)
        assert any("sysUpTime" in issue for issue in result.issues)
        assert result.additional[0].oid == oid("1.3.6.1.4.1.99999.1.0")


class TestReliabilityView:
    def test_reliable_objects_excludes_every_ambiguous_binding(self):
        engine = SnmpEngine()
        result = parse_notification(
            engine,
            trap_header()
            + [
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_INDEX}.7"), rfc1902.Integer32(7)),
                (oid(f"{IF_ADMIN}.7"), rfc1902.Integer32(1)),
                (oid(f"{IF_OPER}.7"), rfc1902.Integer32(2)),
            ],
            load_mibs=("IF-MIB",),
        )
        assert "IF-MIB::ifIndex" not in result.reliable_objects
        assert "IF-MIB::ifAdminStatus" in result.reliable_objects
        assert "IF-MIB::ifOperStatus" in result.reliable_objects


class TestIndexAndScalarDeclarations:
    def test_multi_component_index_decodes_each_part(self):
        engine = SnmpEngine()
        engine.getMibBuilder().loadModules("IP-MIB")
        from pysnmp.smi import view as _view
        from pysnmp.hlapi.varbinds import AbstractVarBinds

        mvc = AbstractVarBinds.getMibViewController(engine)
        (column,) = engine.getMibBuilder().importSymbols(
            "IP-MIB", "ipIfStatsInReceives"
        )
        # Synthesize a notification whose trap OID is unknown but which still
        # carries a multi-index column; it lands in additional with the index.
        col_oid = tuple(column.getName()) + (1, 7)
        result = parse_notification(
            engine,
            trap_header(trap_oid="1.3.6.1.4.1.99999.0.7")
            + [(col_oid, rfc1902.Counter32(42))],
        )
        binding = result.additional[0]
        assert binding.column
        assert [b.prettyPrint() for b in binding.index] == ["ipv4", "7"]
        assert binding.index_names == (
            "IP-MIB::ipIfStatsIPVersion",
            "IP-MIB::ipIfStatsIfIndex",
        )

    def test_notification_mixing_scalar_and_column_objects(self):
        engine = SnmpEngine()
        # ACCOUNTING-CONTROL-MIB::acctngFileNearlyFull declares two columns,
        # one scalar and another column.
        nearly_full = "1.3.6.1.2.1.60.2.0.1"
        result = parse_notification(
            engine,
            trap_header(trap_oid=nearly_full)
            + [
                (oid("1.3.6.1.2.1.60.1.2.1.1.2.1"), rfc1902.OctetString(b"a.acct")),
                (oid("1.3.6.1.2.1.60.1.2.1.1.6.1"), rfc1902.Integer32(1000)),
                (oid("1.3.6.1.2.1.60.1.4.1.0"), rfc1902.Integer32(80)),
                (oid("1.3.6.1.2.1.60.1.2.1.1.3.1"), rfc1902.OctetString(b".gz")),
            ],
            load_mibs=("ACCOUNTING-CONTROL-MIB",),
        )
        assert result.trap_name == "ACCOUNTING-CONTROL-MIB::acctngFileNearlyFull"
        assert (
            result.objects["ACCOUNTING-CONTROL-MIB::acctngControlTrapThreshold"]
            .bindings[0]
            .native_value
            == 80
        )
        (row,) = result.rows
        assert row.raw_index == (1,)
        assert row.objects["ACCOUNTING-CONTROL-MIB::acctngFileName"].bindings[
            0
        ].native_value == b"a.acct"
        assert result.issues == []

    def test_undecodable_instance_index_is_marked_unreliable(self):
        engine = SnmpEngine()
        # IP-MIB::ipAddressIfIndex indexed by InetAddressType + InetAddress;
        # type ipv4 requires four address octets, so three do not decode.
        column = (1, 3, 6, 1, 2, 1, 4, 34, 1, 3)
        result = parse_notification(
            engine,
            trap_header(trap_oid="1.3.6.1.4.1.99999.0.7")
            + [(column + (1, 10, 0, 0), rfc1902.Integer32(7))],
            load_mibs=("IP-MIB",),
        )
        binding = result.additional[0]
        assert binding.column
        assert binding.index is None
        assert not binding.index_reliable
        assert binding.native_value == 7
        assert any("does not decode" in issue for issue in result.issues)
