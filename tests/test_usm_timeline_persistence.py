"""USM remote-engine-clock persistence: export, import, and replay safety.

Restarting a collector used to mean rediscovering engine boots/time for every
SNMPv3 device. These tests drive a real manager/agent USM exchange, export the
trusted timeline, restore it into a fresh engine behind an injectable clock,
and prove the two goals do not cancel each other: discovery round trips are
avoided, yet authentication and the RFC 3414 boots/time monotonic rules still
apply to every incoming message.
"""

import itertools
import json

import pytest
from pyasn1.codec.ber import decoder

from pysnmp.entity import config
from pysnmp.entity.engine import SnmpEngine
from pysnmp.proto import api, errind, error
from pysnmp.proto.mpmod.rfc3412 import HeaderData, ScopedPDU, SNMPv3Message
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

pMod = api.protoModules[api.protoVersion2c]

USER_NAME = "usr-sha"
AUTH_KEY = "authkey1"
WRONG_KEY = "wrongkey1"
MAX_MESSAGE_SIZE = 65535

AUTH_PROTOCOL = config.usmHMAC192SHA256AuthProtocol

_msg_ids = itertools.count(1)


class FakeClock:
    """Wall clock the tests can advance without sleeping."""

    def __init__(self, start=1_700_000_000):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def _new_manager(agent_engine_id, clock=None, auth_key=AUTH_KEY):
    """A manager engine holding keys localized to the agent's engine ID."""
    engine = SnmpEngine()
    config.addV3User(
        engine,
        USER_NAME,
        AUTH_PROTOCOL,
        auth_key,
        securityEngineId=agent_engine_id,
    )
    usm = engine.securityModels[3]
    if clock is not None:
        usm._clock = clock
    return engine, usm


def _new_agent(clock=None):
    """An authoritative agent engine holding the same user."""
    engine = SnmpEngine()
    config.addV3User(engine, USER_NAME, AUTH_PROTOCOL, AUTH_KEY)
    usm = engine.securityModels[3]
    if clock is not None:
        usm._clock = clock
    return engine, usm


def _lcd_scalar(engine, name):
    (scalar,) = engine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        "__SNMP-FRAMEWORK-MIB", name
    )
    return scalar


def _lcd_boots_time(engine):
    return (
        int(_lcd_scalar(engine, "snmpEngineBoots").syntax),
        int(_lcd_scalar(engine, "snmpEngineTime").syntax),
    )


def _new_message(flags=b"\x05"):
    msg = SNMPv3Message()
    msg.setComponentByPosition(0, 3)
    header = HeaderData()
    header.setComponentByPosition(0, next(_msg_ids))
    header.setComponentByPosition(1, MAX_MESSAGE_SIZE)
    header.setComponentByPosition(2, flags)
    header.setComponentByPosition(3, 3)
    msg.setComponentByPosition(1, header)
    return msg


def _scoped_pdu(context_engine_id, pdu):
    scoped = ScopedPDU()
    scoped.setComponentByPosition(0, context_engine_id)
    scoped.setComponentByPosition(1, b"")
    scoped.setComponentByPosition(2)
    scoped.getComponentByPosition(2).setComponentByType(
        pdu.tagSet,
        pdu,
        verifyConstraints=False,
        matchTags=False,
        matchConstraints=False,
    )
    return scoped


def _send_request(usm, engine, agent_engine_id):
    """Build an authenticated authNoPriv GET request; return the wire message."""
    pdu = pMod.GetRequestPDU()
    pMod.apiPDU.setDefaults(pdu)
    pMod.apiPDU.setVarBinds(pdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0), pMod.Null())])
    _, whole_msg = usm.generateRequestMsg(
        engine,
        3,
        _new_message(),
        MAX_MESSAGE_SIZE,
        3,
        agent_engine_id,
        pMod.OctetString(USER_NAME),
        2,
        _scoped_pdu(agent_engine_id, pdu),
    )
    return whole_msg


def _request_boots_time(whole_msg):
    """Pull msgAuthoritativeEngineBoots/Time out of a wire message."""
    msg, _ = decoder.decode(whole_msg, asn1Spec=SNMPv3Message())
    sec_params, _ = decoder.decode(
        msg.getComponentByPosition(2), asn1Spec=UsmSecurityParameters()
    )
    return (
        int(sec_params.getComponentByPosition(1)),
        int(sec_params.getComponentByPosition(2)),
    )


def _deliver(usm, engine, whole_msg):
    """Run a wire message through the receiving USM."""
    msg, _ = decoder.decode(whole_msg, asn1Spec=SNMPv3Message())
    return usm.processIncomingMsg(
        engine,
        3,
        MAX_MESSAGE_SIZE,
        msg.getComponentByPosition(2),
        3,
        2,
        whole_msg,
        msg,
    )


def _build_report(usm, engine, status_info):
    """Turn a USM failure into the authenticated report an agent would send."""
    report_pdu = pMod.ReportPDU()
    pMod.apiPDU.setDefaults(report_pdu)
    pMod.apiPDU.setVarBinds(report_pdu, [(status_info["oid"], status_info["val"])])
    _, whole_msg = usm.generateResponseMsg(
        engine,
        3,
        _new_message(flags=b"\x01"),
        MAX_MESSAGE_SIZE,
        3,
        engine.snmpEngineID,
        None,
        2,
        _scoped_pdu(status_info["contextEngineId"], report_pdu),
        status_info["securityStateReference"],
    )
    return whole_msg


def _discover(mgr_engine, mgr_usm, agent_engine, agent_usm):
    """Run the RFC 3414 discovery exchange, syncing the manager's timeline."""
    request = _send_request(mgr_usm, mgr_engine, agent_engine.snmpEngineID)
    with pytest.raises(error.StatusInformation) as exc:
        _deliver(agent_usm, agent_engine, request)
    assert exc.value["errorIndication"] is errind.notInTimeWindow
    report = _build_report(agent_usm, agent_engine, exc.value)
    result = _deliver(mgr_usm, mgr_engine, report)
    assert result[0] == agent_engine.snmpEngineID


def _exchange(mgr_engine, mgr_usm, agent_engine, agent_usm):
    """A full accepted request/response round trip."""
    request = _send_request(mgr_usm, mgr_engine, agent_engine.snmpEngineID)
    _, _, scoped_pdu, _, state_ref = _deliver(agent_usm, agent_engine, request)
    response_pdu = pMod.ResponsePDU()
    pMod.apiPDU.setDefaults(response_pdu)
    pMod.apiPDU.setVarBinds(
        response_pdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0), pMod.OctetString("x"))]
    )
    _, whole_msg = agent_usm.generateResponseMsg(
        agent_engine,
        3,
        _new_message(flags=b"\x01"),
        MAX_MESSAGE_SIZE,
        3,
        agent_engine.snmpEngineID,
        None,
        2,
        _scoped_pdu(scoped_pdu.getComponentByPosition(0), response_pdu),
        state_ref,
    )
    return _deliver(mgr_usm, mgr_engine, whole_msg)


def _restart_manager(agent_engine_id, clock):
    """A fresh manager engine with no memory of any peer, as after a restart."""
    return _new_manager(agent_engine_id, clock)


class TestTimelineExport:
    def test_export_contains_trusted_state_without_keys(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)

        # Nothing authenticated yet: nothing to export.
        assert mgr_usm.exportTimeline()["entries"] == []

        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)

        snapshot = mgr_usm.exportTimeline()
        assert snapshot["version"] == 1
        assert snapshot["savedAt"] == int(clock.now)
        (entry,) = snapshot["entries"]
        assert entry["engineId"] == agent_engine.snmpEngineID.asOctets().hex()
        agent_boots, agent_time = _lcd_boots_time(agent_engine)
        assert entry["boots"] == agent_boots
        assert entry["time"] == agent_time
        assert entry["latestReceivedEngineTime"] == agent_time
        assert entry["updatedAt"] == int(clock.now)

        # The snapshot is JSON-serializable and carries no key material.
        blob = json.dumps(snapshot)
        assert AUTH_KEY not in blob
        assert "key" not in blob.lower()

    def test_unauthenticated_message_creates_no_exportable_state(self):
        agent_engine, _ = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        bad_engine, bad_usm = _new_manager(
            agent_engine.snmpEngineID, clock, auth_key=WRONG_KEY
        )

        forged = _send_request(bad_usm, bad_engine, agent_engine.snmpEngineID)
        with pytest.raises(error.StatusInformation) as exc:
            _deliver(mgr_usm, mgr_engine, forged)
        assert exc.value["errorIndication"] is errind.authenticationFailure

        assert mgr_usm.exportTimeline()["entries"] == []

    def test_forged_message_does_not_poison_existing_state(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        before = mgr_usm.exportTimeline()["entries"]

        bad_engine, bad_usm = _new_manager(
            agent_engine.snmpEngineID, clock, auth_key=WRONG_KEY
        )
        forged = _send_request(bad_usm, bad_engine, agent_engine.snmpEngineID)
        with pytest.raises(error.StatusInformation):
            _deliver(mgr_usm, mgr_engine, forged)

        assert mgr_usm.exportTimeline()["entries"] == before


class TestTimelineImport:
    def test_import_avoids_rediscovery_after_restart(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        snapshot = mgr_usm.exportTimeline()

        # The collector restarts; the outage lasts two minutes.
        clock.advance(120)
        mgr2_engine, mgr2_usm = _restart_manager(agent_engine.snmpEngineID, clock)
        assert mgr2_usm.importTimeline(mgr2_engine, snapshot) == 1

        # The very first request already carries the restored estimate...
        request = _send_request(mgr2_usm, mgr2_engine, agent_engine.snmpEngineID)
        assert _request_boots_time(request) == _lcd_boots_time(agent_engine)

        # ...so the agent accepts it outright: no report round trip, no
        # rediscovery, yet the message was still fully authenticated.
        result = _deliver(agent_usm, agent_engine, request)
        assert result[0] == agent_engine.snmpEngineID

    def test_restart_without_import_falls_back_to_discovery(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        mgr_usm.exportTimeline()

        clock.advance(120)
        mgr2_engine, mgr2_usm = _restart_manager(agent_engine.snmpEngineID, clock)

        # No import: the first request goes out with zero boots/time...
        request = _send_request(mgr2_usm, mgr2_engine, agent_engine.snmpEngineID)
        assert _request_boots_time(request) == (0, 0)

        # ...and the agent answers with the notInTimeWindow discovery report.
        with pytest.raises(error.StatusInformation) as exc:
            _deliver(agent_usm, agent_engine, request)
        assert exc.value["errorIndication"] is errind.notInTimeWindow

    def test_device_reboot_falls_back_to_discovery(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        snapshot = mgr_usm.exportTimeline()

        clock.advance(120)
        mgr2_engine, mgr2_usm = _restart_manager(agent_engine.snmpEngineID, clock)
        assert mgr2_usm.importTimeline(mgr2_engine, snapshot) == 1

        # The device rebooted while the collector was down: boots moved on.
        _lcd_scalar(agent_engine, "snmpEngineBoots").syntax += 1

        # The restored estimate is stale, so the agent refuses the message and
        # reports instead of accepting it -- the import widened nothing.
        request = _send_request(mgr2_usm, mgr2_engine, agent_engine.snmpEngineID)
        with pytest.raises(error.StatusInformation) as exc:
            _deliver(agent_usm, agent_engine, request)
        assert exc.value["errorIndication"] is errind.notInTimeWindow

        # The report resynchronizes the manager to the new boots, monotonically.
        report = _build_report(agent_usm, agent_engine, exc.value)
        _deliver(mgr2_usm, mgr2_engine, report)
        (entry,) = mgr2_usm.exportTimeline()["entries"]
        assert entry["boots"] == _lcd_boots_time(agent_engine)[0]

        # And requests are accepted again.
        request = _send_request(mgr2_usm, mgr2_engine, agent_engine.snmpEngineID)
        result = _deliver(agent_usm, agent_engine, request)
        assert result[0] == agent_engine.snmpEngineID

    def test_stale_snapshot_falls_back_to_discovery(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        snapshot = mgr_usm.exportTimeline()

        clock.advance(86401)
        mgr2_engine, mgr2_usm = _restart_manager(agent_engine.snmpEngineID, clock)
        with pytest.raises(ValueError, match="old"):
            mgr2_usm.importTimeline(mgr2_engine, snapshot)

        # Nothing was imported: discovery happens as usual.
        request = _send_request(mgr2_usm, mgr2_engine, agent_engine.snmpEngineID)
        assert _request_boots_time(request) == (0, 0)

    def test_wall_clock_rollback_falls_back_to_discovery(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        snapshot = mgr_usm.exportTimeline()

        # The wall clock jumps backwards across the restart.
        clock.now -= 3600
        mgr2_engine, mgr2_usm = _restart_manager(agent_engine.snmpEngineID, clock)
        with pytest.raises(ValueError, match="future"):
            mgr2_usm.importTimeline(mgr2_engine, snapshot)

        request = _send_request(mgr2_usm, mgr2_engine, agent_engine.snmpEngineID)
        assert _request_boots_time(request) == (0, 0)

    def test_malformed_snapshots_rejected(self):
        agent_engine, _ = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        for bad in (
            None,
            [],
            "snapshot",
            {},
            {"version": 2, "savedAt": int(clock.now), "entries": []},
            {"version": 1, "savedAt": "soon", "entries": []},
            {"version": 1, "savedAt": int(clock.now), "entries": {}},
        ):
            with pytest.raises(ValueError):
                mgr_usm.importTimeline(mgr_engine, bad)

    def test_invalid_entries_skipped(self):
        agent_engine, _ = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        now = int(clock.now)
        valid = {
            "engineId": "800102030405",
            "boots": 7,
            "time": 42,
            "latestReceivedEngineTime": 42,
            "updatedAt": now - 10,
        }
        snapshot = {
            "version": 1,
            "savedAt": now,
            "entries": [
                valid,
                # too short to be an SnmpEngineID
                {**valid, "engineId": "0102"},
                # boots outside the RFC 3414 range
                {**valid, "engineId": "800102030406", "boots": 2147483648},
                # entry newer than the snapshot: continuity unprovable
                {**valid, "engineId": "800102030407", "updatedAt": now + 1},
                # last authenticated contact too long ago
                {**valid, "engineId": "800102030408", "updatedAt": now - 86401},
                # our own engine's clock is never imported
                {**valid, "engineId": mgr_engine.snmpEngineID.asOctets().hex()},
                # wrong field type
                {**valid, "engineId": "800102030409", "boots": "7"},
                # missing fields
                {"engineId": "80010203040a"},
                # not even a dict
                "not-an-entry",
            ],
        }
        assert mgr_usm.importTimeline(mgr_engine, snapshot) == 1
        entries = mgr_usm.exportTimeline()["entries"]
        assert [entry["engineId"] for entry in entries] == ["800102030405"]
        assert entries[0]["boots"] == 7
        assert entries[0]["time"] == 42

    def test_imported_entries_expire_like_learned_ones(self):
        agent_engine, _ = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        now = int(clock.now)
        snapshot = {
            "version": 1,
            "savedAt": now,
            "entries": [
                {
                    "engineId": "800102030405",
                    "boots": 1,
                    "time": 10,
                    "latestReceivedEngineTime": 10,
                    "updatedAt": now,
                }
            ],
        }
        assert mgr_usm.importTimeline(mgr_engine, snapshot) == 1
        assert mgr_usm.exportTimeline()["entries"]

        for _ in range(301):
            mgr_usm.receiveTimerTick(mgr_engine, 0)

        assert mgr_usm.exportTimeline()["entries"] == []

    def test_import_never_downgrades_fresher_state(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        snapshot = mgr_usm.exportTimeline()

        # The same live USM keeps talking to the device, refreshing its entry.
        clock.advance(60)
        _exchange(mgr_engine, mgr_usm, agent_engine, agent_usm)

        # Re-importing the older snapshot must not move the entry backwards.
        assert mgr_usm.importTimeline(mgr_engine, snapshot) == 0
        (entry,) = mgr_usm.exportTimeline()["entries"]
        assert entry["updatedAt"] == int(clock.now)


class TestReplayProtectionAfterImport:
    def test_replayed_message_outside_time_window_rejected(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        snapshot = mgr_usm.exportTimeline()

        clock.advance(120)
        mgr2_engine, mgr2_usm = _restart_manager(agent_engine.snmpEngineID, clock)
        assert mgr2_usm.importTimeline(mgr2_engine, snapshot) == 1

        # A valid request goes out carrying the restored estimate.
        request = _send_request(mgr2_usm, mgr2_engine, agent_engine.snmpEngineID)

        # The device's clock then moves beyond the 150 s window...
        time_scalar = _lcd_scalar(agent_engine, "snmpEngineTime")
        time_scalar.syntax = time_scalar.syntax.clone(int(time_scalar.syntax) + 200)

        # ...and replaying the captured request is rejected: the imported state
        # did not widen the RFC 3414 time window on the receive side.
        with pytest.raises(error.StatusInformation) as exc:
            _deliver(agent_usm, agent_engine, request)
        assert exc.value["errorIndication"] is errind.notInTimeWindow

    def test_unauthenticated_message_still_rejected_after_import(self):
        agent_engine, agent_usm = _new_agent()
        clock = FakeClock()
        mgr_engine, mgr_usm = _new_manager(agent_engine.snmpEngineID, clock)
        _discover(mgr_engine, mgr_usm, agent_engine, agent_usm)
        snapshot = mgr_usm.exportTimeline()

        clock.advance(120)
        mgr2_engine, mgr2_usm = _restart_manager(agent_engine.snmpEngineID, clock)
        assert mgr2_usm.importTimeline(mgr2_engine, snapshot) == 1

        # An attacker who knows the engine ID and user name but not the key
        # still cannot get a message past authentication.
        bad_engine, bad_usm = _new_manager(
            agent_engine.snmpEngineID, clock, auth_key=WRONG_KEY
        )
        forged = _send_request(bad_usm, bad_engine, agent_engine.snmpEngineID)
        with pytest.raises(error.StatusInformation) as exc:
            _deliver(mgr2_usm, mgr2_engine, forged)
        assert exc.value["errorIndication"] is errind.authenticationFailure

        # And the imported estimate is left untouched.
        (after,) = mgr2_usm.exportTimeline()["entries"]
        (before,) = snapshot["entries"]
        for field in ("engineId", "boots", "time", "latestReceivedEngineTime"):
            assert after[field] == before[field]
