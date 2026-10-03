"""Persistent USM remote clock estimates keep discovery cheap and replay stale."""

import json
import warnings

import pytest
from pyasn1.codec.ber import decoder
from pyasn1.type import univ

from pysnmp.entity import config
from pysnmp.entity.engine import SnmpEngine
from pysnmp.proto import errind, error
from pysnmp.proto.api import v2c
from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

MANAGER_ID = univ.OctetString(hexValue="80004fb8050102030405")
AGENT_ID = univ.OctetString(hexValue="80004fb805060708090a")
DOMAIN = (1, 3, 6, 1, 6, 1, 1)
ADDRESS = ("127.0.0.1", 161)
USER = "test-user"
AUTH_KEY = "authkey1"


class MutableClock:
    def __init__(self, value):
        self.value = value

    def __call__(self):
        return self.value


class RecordingDispatcher:
    def __init__(self):
        self.messages = []

    def sendMessage(self, whole_message, transport_domain, transport_address):
        self.messages.append((whole_message, transport_domain, transport_address))

    def getTimerResolution(self):
        return 1.0


def configure_user(engine, security_engine_id=None):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        config.addV3User(
            engine,
            USER,
            authProtocol=config.usmHMACSHAAuthProtocol,
            authKey=AUTH_KEY,
            securityEngineId=security_engine_id,
        )


def make_engine(engine_id, clock=None):
    engine = SnmpEngine(snmpEngineID=engine_id, clock=clock)
    engine.transportDispatcher = RecordingDispatcher()
    return engine


def make_pair(clock):
    manager = make_engine(MANAGER_ID, clock)
    agent = make_engine(AGENT_ID, clock)
    (boots,) = agent.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineBoots"
    )
    boots.syntax = boots.syntax.clone(1)
    (engine_time,) = agent.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineTime"
    )
    engine_time.syntax = engine_time.syntax.clone(0)
    configure_user(manager, AGENT_ID)
    configure_user(agent)
    return manager, agent


def get_request_pdu():
    pdu = v2c.GetRequestPDU()
    v2c.apiPDU.setDefaults(pdu)
    v2c.apiPDU.setVarBinds(pdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0), univ.Null(""))])
    return pdu


def build_get(manager, agent):
    return manager.messageProcessingSubsystems[3].prepareOutgoingMessage(
        manager,
        DOMAIN,
        ADDRESS,
        3,
        3,
        univ.OctetString(USER),
        2,
        None,
        b"",
        1,
        get_request_pdu(),
        True,
        1,
    )[2]


def decode_message(whole_message):
    message, _ = decoder.decode(whole_message, asn1Spec=SNMPv3Message())
    security_parameters, _ = decoder.decode(
        message[2], asn1Spec=UsmSecurityParameters()
    )
    return message, security_parameters


def is_authenticated(whole_message):
    message, _ = decode_message(whole_message)
    return bool(message[1][2].asNumbers()[0] & 0x01)


def deliver(engine, whole_message):
    return engine.messageProcessingSubsystems[3].prepareDataElements(
        engine, DOMAIN, ADDRESS, whole_message
    )


def last_report(engine):
    return engine.transportDispatcher.messages[-1][0]


def discover(clock):
    manager, agent = make_pair(clock)

    discovery = build_get(manager, agent)
    assert not is_authenticated(discovery)
    with pytest.raises(error.StatusInformation):
        deliver(agent, discovery)
    with pytest.raises(error.StatusInformation):
        deliver(manager, last_report(agent))

    timed_request = build_get(manager, agent)
    assert is_authenticated(timed_request)
    with pytest.raises(error.StatusInformation):
        deliver(agent, timed_request)
    with pytest.raises(error.StatusInformation):
        deliver(manager, last_report(agent))

    synchronized_request = build_get(manager, agent)
    assert is_authenticated(synchronized_request)
    assert deliver(agent, synchronized_request)

    return manager, agent


def clock_entry(snapshot):
    return snapshot["clocks"]["entries"][0]


def restart_manager(clock):
    manager = make_engine(MANAGER_ID, clock)
    configure_user(manager, AGENT_ID)
    return manager


def test_export_contains_only_authenticated_key_free_state():
    clock = MutableClock(1000)
    manager, _agent = discover(clock)

    snapshot = manager.export_remote_clocks()

    assert json.dumps(snapshot)
    assert snapshot["clocks"]["version"] == 1
    assert snapshot["peers"]["version"] == 1
    entry = clock_entry(snapshot)
    assert entry["engineBoots"] == 1
    assert entry["engineTime"] == 0
    assert entry["savedAt"] == 1000
    assert entry["securityEngineId"] == bytes(AGENT_ID).hex()
    assert snapshot["peers"]["entries"][0]["transport"]["address"] == list(ADDRESS)
    serialized = json.dumps(snapshot).lower()
    assert "auth" not in serialized
    assert "priv" not in serialized
    assert "key" not in serialized
    assert "username" not in serialized


def test_unauthenticated_discovery_report_is_not_exported():
    clock = MutableClock(1000)
    manager, agent = make_pair(clock)

    discovery = build_get(manager, agent)
    with pytest.raises(error.StatusInformation):
        deliver(agent, discovery)
    with pytest.raises(error.StatusInformation):
        deliver(manager, last_report(agent))

    snapshot = manager.export_remote_clocks()

    assert snapshot["clocks"]["entries"] == []
    assert snapshot["peers"]["entries"] == []


def test_restart_import_uses_estimate_without_discovery():
    clock = MutableClock(1000)
    manager, agent = discover(clock)
    snapshot = manager.export_remote_clocks()

    clock.value = 1010
    restarted = restart_manager(clock)

    assert restarted.messageProcessingSubsystems[3].getPeerEngineInfo(
        DOMAIN, ADDRESS
    ) == (None, None, None)
    result = restarted.import_remote_clocks(snapshot)
    assert result == {
        "clocks": {"imported": 1, "rejected": 0, "entries": [bytes(AGENT_ID).hex()]},
        "peers": {"imported": 1, "rejected": 0},
    }
    assert restarted.messageProcessingSubsystems[3].getPeerEngineInfo(
        DOMAIN, ADDRESS
    )[0] == agent.snmpEngineID

    request = build_get(restarted, agent)
    assert is_authenticated(request)
    _message, parameters = decode_message(request)
    assert int(parameters[1]) == 1
    assert int(parameters[2]) == 10
    assert deliver(agent, request)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("securityEngineId", "00000000"),
        ("engineBoots", 2147483647),
        ("engineBoots", -1),
        ("engineTime", 2147483648),
        ("latestReceivedEngineTime", -1),
        ("savedAt", 1151),
        ("savedAt", 999),
    ),
)
def test_import_rejects_invalid_or_unprovable_clock_records(field, value):
    clock = MutableClock(1000)
    manager, _agent = discover(clock)
    snapshot = manager.export_remote_clocks()
    clock_entry(snapshot)[field] = value
    clock.value = 1150
    restarted = restart_manager(clock)

    result = restarted.import_remote_clocks(snapshot)

    assert result["clocks"]["imported"] == 0
    assert result["clocks"]["rejected"] == 1
    assert result["peers"]["imported"] == 0
    assert restarted.messageProcessingSubsystems[3].getPeerEngineInfo(
        DOMAIN, ADDRESS
    ) == (None, None, None)


def test_expired_record_falls_back_to_discovery():
    clock = MutableClock(1000)
    manager, agent = discover(clock)
    snapshot = manager.export_remote_clocks()

    clock.value = 1160
    restarted = restart_manager(clock)
    assert restarted.import_remote_clocks(snapshot)["clocks"]["imported"] == 0

    request = build_get(restarted, agent)
    assert not is_authenticated(request)


def test_wall_clock_rollback_falls_back_to_discovery():
    saved_clock = MutableClock(1000)
    snapshot = discover(saved_clock)[0].export_remote_clocks()
    clock_entry(snapshot)["engineBoots"] = 2
    clock_entry(snapshot)["latestReceivedEngineTime"] = 1

    current_clock = MutableClock(1010)
    manager = restart_manager(current_clock)
    assert manager.import_remote_clocks(snapshot)["clocks"]["imported"] == 1

    current_clock.value = 900
    request = build_get(manager, SnmpEngine(snmpEngineID=AGENT_ID))

    _message, parameters = decode_message(request)
    assert is_authenticated(request)
    assert int(parameters[1]) == 0
    assert int(parameters[2]) == 0
    assert manager.export_remote_clocks()["clocks"]["entries"] == []


def test_device_reboot_invalidates_lower_boots_and_rediscovers():
    clock = MutableClock(1000)
    _old_manager, _agent = discover(clock)
    snapshot = _old_manager.export_remote_clocks()
    clock_entry(snapshot)["engineBoots"] = 2

    clock.value = 1010
    manager = restart_manager(clock)
    assert manager.import_remote_clocks(snapshot)["clocks"]["imported"] == 1

    rebooted = make_engine(AGENT_ID, clock)
    configure_user(rebooted)
    (boots,) = rebooted.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineBoots"
    )
    boots.syntax = boots.syntax.clone(1)
    (engine_time,) = (
        rebooted.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
            "__SNMP-FRAMEWORK-MIB", "snmpEngineTime"
        )
    )
    engine_time.syntax = engine_time.syntax.clone(0)

    request = build_get(manager, rebooted)
    assert is_authenticated(request)
    with pytest.raises(error.StatusInformation):
        deliver(rebooted, request)
    with pytest.raises(error.StatusInformation) as exc_info:
        deliver(manager, last_report(rebooted))
    assert exc_info.value["errorIndication"] is errind.notInTimeWindow

    assert not is_authenticated(build_get(manager, rebooted))
    assert manager.export_remote_clocks()["clocks"]["entries"] == []


def test_receiver_rejects_replay_without_import_advancing_old_time():
    clock = MutableClock(1000)
    manager, agent = discover(clock)
    snapshot = manager.export_remote_clocks()

    clock.value = 1010
    manager = restart_manager(clock)
    assert manager.import_remote_clocks(snapshot)["clocks"]["imported"] == 1

    captured_request = build_get(manager, agent)
    assert is_authenticated(captured_request)
    assert deliver(agent, captured_request)

    (engine_time,) = agent.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineTime"
    )
    engine_time.syntax = engine_time.syntax.clone(200)
    clock.value = 1170

    with pytest.raises(error.StatusInformation):
        deliver(agent, captured_request)
    with pytest.raises(error.StatusInformation) as exc_info:
        deliver(manager, last_report(agent))
    assert exc_info.value["errorIndication"] is errind.notInTimeWindow

    entry = clock_entry(manager.export_remote_clocks())
    assert entry["engineTime"] == 200
    assert entry["latestReceivedEngineTime"] == 200


def test_envelope_format_is_required():
    clock = MutableClock(1000)
    manager = restart_manager(clock)

    with pytest.raises(ValueError):
        manager.import_remote_clocks({})
