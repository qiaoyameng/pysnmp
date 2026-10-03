"""
Decoding notifications against their MIB definition
++++++++++++++++++++++++++++++++++++++++++++++++++++

Receive SNMP TRAP/INFORM messages and structure them through
:func:`pysnmp.hlapi.parse_notification`: protocol fields
(``sysUpTime``, ``snmpTrapOID`` and the v1 ``snmpTrapEnterprise``) stay
separate, the notification's declared ``OBJECTS`` bind to their varbinds with
table-row indexes decoded, additional varbinds are retained, and anything
ambiguous or missing is reported instead of silently guessed.

The MIBs the agent uses have to be loaded for names to resolve; here IF-MIB is
named up front. A notification no loaded MIB defines is still returned with
every varbind intact.

A matching Net-SNMP command (a linkDown for interface 2):

| $ snmptrap -v2c -c public 127.0.0.1:162 '' 1.3.6.1.6.3.1.1.5.3 \\
      1.3.6.1.2.1.2.2.1.1.2 i 2 1.3.6.1.2.1.2.2.1.7.2 i 1 \\
      1.3.6.1.2.1.2.2.1.8.2 i 2

Requires Python 3.10 and later!
"""

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.hlapi import parse_notification

snmpEngine = engine.SnmpEngine()

config.addTransport(
    snmpEngine,
    udp.domainName,
    udp.UdpTransport().openServerMode(("0.0.0.0", 162)),
)

config.addV1System(snmpEngine, "my-area", "public")


def cbFun(snmpEngine, contextEngineId, contextName, varBinds, cbCtx):
    notification = parse_notification(snmpEngine, varBinds, load_mibs=("IF-MIB",))

    print(f"Notification: {notification.trap_name or notification.trap_oid}")
    print(f"Uptime: {notification.protocol_fields['sysUpTime'][1].prettyPrint()}")

    # The values safe to use without further judgement.
    for name, value in notification.values().items():
        print(f"  {name} = {value!r}")

    # Table columns grouped per decoded row instance.
    for row in notification.rows:
        print(f"  row index {tuple(index.prettyPrint() for index in row.index)}")
        for name, obj in row.objects.items():
            status = "reliable" if obj.reliable else "ambiguous"
            shown = obj.binding.native_value if obj.binding else obj.bindings
            print(f"    {name} ({status}): {shown}")

    # Everything the OBJECTS clause did not declare, unknown OIDs included.
    for binding in notification.additional:
        print(f"  additional {binding.name or binding.oid} = {binding.native_value!r}")

    # Missing objects, repeated OIDs, undecodable indexes, bad syntaxes.
    for issue in notification.issues:
        print(f"  issue: {issue}")


ntfrcv.NotificationReceiver(snmpEngine, cbFun)

snmpEngine.transportDispatcher.jobStarted(1)

try:
    snmpEngine.transportDispatcher.runDispatcher()
finally:
    snmpEngine.transportDispatcher.closeDispatcher()
