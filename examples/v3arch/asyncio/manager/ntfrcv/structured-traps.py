"""
Reading received notifications against their NOTIFICATION-TYPE
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Receive SNMP TRAP/INFORM messages and read each one back against the
NOTIFICATION-TYPE its ``snmpTrapOID.0`` names, instead of matching OIDs by
hand:

* SNMPv1/SNMPv2c
* with SNMP community "public"
* over IPv4/UDP, listening at 127.0.0.1:162
* using Asyncio framework for network transport

162 is a privileged port, so run this as root or change `LISTEN_AT` below to
something above 1024 and put the same port in the `snmptrap` command.

:py:func:`~pysnmp.entity.rfc3413.notification.structureNotification` lifts
``sysUpTime.0`` and ``snmpTrapOID.0`` out as protocol fields, resolves the
trap OID to its NOTIFICATION-TYPE, and matches every object its OBJECTS
clause declares against the received varbinds. A scalar matches its ``.0``
instance; a table column matches every instance under it, with the OID suffix
decoded back into the row's index values.

The result is deliberately not a dictionary. A declared object no varbind
matched is reported *missing*; one matched by several varbinds -- a duplicate
OID, or instances from two rows of the same table -- is reported *ambiguous*
with every candidate kept; varbinds matching nothing declared are kept as
*extras*. A notification whose NOTIFICATION-TYPE is not in the MIB still
comes back whole, simply unresolved, so an unknown trap is never dropped for
want of a MIB.

Send a notification into this receiver with:

| $ snmptrap -v2c -c public 127.0.0.1 123 1.3.6.1.6.3.1.1.5.3 1.3.6.1.2.1.2.2.1.1.3 i 3

"""  #

from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.entity.rfc3413.notification import structureNotification

# Where notifications arrive. Binding 162 needs privilege; an unprivileged
# port works the same way, and the `snmptrap` command above has to name it.
LISTEN_AT = ("127.0.0.1", 162)


def observe(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    """Print each notification the way its NOTIFICATION-TYPE reads it."""
    notification = structureNotification(varBinds, snmpEngine)

    if notification.known:
        modName, symName = notification.notificationType
        print(f"notification: {modName}::{symName}")
    else:
        print("notification: unknown (NOTIFICATION-TYPE not in the MIB)")

    for field in notification.fields:
        if field.status == field.RESOLVED:
            print(f"  {field.symbol} = {field.value.prettyPrint()}")
        elif field.status == field.AMBIGUOUS:
            candidates = ", ".join(
                f"{b.oid} = {b.value.prettyPrint()}" for b in field.bindings
            )
            print(f"  {field.symbol}: ambiguous -- {candidates}")
        else:
            print(f"  {field.symbol}: missing")

    for extra in notification.extras:
        print(f"  extra: {extra.oid} = {extra.value.prettyPrint()}")


snmpEngine = engine.SnmpEngine()

config.addV1System(snmpEngine, "my-area", "public")
config.addTransport(
    snmpEngine, udp.DOMAIN_NAME, udp.UdpTransport().openServerMode(LISTEN_AT)
)

ntfrcv.NotificationReceiver(snmpEngine, observe)

snmpEngine.transportDispatcher.jobStarted(1)

try:
    snmpEngine.transportDispatcher.runDispatcher()
except KeyboardInterrupt:
    snmpEngine.transportDispatcher.closeDispatcher()
