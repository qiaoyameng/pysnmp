#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof deceased
#

"""Reading a received notification back against its NOTIFICATION-TYPE definition.

A trap or inform arrives at the application as a flat list of
variable-bindings, and the MIB already says what a notification of that kind
is supposed to carry -- the OBJECTS clause of its NOTIFICATION-TYPE. The flat
list can therefore be read back into named fields instead of every
application matching OIDs by hand.

:py:func:`structureNotification` does that reading. The protocol fields
(``sysUpTime.0`` and ``snmpTrapOID.0``) are lifted out first, then every
object the NOTIFICATION-TYPE declares is matched against the remaining
varbinds: a scalar against its ``.0`` instance, a table column against every
varbind prefix-matched under it, with the trailing sub-OIDs decoded back into
the row's index values.

Nothing is collapsed into a dictionary. A declared object with no matching
varbind is reported missing; one with several candidates -- a duplicated OID,
or instances coming from more than one table row -- is reported ambiguous
with every candidate kept; varbinds no declared object claimed are kept as
extras. A notification whose NOTIFICATION-TYPE is not in the MIB still comes
back with its varbinds intact, simply unresolved.
"""

from pyasn1.error import PyAsn1Error

from pysnmp.smi import error, view

__all__ = [
    "NotificationBinding",
    "NotificationField",
    "StructuredNotification",
    "UnmatchedBinding",
    "structureNotification",
]

#: Instance OIDs of the two protocol fields every SNMPv2 notification carries.
SYS_UP_TIME_0 = (1, 3, 6, 1, 2, 1, 1, 3, 0)
SNMP_TRAP_OID_0 = (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0)


class NotificationBinding:
    """One varbind matched to an object the notification declares.

    For a scalar, `instance` is ``None``. For a table column, `instance` is
    the row's index values decoded from the OID suffix and `row` names the
    table entry as a ``(module, symbol)`` pair; when the suffix does not
    decode against the row's INDEX, `instance` is the raw suffix and `note`
    says so.
    """

    def __init__(self, oid, value, instance=None, row=None, note=""):
        self.oid = oid
        self.value = value
        self.instance = instance
        self.row = row
        self.note = note

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.oid!r}, {self.value!r}, "
            f"instance={self.instance!r})"
        )


class NotificationField:
    """One object of the NOTIFICATION-TYPE's OBJECTS clause, matched.

    `status` is derived from how many varbinds matched: exactly one is
    ``resolved``, none is ``missing``, more than one is ``ambiguous``. Only a
    resolved field has a value the caller can use without further judgement;
    an ambiguous field keeps every candidate in `bindings` instead of letting
    one overwrite the others.
    """

    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    MISSING = "missing"

    #: What the declared object turned out to be in the MIB.
    KIND_SCALAR = "scalar"
    KIND_COLUMN = "column"
    KIND_UNKNOWN = "unknown"

    def __init__(self, module, symbol, oid, kind, bindings=(), note=""):
        self.module = module
        self.symbol = symbol
        self.oid = oid
        self.kind = kind
        self.bindings = tuple(bindings)
        self.note = note

    @property
    def status(self):
        """How the match against the received varbinds came out."""
        if not self.bindings:
            return self.MISSING
        if len(self.bindings) > 1:
            return self.AMBIGUOUS
        return self.RESOLVED

    @property
    def binding(self):
        """The single matched varbind, or ``None`` when not resolved."""
        if self.status == self.RESOLVED:
            return self.bindings[0]
        return None

    @property
    def value(self):
        """The single matched value, or ``None`` when not resolved."""
        binding = self.binding
        return binding.value if binding is not None else None

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.module!r}, {self.symbol!r}, "
            f"status={self.status!r}, bindings={len(self.bindings)})"
        )


class UnmatchedBinding:
    """A varbind no declared object claimed, kept as it arrived.

    `module` and `symbol` are the nearest MIB symbol the OID resolves to
    (itself when nothing known prefixes it, in which case both are ``None``);
    `suffix` is whatever trailed that symbol.
    """

    def __init__(self, oid, value, module=None, symbol=None, suffix=()):
        self.oid = oid
        self.value = value
        self.module = module
        self.symbol = symbol
        self.suffix = suffix

    def __repr__(self):
        location = (
            f"{self.module}::{self.symbol}" if self.module is not None else "unresolved"
        )
        return f"{self.__class__.__name__}({self.oid!r}, {self.value!r}, {location})"


class StructuredNotification:
    """A received notification read back against its NOTIFICATION-TYPE.

    `sysUpTime` and `snmpTrapOID` are the protocol fields as ``(oid, value)``
    pairs, ``None`` when the message did not carry them. `notificationType`
    is the resolved ``(module, symbol)`` of the NOTIFICATION-TYPE, ``None``
    when the trap OID did not resolve to one -- in which case `fields` is
    empty and every payload varbind is in `extras`. `varBinds` always holds
    the message exactly as received.
    """

    def __init__(
        self, varBinds, sysUpTime, snmpTrapOID, notificationType, fields, extras
    ):
        self.varBinds = tuple(varBinds)
        self.sysUpTime = sysUpTime
        self.snmpTrapOID = snmpTrapOID
        self.notificationType = notificationType
        self.fields = tuple(fields)
        self.extras = tuple(extras)

    @property
    def known(self):
        """Whether the trap OID resolved to a NOTIFICATION-TYPE in the MIB."""
        return self.notificationType is not None

    @property
    def missing(self):
        """Declared objects no received varbind matched."""
        return tuple(f for f in self.fields if f.status == NotificationField.MISSING)

    @property
    def ambiguous(self):
        """Declared objects more than one received varbind matched."""
        return tuple(f for f in self.fields if f.status == NotificationField.AMBIGUOUS)

    def getField(self, symbol, module=""):
        """The field for a declared object, by symbol (and optionally module)."""
        for field in self.fields:
            if field.symbol == symbol and (not module or field.module == module):
                return field
        raise KeyError(symbol)

    def __iter__(self):
        return iter(self.fields)

    def __len__(self):
        return len(self.fields)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(notificationType={self.notificationType!r}, "
            f"fields={len(self.fields)}, extras={len(self.extras)})"
        )


def _resolveNotificationType(mibViewController, trapOidValue):
    """Resolve a snmpTrapOID value to its NOTIFICATION-TYPE node, if known."""
    mibBuilder = mibViewController.mibBuilder
    try:
        modName, symName, suffix = mibViewController.getNodeLocation(
            tuple(trapOidValue)
        )
        if suffix:
            return None, None
        (node,) = mibBuilder.importSymbols(modName, symName)
        (notificationTypeClass,) = mibBuilder.importSymbols(
            "SNMPv2-SMI", "NotificationType"
        )
        if not isinstance(node, notificationTypeClass):
            return None, None
    except (error.SmiError, PyAsn1Error, TypeError, ValueError):
        return None, None
    return (modName, symName), node


def _decodeColumnInstance(mibViewController, columnNode, suffix):
    """Decode a column instance suffix into the row's typed index values."""
    mibBuilder = mibViewController.mibBuilder
    try:
        rowModName, rowName, rowSuffix = mibViewController.getNodeLocation(
            columnNode.getName()[:-1]
        )
        (rowNode,) = mibBuilder.importSymbols(rowModName, rowName)
        (mibTableRowClass,) = mibBuilder.importSymbols("SNMPv2-SMI", "MibTableRow")
        if rowSuffix or not isinstance(rowNode, mibTableRowClass):
            raise error.SmiError(
                f"Column {columnNode.getName()!r} has no table row "
                f"at {mibViewController}"
            )
        return (rowModName, rowName), tuple(rowNode.getCellIndices(suffix)), ""
    except error.SmiError as exc:
        return None, tuple(suffix), f"instance indices not decoded: {exc}"


def _matchObject(mibViewController, modName, symName, pool):
    """Match one declared object against the varbind pool.

    Returns the field and the pool entries it claimed. A scalar claims its
    ``.0`` instance; a table column claims every varbind under it, decoding
    each suffix into row indices.
    """
    mibBuilder = mibViewController.mibBuilder
    try:
        (objNode,) = mibBuilder.importSymbols(modName, symName)
    except error.SmiError as exc:
        field = NotificationField(
            modName,
            symName,
            None,
            NotificationField.KIND_UNKNOWN,
            (),
            f"definition unavailable: {exc}",
        )
        return field, ()

    (mibTableColumnClass,) = mibBuilder.importSymbols("SNMPv2-SMI", "MibTableColumn")
    baseOid = tuple(objNode.getName())

    if isinstance(objNode, mibTableColumnClass):
        kind = NotificationField.KIND_COLUMN
        claimed = [
            (oid, value)
            for oid, value in pool
            if len(oid) > len(baseOid) and oid[: len(baseOid)] == baseOid
        ]
        bindings = []
        for oid, value in claimed:
            row, instance, note = _decodeColumnInstance(
                mibViewController, objNode, oid[len(baseOid) :]
            )
            bindings.append(
                NotificationBinding(oid, value, instance=instance, row=row, note=note)
            )
    else:
        kind = NotificationField.KIND_SCALAR
        instanceOid = baseOid + (0,)
        claimed = [(oid, value) for oid, value in pool if oid == instanceOid]
        bindings = [NotificationBinding(oid, value) for oid, value in claimed]

    return NotificationField(modName, symName, baseOid, kind, bindings), claimed


def _locate(mibViewController, oid, value):
    """Best-effort nearest-symbol location for a varbind nothing claimed."""
    try:
        modName, symName, suffix = mibViewController.getNodeLocation(oid)
    except (error.SmiError, PyAsn1Error, TypeError, ValueError):
        modName = symName = None
        suffix = ()
    return UnmatchedBinding(oid, value, modName, symName, suffix)


def structureNotification(varBinds, mibViewController):
    """Read received notification varbinds against the NOTIFICATION-TYPE.

    Parameters
    ----------
    varBinds :
        The variable-bindings exactly as the notification callback received
        them, a sequence of ``(oid, value)`` pairs.
    mibViewController : :py:class:`~pysnmp.smi.view.MibViewController` or SnmpEngine
        Where to resolve the NOTIFICATION-TYPE and its objects. An engine is
        accepted for use straight inside a notification callback; its view
        controller is created once and cached in the engine's user context.

    Returns
    -------
    :py:class:`StructuredNotification`
        The notification with protocol fields lifted out, declared objects
        matched, and everything else kept. A notification whose
        NOTIFICATION-TYPE is not in the MIB comes back with ``known`` false
        and its varbinds untouched -- an unknown notification is never
        dropped for want of a MIB.
    """
    if not isinstance(mibViewController, view.MibViewController):
        # An SnmpEngine, the way a notification callback has it.
        snmpEngine = mibViewController
        mibViewController = snmpEngine.getUserContext("mibViewController")
        if not mibViewController:
            mibViewController = view.MibViewController(snmpEngine.getMibBuilder())
            snmpEngine.setUserContext(mibViewController=mibViewController)

    sysUpTime = None
    snmpTrapOID = None
    pool = []
    for oid, value in varBinds:
        oid = tuple(oid)
        if sysUpTime is None and oid == SYS_UP_TIME_0:
            sysUpTime = (oid, value)
        elif snmpTrapOID is None and oid == SNMP_TRAP_OID_0:
            snmpTrapOID = (oid, value)
        else:
            pool.append((oid, value))

    notificationType = None
    notificationNode = None
    if snmpTrapOID is not None:
        notificationType, notificationNode = _resolveNotificationType(
            mibViewController, snmpTrapOID[1]
        )

    fields = []
    if notificationNode is not None:
        for objModName, objSymName in notificationNode.getObjects():
            field, claimed = _matchObject(
                mibViewController, objModName, objSymName, pool
            )
            fields.append(field)
            for entry in claimed:
                pool.remove(entry)

    extras = [_locate(mibViewController, oid, value) for oid, value in pool]

    return StructuredNotification(
        varBinds, sysUpTime, snmpTrapOID, notificationType, fields, extras
    )
