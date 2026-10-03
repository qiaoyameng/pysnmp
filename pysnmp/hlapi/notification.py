#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof deceased
#
"""Structured interpretation of received SNMP notifications.

A receiver historically got a list of ``(oid, value)`` pairs and had to know,
on its own, that the first two are :RFC:`3416` bookkeeping, which of the rest
the trap's ``NOTIFICATION-TYPE`` declares, and which instance of a table row
each column varbind came from. :func:`parse_notification` does that work
against the receiver's loaded MIBs and hands back a result that says, for
every varbind, what it is and how much trust to put in the binding:

* ``sysUpTime.0``, ``snmpTrapOID.0`` and (for v1 traps)
  ``snmpTrapEnterprise.0`` stay protocol fields, never treated as payload.
* Declared ``OBJECTS`` are matched by column/scalar OID prefix, in declared
  order. Scalar instances (``.0``) and table-column instances are handled
  separately, and for columns the instance index is decoded through the
  row's ``INDEX`` clause.
* Varbinds the notification does not declare stay available verbatim,
  resolved against the MIB where possible.
* Ambiguity -- a declared object absent, a varbind matching more than one
  declared object, or one declared object carried by several varbinds -- is
  reported on the result, never silently resolved by dict-overwrite.
* A notification no loaded MIB defines still parses: its declared-object
  section is empty and every varbind is retained.
"""

from __future__ import annotations

from dataclasses import replace
from dataclasses import dataclass, field
from typing import Any

from pyasn1.type import univ as _asn1

from pysnmp.proto import rfc1905
from pysnmp.smi.error import SmiError
from pysnmp.smi.rfc1902 import ObjectIdentity, ObjectType

__all__ = [
    "NotificationBinding",
    "NotificationObject",
    "NotificationRow",
    "ParsedNotification",
    "parse_notification",
]

#: The :RFC:`3416` section-4.2.6 bookkeeping varbinds every v2/v3 notification
#: starts with, plus the v1 ``snmpTrapEnterprise`` the proxy adds. They are
#: protocol fields, not payload, even when a MIB happens to name them.
_PROTOCOL_OIDS = {
    (1, 3, 6, 1, 2, 1, 1, 3, 0): "sysUpTime",
    (1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0): "snmpTrapOID",
    (1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0): "snmpTrapEnterprise",
}


def _as_tuple(oid: Any) -> tuple[int, ...]:
    """An OID, however it arrived, as a tuple of arcs."""
    if isinstance(oid, tuple):
        return oid
    try:
        return tuple(oid.asNumbers())
    except AttributeError:
        return tuple(int(x) for x in str(oid).split(".") if x != "")


def _native_value(value: Any) -> Any:
    """Best-effort conversion of an ASN.1 value to a plain Python value."""
    if isinstance(value, rfc1905.NoSuchObject):
        return None
    if isinstance(value, rfc1905.NoSuchInstance):
        return None
    if isinstance(value, rfc1905.EndOfMibView):
        return None
    # Explicit dispatch rather than try/except: an OctetString accepts
    # bytes() and a TimeTicks accepts bytes() too, but only the octets are
    # meaningful as bytes.
    if isinstance(value, _asn1.OctetString):
        try:
            return bytes(value)
        except Exception:  # noqa: BLE001 - an unrenderable value still parses
            pass
    if isinstance(value, _asn1.ObjectIdentifier):
        try:
            return tuple(value)
        except (AttributeError, ValueError):
            return value.prettyPrint()
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return value.asNumbers()
    except (AttributeError, ValueError):
        pass
    return value.prettyPrint()


@dataclass(frozen=True)
class NotificationBinding:
    """One varbind after the protocol fields, interpreted as far as the MIB allows.

    Attributes
    ----------
    oid:
        The full varbind OID as a tuple of arcs, including any instance
        suffix.
    name:
        ``MODULE::symbol`` of the object the OID names, or ``None`` when no
        loaded MIB names it.
    value:
        The original ASN.1 value object, never replaced -- this is always the
        value as received, even when it disagrees with the MIB-declared
        syntax.
    native_value:
        `value` reduced to a plain Python type (``int``, ``bytes``, ``str``,
        OID tuple) where that is unambiguous; otherwise the ASN.1 object
        itself.
    pretty_value:
        Human-readable rendering of `value` (named enum values included).
    index:
        For a table-column instance, the decoded row index as a tuple of
        index values; for a scalar instance, ``()``; ``None`` when the OID is
        unknown or the index could not be decoded against the row's
        ``INDEX`` clause.
    index_names:
        Symbolic index names parallel to `index` (``IF-MIB::ifIndex`` style),
        or ``None`` alongside an undecodable `index`.
    scalar:
        Whether the named object is a scalar carried on its ``.0`` instance.
    column:
        Whether the named object is a table column carried on a row instance.
    instance_suffix:
        The arcs below the named object. ``(0,)`` for a scalar, the raw
        instance OID for a column, the whole tail for an unknown OID.
    value_type_mismatch:
        Whether the value could not be cast to the syntax the MIB declares
        for this object.
    """

    oid: tuple[int, ...]
    name: str | None
    value: Any
    native_value: Any
    pretty_value: str
    index: tuple[Any, ...] | None
    index_names: tuple[str, ...] | None
    scalar: bool
    column: bool
    instance_suffix: tuple[int, ...]
    value_type_mismatch: bool

    @property
    def resolved(self) -> bool:
        """Whether a loaded MIB names the object this varbind carries."""
        return self.name is not None

    @property
    def index_reliable(self) -> bool:
        """Whether `index` decoded cleanly against the row's INDEX clause."""
        return self.column and self.index is not None and self.index_names is not None


@dataclass(frozen=True)
class NotificationObject:
    """One entry of the notification's ``NOTIFICATION-TYPE`` ``OBJECTS`` clause.

    ``bindings`` keeps every varbind that matched; with one entry the value
    is trustworthy, with several the agent repeated the object and the
    caller has to choose. ``missing`` says no varbind carried it at all.
    """

    module: str
    symbol: str
    name: str
    base_oid: tuple[int, ...]
    scalar: bool
    bindings: tuple[NotificationBinding, ...] = ()
    ambiguous: bool = False
    missing: bool = True
    index_unreliable: bool = False
    value_type_mismatch: bool = False

    @property
    def reliable(self) -> bool:
        """Exactly one well-formed varbind, decodeable index, declared syntax."""
        return (
            not self.missing
            and not self.ambiguous
            and not self.index_unreliable
            and not self.value_type_mismatch
        )

    @property
    def binding(self) -> NotificationBinding | None:
        """The sole binding when unambiguous, else ``None``."""
        return self.bindings[0] if len(self.bindings) == 1 else None


@dataclass(frozen=True)
class NotificationRow:
    """Table-column bindings that share one decoded row instance.

    Columns from one ``OBJECTS`` clause may legitimately come from different
    rows -- nothing in :RFC:`3416` forbids it -- so a notification with
    several distinct column indexes produces one of these per row.
    """

    index: tuple[Any, ...]
    index_names: tuple[str, ...]
    objects: dict[str, NotificationObject]
    raw_index: tuple[int, ...] | None = None


@dataclass
class ParsedNotification:
    """Structured result of interpreting one notification PDU.

    Attributes
    ----------
    trap_oid:
        The value of ``snmpTrapOID.0`` as an OID tuple, or ``None`` when the
        PDU carried no ``snmpTrapOID`` (a malformed v2 trap).
    trap_name:
        ``MODULE::notification`` for the trap OID when a loaded MIB defines
        it, else ``None``.
    known_type:
        Whether a loaded MIB defines the notification. When ``False`` no
        ``OBJECTS`` clause was available: `objects` and `rows` are empty and
        everything is in `additional`, but no varbind has been dropped.
    protocol_fields:
        The bookkeeping varbinds keyed by their fixed names --
        ``sysUpTime``, ``snmpTrapOID`` and, for v1 traps,
        ``snmpTrapEnterprise`` -- each as the original ``(oid, value)`` pair.
    objects:
        Declared scalar objects (those carried on ``.0`` instances) keyed by
        ``MODULE::symbol``. Multi-binding entries remain visible through the
        value's ``bindings``; nothing is collapsed by overwrite.
    rows:
        Declared table-column objects grouped per decoded row instance.
    additional:
        Every non-protocol varbind the ``OBJECTS`` clause did not account
        for, each a `NotificationBinding`; unknown OIDs included.
    unmatched:
        Varbinds that did match a declared object but left the binding
        ambiguous (matched several declarations), for completeness alongside
        the per-object ``ambiguous`` flag.
    issues:
        Human-readable findings: missing declared objects, repeated
        objects, multiple candidates, undecodable indexes, syntax
        disagreements and protocol-field problems. Empty means every
        declared object bound exactly once and cleanly.
    var_binds:
        The original varbind list, unchanged.
    """

    trap_oid: tuple[int, ...] | None
    trap_name: str | None
    known_type: bool
    protocol_fields: dict[str, tuple[tuple[int, ...], Any]]
    objects: dict[str, NotificationObject] = field(default_factory=dict)
    rows: list[NotificationRow] = field(default_factory=list)
    additional: list[NotificationBinding] = field(default_factory=list)
    unmatched: list[NotificationBinding] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    var_binds: list[Any] = field(default_factory=list)

    @property
    def reliable_objects(self) -> dict[str, NotificationObject]:
        """Declared objects whose single binding is trustworthy as-is.

        Scalar objects come from `objects`; table-column objects are taken
        across every row. A column present in several rows is not ambiguous at
        the row level, but a single name-to-value view cannot represent it, so
        it is left out here -- read `rows` for those.
        """
        result = {
            name: obj for name, obj in self.objects.items() if obj.reliable
        }
        column_counts: dict[str, int] = {}
        reliable_columns: dict[str, NotificationObject] = {}
        for row in self.rows:
            for name, obj in row.objects.items():
                column_counts[name] = column_counts.get(name, 0) + 1
                if obj.reliable:
                    reliable_columns[name] = obj
        for name, obj in reliable_columns.items():
            if column_counts[name] == 1:
                result[name] = obj
        return result

    def values(self) -> dict[str, Any]:
        """Plain ``name -> native_value`` for the unambiguous declared objects.

        This is the convenience view. Anything ambiguous, missing, or carrying
        an index that did not decode is left out rather than guessed; inspect
        `objects`, `rows` and `issues` for those.
        """
        result = {
            name: obj.binding.native_value
            for name, obj in self.objects.items()
            if obj.reliable
        }
        for row in self.rows:
            for name, obj in row.objects.items():
                if obj.reliable:
                    result.setdefault(name, obj.binding.native_value)
        return result


def _resolve_binding(
    mib_view: Any,
    node_classes: tuple[Any, Any],
    oid: tuple[int, ...],
    value: Any,
    issues: list[str],
) -> NotificationBinding:
    """Resolve one non-protocol varbind against the MIB, tolerating every miss."""
    identity = ObjectIdentity(oid)
    name: str | None = None
    index: tuple[Any, ...] | None = None
    index_names: tuple[str, ...] | None = None
    scalar = False
    column = False
    suffix: tuple[int, ...] = oid
    mismatch = False

    try:
        identity.resolveWithMib(mib_view, ignoreErrors=False)
        node = identity.getMibNode()
    except SmiError:
        node = None

    scalar_node, column_node_cls = node_classes

    if node is not None:
        module, symbol, indices = identity.getMibSymbol()
        suffix = tuple(int(x) for x in oid[len(tuple(node.getName())):])
        node_name = f"{module}::{symbol}"

        if isinstance(node, column_node_cls):
            column = True
            decoded = tuple(indices)
            index_names = _row_index_names(mib_view, node)
            if len(decoded) != len(index_names) or _opaque_index(
                decoded, suffix, node, mib_view
            ):
                # ObjectIdentity leaves an index it cannot decode against the
                # row's INDEX clause as one opaque ObjectName over the suffix;
                # a part count mismatch catches the cases it encodes quietly.
                index = None
                index_names = None
                issues.append(
                    f"instance index {suffix!r} of {node_name} does not decode "
                    "against the row's INDEX clause"
                )
            else:
                index = decoded
            name = node_name
        elif isinstance(node, scalar_node):
            scalar = True
            index = ()
            if suffix != (0,):
                issues.append(
                    f"scalar {node_name} carried on instance {suffix!r}, not '.0'"
                )
            name = node_name
        # Other node kinds (MibIdentifier, ObjectIdentity, ...) leave name
        # None: an arc registered as a container carries no value semantics.

    if name is not None:
        try:
            resolved = ObjectType(ObjectIdentity(oid), value).resolveWithMib(
                mib_view, ignoreErrors=False, ignoreValueErrors=False
            )
            value = resolved[1]
        except SmiError as exc:
            mismatch = True
            issues.append(f"value of {name} disagrees with its MIB syntax: {exc}")

    try:
        pretty = value.prettyPrint()
    except Exception as exc:  # noqa: BLE001 - rendering must never lose a trap
        pretty = f"<unprintable {type(value).__name__}: {exc}>"

    return NotificationBinding(
        oid=oid,
        name=name,
        value=value,
        native_value=_native_value(value),
        pretty_value=pretty,
        index=index,
        index_names=index_names,
        scalar=scalar,
        column=column,
        instance_suffix=suffix,
        value_type_mismatch=mismatch,
    )


def _opaque_index(
    decoded: tuple[Any, ...],
    suffix: tuple[int, ...],
    column_node: Any,
    mib_view: Any,
) -> bool:
    """Whether a one-part index quietly failed to decode against its row.

    With the right part count, the only soft failure is a single index part
    whose declared type cannot represent the arcs (an InetAddress of the
    wrong length, for instance). Re-run the row's own decoder to find out.
    """
    if len(decoded) != 1 or not suffix:
        return False
    try:
        row_module, row_symbol, _ = mib_view.getNodeLocation(
            column_node.getName()[:-1]
        )
        (row_node,) = mib_view.mibBuilder.importSymbols(row_module, row_symbol)
        row_node.getIndicesFromInstId(suffix)
    except SmiError:
        return True
    return False


def _row_index_names(mib_view: Any, column_node: Any) -> tuple[str, ...]:
    """The row's symbolic index names (``MODULE::symbol``) for a column node."""
    try:
        row_module, row_symbol, _ = mib_view.getNodeLocation(
            column_node.getName()[:-1]
        )
        (row_node,) = mib_view.mibBuilder.importSymbols(row_module, row_symbol)
        return tuple(
            f"{module}::{symbol}"
            for _, module, symbol in row_node.getIndexNames()
        )
    except SmiError:
        return ()


def parse_notification(
    snmp_engine: Any,
    var_binds: Any,
    *,
    load_mibs: tuple[str, ...] | list[str] | None = None,
    mib_view_controller: Any = None,
) -> ParsedNotification:
    """Interpret a received notification's varbinds through its MIB definition.

    Pass the same ``varBinds`` the receiver callback gets, already converted
    to SMIv2 form (pysnmp's receiver does the v1 conversion). The engine
    supplies the MIB view its applications resolve against; pass
    `mib_view_controller` explicitly to resolve against another one.

    OID resolution only sees modules already loaded into that view, matching
    the rest of the high-level API: name an agent's modules with `load_mibs`
    (``load_mibs=("IF-MIB",)``) or load them on the builder beforehand. With
    none loaded the result is still complete -- `known_type` is ``False`` and
    every varbind lands in `additional`.

    Nothing here raises on MIB gaps: an unknown notification or an unknown
    varbind OID yields a result with `known_type` ``False`` or an unresolved
    `NotificationBinding`, and the original list in `var_binds`.

    Returns
    -------
    ParsedNotification
        Structured protocol fields, declared objects, per-row columns,
        additional varbinds and an `issues` list describing every ambiguity.
    """
    if mib_view_controller is None:
        from pysnmp.hlapi.varbinds import AbstractVarBinds

        mib_view_controller = AbstractVarBinds.getMibViewController(snmp_engine)

    var_binds = list(var_binds)
    issues: list[str] = []

    if load_mibs:
        try:
            mib_view_controller.mibBuilder.loadModules(*load_mibs)
        except SmiError as exc:
            # A module the caller named that is not in any source is a setup
            # problem worth surfacing, but not at the cost of dropping the
            # trap: note it and carry on with whatever did load.
            issues.append(f"requested MIB module(s) could not be loaded: {exc}")

    protocol_fields: dict[str, tuple[tuple[int, ...], Any]] = {}
    payload: list[tuple[tuple[int, ...], Any]] = []
    for raw_oid, value in var_binds:
        oid = _as_tuple(raw_oid)
        protocol_name = _PROTOCOL_OIDS.get(oid)
        if protocol_name is not None:
            if protocol_name in protocol_fields:
                issues.append(
                    f"protocol field {protocol_name} appears more than once"
                )
            protocol_fields.setdefault(protocol_name, (oid, value))
        else:
            payload.append((oid, value))

    trap_oid: tuple[int, ...] | None = None
    if "snmpTrapOID" in protocol_fields:
        trap_oid = _as_tuple(protocol_fields["snmpTrapOID"][1])
    else:
        issues.append("notification carries no snmpTrapOID.0 protocol field")
    if "sysUpTime" not in protocol_fields:
        issues.append("notification carries no sysUpTime.0 protocol field")

    trap_name: str | None = None
    declared_refs: tuple[tuple[str, str], ...] = ()
    if trap_oid is not None:
        try:
            trap_identity = ObjectIdentity(trap_oid).resolveWithMib(
                mib_view_controller, ignoreErrors=False
            )
            trap_node = trap_identity.getMibNode()
        except SmiError:
            trap_node = None
        if type(trap_node).__name__ == "NotificationType":
            module, symbol, _ = trap_identity.getMibSymbol()
            trap_name = f"{module}::{symbol}"
            declared_refs = tuple(
                (ref[0], ref[1]) for ref in trap_node.getObjects()
            )
        else:
            issues.append(
                f"snmpTrapOID {'.'.join(str(x) for x in trap_oid)} is not a "
                "NOTIFICATION-TYPE defined in any loaded MIB"
            )

    node_classes = mib_view_controller.mibBuilder.importSymbols(
        "SNMPv2-SMI", "MibScalar", "MibTableColumn"
    )
    _mib_scalar_decl, mib_column_decl = node_classes
    declared: dict[tuple[int, ...], NotificationObject] = {}
    column_objects: list[NotificationObject] = []
    for module, symbol in declared_refs:
        try:
            object_identity = ObjectIdentity(module, symbol).resolveWithMib(
                mib_view_controller, ignoreErrors=False
            )
            object_node = object_identity.getMibNode()
            base_oid = tuple(object_identity.getOid())
        except SmiError as exc:
            issues.append(
                f"declared object {module}::{symbol} cannot be resolved in any "
                f"loaded MIB: {exc}"
            )
            continue
        is_scalar = not isinstance(object_node, mib_column_decl)
        obj = NotificationObject(
            module=module,
            symbol=symbol,
            name=f"{module}::{symbol}",
            base_oid=base_oid,
            scalar=is_scalar,
        )
        declared[base_oid] = obj
        if not is_scalar:
            column_objects.append(obj)

    bindings = [
        _resolve_binding(
            mib_view_controller,
            node_classes,
            oid,
            value,
            issues,
        )
        for oid, value in payload
    ]

    # Match by longest declared OID prefix. A varbind whose OID sits under
    # several declared base OIDs -- possible when one declared object is
    # registered below another's subtree -- is matched to the longest one,
    # the same node the protocol's name resolution would pick. Only a length
    # tie between two declarations is a real ambiguity worth reporting.
    def matches(binding: NotificationBinding) -> list[NotificationObject]:
        candidates = [
            obj
            for obj in declared.values()
            if binding.oid[: len(obj.base_oid)] == obj.base_oid
        ]
        if len(candidates) <= 1:
            return candidates
        longest = max(len(obj.base_oid) for obj in candidates)
        winners = [obj for obj in candidates if len(obj.base_oid) == longest]
        return winners if len(winners) == 1 else candidates

    matched_ids: set[int] = set()
    ambiguous_ids: set[int] = set()
    collected: dict[tuple[int, ...], list[NotificationBinding]] = {
        base: [] for base in declared
    }
    for binding in bindings:
        candidates = matches(binding)
        if len(candidates) == 1:
            collected[candidates[0].base_oid].append(binding)
            matched_ids.add(id(binding))
        elif len(candidates) > 1:
            names = ", ".join(obj.name for obj in candidates)
            issues.append(
                f"varbind {'.'.join(str(x) for x in binding.oid)} matches more "
                f"than one declared object ({names}); left unbound"
            )
            ambiguous_ids.add(id(binding))

    additional = [b for b in bindings if id(b) not in matched_ids]

    objects: dict[str, NotificationObject] = {}
    rows: list[NotificationRow] = []

    for base, obj in declared.items():
        obj_bindings = tuple(collected.get(base, ()))
        if not obj_bindings:
            issues.append(
                f"declared object {obj.name} is absent from the notification"
            )
            continue
        flags = {
            "bindings": obj_bindings,
            "missing": False,
            "ambiguous": len(obj_bindings) > 1,
            "index_unreliable": not obj.scalar
            and any(not b.index_reliable for b in obj_bindings),
            "value_type_mismatch": any(b.value_type_mismatch for b in obj_bindings),
        }
        if flags["ambiguous"]:
            distinct_oids = {b.oid for b in obj_bindings}
            if len(distinct_oids) < len(obj_bindings):
                repeated = sorted(
                    {
                        ".".join(str(x) for x in oid)
                        for oid in distinct_oids
                        if sum(1 for b in obj_bindings if b.oid == oid) > 1
                    }
                )
                detail = f" (repeated OID(s): {', '.join(repeated)})"
            else:
                detail = " from more than one table row"
            issues.append(
                f"declared object {obj.name} is carried by {len(obj_bindings)} "
                f"varbinds{detail}; no single value is authoritative"
            )
        bound = replace(obj, **flags)
        if bound.scalar:
            objects[bound.name] = bound
        else:
            column_objects = [
                bound if existing.base_oid == base else existing
                for existing in column_objects
            ]

    # Group the column bindings into rows by their decoded instance suffix.
    # Columns declared together but arriving from different rows stay in
    # separate NotificationRow entries rather than overwriting each other.
    row_buckets: dict[tuple[int, ...], dict[str, NotificationObject]] = {}
    row_meta: dict[tuple[int, ...], tuple[tuple[Any, ...], tuple[str, ...]]] = {}
    for obj in column_objects:
        if not obj.bindings:
            continue
        for binding in obj.bindings:
            key = binding.instance_suffix
            row_buckets.setdefault(key, {})[obj.name] = obj
            if binding.index is not None and binding.index_names is not None:
                row_meta.setdefault(key, (binding.index, binding.index_names))

    for raw_index, row_objects in row_buckets.items():
        index, index_names = row_meta.get(
            raw_index, ((), ())
        )
        # Columns legitimately arrive from more than one row, so a column
        # missing from one row is reported per row rather than claiming the
        # object present wholesale or dropping it silently.
        for col_obj in column_objects:
            if col_obj.bindings and not any(
                binding.instance_suffix == raw_index
                for binding in col_obj.bindings
            ):
                issues.append(
                    f"declared object {col_obj.name} is absent for row "
                    f"{'.'.join(str(x) for x in raw_index)}"
                )
        row_view = {
            name: replace(
                obj,
                bindings=tuple(
                    b for b in obj.bindings if b.instance_suffix == raw_index
                ),
                ambiguous=sum(
                    1 for b in obj.bindings if b.instance_suffix == raw_index
                )
                > 1,
            )
            for name, obj in row_objects.items()
        }
        rows.append(
            NotificationRow(
                index=index,
                index_names=index_names,
                objects=row_view,
                raw_index=raw_index if raw_index else None,
            )
        )

    return ParsedNotification(
        trap_oid=trap_oid,
        trap_name=trap_name,
        known_type=trap_name is not None,
        protocol_fields=protocol_fields,
        objects=objects,
        rows=rows,
        additional=additional,
        unmatched=[b for b in bindings if id(b) in ambiguous_ids],
        issues=issues,
        var_binds=var_binds,
    )
