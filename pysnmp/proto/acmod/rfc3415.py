#
# This file is part of pysnmp software.
#
# Copyright (c) 2005-2019, Ilya Etingof deceased
#
"""The View-based Access Control Model of RFC 3415."""

from pysnmp import debug
from pysnmp.proto import errind, error
from pysnmp.smi.error import NoSuchInstanceError


class VacmAccessSnapshot:
    """An immutable VACM decision for one security/context/view-type tuple."""

    __slots__ = (
        "_securityModel",
        "_securityName",
        "_securityLevel",
        "_viewType",
        "_contextName",
        "_viewTreeEntries",
    )

    def __init__(
        self,
        securityModel,
        securityName,
        securityLevel,
        viewType,
        contextName,
        viewTreeEntries,
    ):
        object.__setattr__(self, "_securityModel", securityModel)
        object.__setattr__(self, "_securityName", securityName)
        object.__setattr__(self, "_securityLevel", securityLevel)
        object.__setattr__(self, "_viewType", viewType)
        object.__setattr__(self, "_contextName", contextName)
        object.__setattr__(
            self,
            "_viewTreeEntries",
            tuple(
                (subtree.clone(), tuple(ignoredSubOids), included)
                for subtree, ignoredSubOids, included in viewTreeEntries
            ),
        )

    def __setattr__(self, name, value):
        raise AttributeError(f"{type(self).__name__!s} is read-only")

    def __delattr__(self, name):
        raise AttributeError(f"{type(self).__name__!s} is read-only")

    def isAccessAllowed(self, variableName):
        """Check another OID against the access rules frozen in this snapshot."""
        debug.logger & debug.flagACL and debug.logger(
            f"VacmAccessSnapshot.isAccessAllowed: securityModel {self._securityModel}, "
            f"securityName {debug.prettify(self._securityName)}, "
            f"securityLevel {self._securityLevel}, viewType {self._viewType}, "
            f"contextName {debug.prettify(self._contextName)} "
            f"for variableName {variableName}"
        )

        accessAllowed = False

        for subtree, ignoredSubOids, included in self._viewTreeEntries:
            if len(variableName) < len(subtree):
                continue

            if ignoredSubOids:
                subOids = list(variableName)

                for ignoredSubOid in ignoredSubOids:
                    subOids[ignoredSubOid] = 0

                normalizedVariableName = subtree.clone(subOids)

            else:
                normalizedVariableName = variableName

            if subtree.isPrefixOf(normalizedVariableName):
                accessAllowed = included

        if not accessAllowed:
            raise error.StatusInformation(errorIndication=errind.notInView)


# 3.2
class Vacm:
    """View-based Access Control Model."""

    accessModelID = 3

    _powOfTwoSeq = (128, 64, 32, 16, 8, 4, 2, 1)

    def __init__(self):
        """Four VACM tables, each cached against its own branch version.

        Access control runs on every variable binding of every request, so the tables
        are read once and kept. Each has its own version ID, so a write to one does not
        discard the caches of the other three.
        """
        self._contextBranchId = -1
        self._groupNameBranchId = -1
        self._accessBranchId = -1
        self._viewTreeBranchId = -1

        self._contextMap = {}
        self._groupNameMap = {}
        self._accessMap = {}
        self._viewTreeMap = {}

    def _refreshContextMap(self, mibBuilder):
        (vacmContextName,) = mibBuilder.importSymbols(
            "SNMP-VIEW-BASED-ACM-MIB", "vacmContextName"
        )

        if self._contextBranchId == vacmContextName.branchVersionId:
            return

        self._contextMap.clear()

        nextMibNode = vacmContextName

        while True:
            try:
                nextMibNode = vacmContextName.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            self._contextMap[nextMibNode.syntax] = True

        self._contextBranchId = vacmContextName.branchVersionId

    def _refreshGroupNameMap(self, mibBuilder):
        (vacmGroupName,) = mibBuilder.importSymbols(
            "SNMP-VIEW-BASED-ACM-MIB", "vacmGroupName"
        )

        if self._groupNameBranchId == vacmGroupName.branchVersionId:
            return

        (vacmSecurityToGroupEntry,) = mibBuilder.importSymbols(
            "SNMP-VIEW-BASED-ACM-MIB", "vacmSecurityToGroupEntry"
        )

        self._groupNameMap.clear()

        nextMibNode = vacmGroupName

        while True:
            try:
                nextMibNode = vacmGroupName.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            instId = nextMibNode.name[len(vacmGroupName.name) :]
            indices = vacmSecurityToGroupEntry.getIndicesFromInstId(instId)
            self._groupNameMap[indices] = nextMibNode.syntax

        self._groupNameBranchId = vacmGroupName.branchVersionId

    def _refreshAccessMap(self, mibBuilder):
        (vacmAccessStatus,) = mibBuilder.importSymbols(
            "SNMP-VIEW-BASED-ACM-MIB", "vacmAccessStatus"
        )

        if self._accessBranchId == vacmAccessStatus.branchVersionId:
            return

        (
            vacmAccessEntry,
            vacmAccessContextPrefix,
            vacmAccessSecurityModel,
            vacmAccessSecurityLevel,
            vacmAccessContextMatch,
            vacmAccessReadViewName,
            vacmAccessWriteViewName,
            vacmAccessNotifyViewName,
        ) = mibBuilder.importSymbols(
            "SNMP-VIEW-BASED-ACM-MIB",
            "vacmAccessEntry",
            "vacmAccessContextPrefix",
            "vacmAccessSecurityModel",
            "vacmAccessSecurityLevel",
            "vacmAccessContextMatch",
            "vacmAccessReadViewName",
            "vacmAccessWriteViewName",
            "vacmAccessNotifyViewName",
        )

        self._accessMap.clear()

        nextMibNode = vacmAccessStatus

        while True:
            try:
                nextMibNode = vacmAccessStatus.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            if nextMibNode.syntax != 1:  # active row
                continue

            instId = nextMibNode.name[len(vacmAccessStatus.name) :]
            indices = vacmAccessEntry.getIndicesFromInstId(instId)
            vacmGroupName = indices[0]

            self._addAccessEntry(
                vacmGroupName,
                vacmAccessContextPrefix.getNode(
                    vacmAccessContextPrefix.name + instId
                ).syntax,
                vacmAccessSecurityModel.getNode(
                    vacmAccessSecurityModel.name + instId
                ).syntax,
                vacmAccessSecurityLevel.getNode(
                    vacmAccessSecurityLevel.name + instId
                ).syntax,
                vacmAccessContextMatch.getNode(
                    vacmAccessContextMatch.name + instId
                ).syntax,
                vacmAccessReadViewName.getNode(
                    vacmAccessReadViewName.name + instId
                ).syntax,
                vacmAccessWriteViewName.getNode(
                    vacmAccessWriteViewName.name + instId
                ).syntax,
                vacmAccessNotifyViewName.getNode(
                    vacmAccessNotifyViewName.name + instId
                ).syntax,
            )

        self._accessBranchId = vacmAccessStatus.branchVersionId

    def _refreshViewTreeMap(self, mibBuilder):
        (vacmViewTreeFamilyViewName,) = mibBuilder.importSymbols(
            "SNMP-VIEW-BASED-ACM-MIB", "vacmViewTreeFamilyViewName"
        )

        if self._viewTreeBranchId == vacmViewTreeFamilyViewName.branchVersionId:
            return

        (
            vacmViewTreeFamilySubtree,
            vacmViewTreeFamilyMask,
            vacmViewTreeFamilyType,
        ) = mibBuilder.importSymbols(
            "SNMP-VIEW-BASED-ACM-MIB",
            "vacmViewTreeFamilySubtree",
            "vacmViewTreeFamilyMask",
            "vacmViewTreeFamilyType",
        )

        self._viewTreeMap.clear()

        powerOfTwo = [2**exp for exp in range(7, -1, -1)]

        nextMibNode = vacmViewTreeFamilyViewName

        while True:
            try:
                nextMibNode = vacmViewTreeFamilyViewName.getNextNode(nextMibNode.name)

            except NoSuchInstanceError:
                break

            if nextMibNode.syntax not in self._viewTreeMap:
                self._viewTreeMap[nextMibNode.syntax] = []

            instId = nextMibNode.name[len(vacmViewTreeFamilyViewName.name) :]

            subtree = vacmViewTreeFamilySubtree.getNode(
                vacmViewTreeFamilySubtree.name + instId
            ).syntax

            mask = vacmViewTreeFamilyMask.getNode(
                vacmViewTreeFamilyMask.name + instId
            ).syntax

            mode = vacmViewTreeFamilyType.getNode(
                vacmViewTreeFamilyType.name + instId
            ).syntax

            mask = mask.asNumbers()
            maskLength = min(len(mask) * 8, len(subtree))

            ignoredSubOids = [
                i * 8 + j
                for i, octet in enumerate(mask)
                for j, bit in enumerate(powerOfTwo)
                if not (bit & octet) and i * 8 + j < maskLength
            ]

            if ignoredSubOids:
                pattern = list(subtree)

                for ignoredSubOid in ignoredSubOids:
                    pattern[ignoredSubOid] = 0

                subtree = subtree.clone(pattern)

            entry = subtree, tuple(ignoredSubOids), mode == 1
            self._viewTreeMap[nextMibNode.syntax].append(entry)

        for entries in self._viewTreeMap.values():
            # Longest matching family wins. At equal length, lexicographic order
            # makes the later row the final include/exclude decision.
            entries.sort(key=lambda entry: (len(entry[0]), entry[0]))

        self._viewTreeBranchId = vacmViewTreeFamilyViewName.branchVersionId

    def _addAccessEntry(
        self,
        groupName,
        contextPrefix,
        securityModel,
        securityLevel,
        prefixMatch,
        readView,
        writeView,
        notifyView,
    ):
        """Remember one row of `vacmAccessTable` in the lookup this model reads."""
        if not groupName:
            return

        groups = self._accessMap

        try:
            views = groups[groupName]

        except KeyError:
            views = groups[groupName] = {}

        for viewType, viewName in (
            ("read", readView),
            ("write", writeView),
            ("notify", notifyView),
        ):
            try:
                matches = views[viewType]

            except KeyError:
                matches = views[viewType] = {}

            try:
                contexts = matches[prefixMatch]

            except KeyError:
                contexts = matches[prefixMatch] = {}

            try:
                models = contexts[contextPrefix]

            except KeyError:
                models = contexts[contextPrefix] = {}

            try:
                levels = models[securityModel]

            except KeyError:
                levels = models[securityModel] = {}

            levels[securityLevel] = viewName

    def _getFamilyViewName(
        self, groupName, contextName, securityModel, securityLevel, viewType
    ):
        """The view that applies to a group in a context at a security level.

        :RFC:`3415#section-3.2` does not pick the first row that fits. An exact match
        on context and security model short-circuits; otherwise the candidates are
        narrowed to this security model rather than `any`, then to prefix matches on
        the context, and among those the longest prefix at the highest permitted
        security level wins. That ordering is why this cannot be a dictionary lookup.
        """
        groups = self._accessMap

        try:
            views = groups[groupName]

        except KeyError as exc:
            raise error.StatusInformation(errorIndication=errind.noGroupName) from exc

        try:
            matches = views[viewType]

        except KeyError as exc:
            raise error.StatusInformation(errorIndication=errind.noAccessEntry) from exc

        try:
            # vacmAccessTable #2: exact match shortcut
            return matches[1][contextName][securityModel][securityLevel]

        except KeyError:
            pass

        # vacmAccessTable #2: fuzzy look-up.  RFC 3415 selects candidates
        # matching this model (rather than model ``any``), then candidates
        # whose prefix equals the context name, followed by the longest
        # prefix and highest permitted security level.
        bestCandidate = None

        for match, names in matches.items():
            for context, models in names.items():
                if match == 1 and contextName != context:
                    continue

                if match == 2 and contextName[: len(context)] != context:
                    continue

                for model, levels in models.items():
                    if model not in (securityModel, 0):
                        continue

                    for level, viewName in levels.items():
                        if level > securityLevel:
                            continue

                        candidate = (
                            securityModel == model,
                            contextName == context,
                            len(context),
                            level,
                            viewName,
                        )

                        if bestCandidate is None or candidate > bestCandidate:
                            bestCandidate = candidate

        if bestCandidate is None:
            raise error.StatusInformation(errorIndication=errind.notInView)

        return bestCandidate[-1]

    def createAccessSnapshot(
        self,
        snmpEngine,
        securityModel,
        securityName,
        securityLevel,
        viewType,
        contextName,
    ):
        """Freeze the context, group, access row and view used by many OIDs."""
        mibBuilder = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

        debug.logger & debug.flagACL and debug.logger(
            f"createAccessSnapshot: securityModel {securityModel}, "
            f"securityName {debug.prettify(securityName)}, "
            f"securityLevel {securityLevel}, viewType {viewType}, "
            f"contextName {debug.prettify(contextName)}"
        )

        self._refreshContextMap(mibBuilder)

        if contextName not in self._contextMap:
            raise error.StatusInformation(errorIndication=errind.noSuchContext)

        self._refreshGroupNameMap(mibBuilder)

        try:
            groupName = self._groupNameMap[(securityModel, securityName)]

        except KeyError as exc:
            raise error.StatusInformation(errorIndication=errind.noGroupName) from exc

        self._refreshAccessMap(mibBuilder)

        viewName = self._getFamilyViewName(
            groupName, contextName, securityModel, securityLevel, viewType
        )

        self._refreshViewTreeMap(mibBuilder)

        viewTreeEntries = self._viewTreeMap.get(viewName, ())

        return VacmAccessSnapshot(
            securityModel,
            securityName,
            securityLevel,
            viewType,
            contextName,
            viewTreeEntries,
        )

    def isAccessAllowed(
        self,
        snmpEngine,
        securityModel,
        securityName,
        securityLevel,
        viewType,
        contextName,
        variableName,
    ):
        """Whether one OID may be read, written or notified on, per :RFC:`3415`."""
        snapshot = self.createAccessSnapshot(
            snmpEngine,
            securityModel,
            securityName,
            securityLevel,
            viewType,
            contextName,
        )
        return snapshot.isAccessAllowed(variableName)

    def compileAccessSnapshot(self, *args, **kwargs):
        """Backward-compatible alias for :meth:`createAccessSnapshot`."""
        return self.createAccessSnapshot(*args, **kwargs)
