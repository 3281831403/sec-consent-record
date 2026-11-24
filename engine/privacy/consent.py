"""Consent records with revocation propagation, version gates and expiry gates.

Times are caller-supplied seconds since the epoch; there is no clock read and
no randomness. Every temporal comparison is exact: the tolerance is 0,
including propagation acknowledgements and expiry.

Canonical store shape (callers may begin with an empty dict):

    {
        "consents": {(user, purpose): consent_record},
        "downstream": {target: {(user, purpose): downstream_snapshot}},
        "propagations": [audit_entry, ...],
        "policy": optional_policy_mapping,
    }

A consent_record contains at least:
    user, purpose, version, granted_at, confirmed_at,
    withdrawn_at (None while live), status ("granted" or "withdrawn").
"""

from __future__ import annotations

import copy
import math
import re

_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*$")
_MISSING = object()


# ---------------------------------------------------------------------------
# Small validation helpers
# ---------------------------------------------------------------------------

def _is_number(value) -> bool:
    """True for a real number that is not a boolean."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_finite_number(value) -> bool:
    """True for a finite, non-boolean number."""
    if not _is_number(value):
        return False
    if isinstance(value, int):
        return True
    return math.isfinite(value)


def _parse_version(value):
    """Parse a dotted numeric version into a comparable tuple.

    Trailing zero components are dropped so that 1.0, 1.0.0 and 1 compare
    equal. Returns None when the value is not a dotted numeric string.
    """
    if not isinstance(value, str):
        return None
    if _VERSION_RE.match(value) is None:
        return None
    parts = [int(part) for part in value.split(".")]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _consents(store) -> dict:
    consents = store.get("consents") if isinstance(store, dict) else None
    return consents if isinstance(consents, dict) else {}


def _live_record(store, user, purpose, now):
    """Return the stored record only when it represents live, valid consent."""
    record = _consents(store).get((user, purpose))
    if not isinstance(record, dict):
        return None
    if record.get("status") != "granted":
        return None
    if record.get("withdrawn_at") is not None:
        return None
    if _parse_version(record.get("version")) is None:
        return None
    granted_at = record.get("granted_at")
    if not _is_finite_number(granted_at):
        return None
    if not _is_finite_number(record.get("confirmed_at")):
        return None
    if not _is_finite_number(now):
        return None
    if now < granted_at:
        return None
    return record


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def record(store, user, purpose, version, now) -> dict:
    """Create or refresh the consent record for a user and purpose.

    Version contract:
    - A version is a dotted numeric string such as 1.2.3; comparison is
      component-wise and numeric, with missing trailing components treated as
      zero (1.0 equals 1.0.0, and 1.10 is newer than 1.9).
    - Recording a higher version is a new consent: granted_at and confirmed_at
      both become now, withdrawn_at becomes None, and status becomes granted.
    - Re-recording the same version is a fresh confirmation: confirmed_at
      becomes now while the original granted_at is preserved.
    - Recording a lower version than the live record is rejected with
      ValueError; no silent downgrade is allowed.

    The record is stored at store["consents"][(user, purpose)]. The return value
    is a copy of the stored record so callers cannot mutate internal state
    through it. now must not predate the existing granted_at.
    """
    if not isinstance(store, dict):
        raise ValueError("store must be a mapping")
    if not _is_finite_number(now):
        raise ValueError("now must be a finite number")
    new_version = _parse_version(version)
    if new_version is None:
        raise ValueError("version must be a dotted numeric string")

    consents = store.get("consents")
    if not isinstance(consents, dict):
        consents = {}
        store["consents"] = consents

    existing = consents.get((user, purpose))
    if isinstance(existing, dict):
        existing_version = _parse_version(existing.get("version"))
        if existing_version is None:
            raise ValueError("existing consent version is malformed")
        existing_granted_at = existing.get("granted_at")
        if not _is_finite_number(existing_granted_at):
            raise ValueError("existing consent granted_at is malformed")
        if now < existing_granted_at:
            raise ValueError("now must not predate granted_at")
        if new_version < existing_version:
            raise ValueError("consent version cannot be downgraded")
        if new_version == existing_version:
            # Fresh confirmation of the same version: keep the original grant
            # instant and refresh the last-confirmation instant. A withdrawal
            # is not undone without a new version, so the record stays
            # withdrawn; the confirmation instant is still recorded.
            stored = dict(existing)
            stored["user"] = user
            stored["purpose"] = purpose
            stored["version"] = version
            stored["confirmed_at"] = now
            consents[(user, purpose)] = stored
            return dict(stored)

    stored = {
        "user": user,
        "purpose": purpose,
        "version": version,
        "granted_at": now,
        "confirmed_at": now,
        "withdrawn_at": None,
        "status": "granted",
    }
    consents[(user, purpose)] = stored
    return dict(stored)


def granted(store, user, purpose, now) -> bool:
    """Return whether this user currently has effective consent.

    This function never defaults to allow. False is returned when the store has
    no record for the pair, when the record was withdrawn (withdrawn_at is not
    None or status is not granted), when now predates granted_at, or when the
    record is malformed.

    If store contains a policy, the policy must pass validate_policy and the
    record must satisfy version_ok against policy["min_version"] when that key
    is present and expiry_ok for policy["max_age"]. An invalid policy, a missing
    expiry rule, or an unsatisfied version gate fails closed with False.
    Temporal checks use a tolerance of exactly 0.
    """
    if not isinstance(store, dict):
        return False
    record_value = _live_record(store, user, purpose, now)
    if record_value is None:
        return False

    if "policy" in store:
        policy = store["policy"]
        if validate_policy(policy):
            return False
        required = policy.get("min_version")
        if not version_ok(record_value, required):
            return False
        if not expiry_ok(record_value, now, policy):
            return False

    return True


def withdraw(store, user, purpose, now) -> dict:
    """Withdraw an existing consent and stamp the withdrawal instant.

    The stored record gets withdrawn_at = now and status = "withdrawn" while
    granted_at and confirmed_at remain intact. Returning without a timestamp,
    or only changing a status flag, is not sufficient: downstream systems need
    withdrawn_at to order the withdrawal against their cached data.

    Raises KeyError when no record exists and ValueError when now predates
    granted_at. Withdrawing an already-withdrawn record is idempotent and keeps
    the first withdrawal time. The return value is a copy of the stored record.
    """
    if not isinstance(store, dict):
        raise KeyError((user, purpose))
    consents = store.get("consents")
    stored = consents.get((user, purpose)) if isinstance(consents, dict) else None
    if not isinstance(stored, dict):
        raise KeyError((user, purpose))
    if not _is_finite_number(now):
        raise ValueError("now must be a finite number")
    granted_at = stored.get("granted_at")
    if not _is_finite_number(granted_at):
        raise ValueError("consent granted_at is malformed")
    if now < granted_at:
        raise ValueError("now must not predate granted_at")

    if stored.get("withdrawn_at") is None:
        stored["withdrawn_at"] = now
    stored["status"] = "withdrawn"
    return dict(stored)


def propagate(store, event, targets) -> dict:
    """Propagate a grant or withdrawal to every target, one confirmation each.

    event fields:
        user, purpose, action ("grant" or "withdraw"), version, at,
        acks (optional mapping of target name to confirmation timestamp).

    A target counts as confirmed only when acks[target] is a non-boolean number
    and that timestamp is greater than or equal to event["at"]. Missing, false,
    non-numeric, or earlier acknowledgements leave the target unconfirmed; they
    must never be treated as success. The tolerance is exactly 0 seconds.

    Each confirmed target receives a downstream snapshot at
    store["downstream"][target][(user, purpose)] containing:
        user, purpose, version, status ("granted" or "withdrawn"), event_at,
        confirmed_at, withdrawn_at (the consent record's value for withdrawals,
        otherwise None).
    An unconfirmed target keeps its previous snapshot unchanged. Audit entries
    are appended to store["propagations"].

    Returns:
        {
            "event": {user, purpose, action, version, at},
            "confirmed": [confirmed targets in input order],
            "unconfirmed": [unconfirmed targets in input order],
            "complete": bool(confirmed) and not unconfirmed,
            "downstream": {target: snapshot or None},
        }
    Duplicate target names are processed once, preserving first-seen order.
    Empty targets produce complete False. A malformed event raises ValueError.
    """
    if not isinstance(store, dict):
        raise ValueError("store must be a mapping")
    if not isinstance(event, dict):
        raise ValueError("event must be a mapping")

    user = event.get("user")
    purpose = event.get("purpose")
    action = event.get("action")
    version = event.get("version")
    at = event.get("at")
    if user is None or purpose is None:
        raise ValueError("event must contain user and purpose")
    if action not in ("grant", "withdraw"):
        raise ValueError("action must be 'grant' or 'withdraw'")
    if _parse_version(version) is None:
        raise ValueError("version must be a dotted numeric string")
    if not _is_finite_number(at):
        raise ValueError("at must be a finite number")
    acks = event.get("acks")
    if acks is None:
        acks = {}
    if not isinstance(acks, dict):
        raise ValueError("acks must be a mapping when present")

    if targets is None:
        raise ValueError("targets must be a collection of names")
    if isinstance(targets, str):
        targets = [targets]
    try:
        unique_targets = list(dict.fromkeys(targets))
    except TypeError as exc:
        raise ValueError("targets must be hashable names") from exc

    downstream = store.get("downstream")
    if not isinstance(downstream, dict):
        downstream = {}
        store["downstream"] = downstream
    propagations = store.get("propagations")
    if not isinstance(propagations, list):
        propagations = []
        store["propagations"] = propagations

    if action == "withdraw":
        consent_record = _consents(store).get((user, purpose))
        withdrawn_at = (
            consent_record.get("withdrawn_at")
            if isinstance(consent_record, dict)
            else None
        )
        status = "withdrawn"
    else:
        withdrawn_at = None
        status = "granted"

    confirmed = []
    unconfirmed = []
    returned_downstream = {}

    for target in unique_targets:
        ack = acks.get(target, _MISSING)
        is_confirmed = (
            ack is not _MISSING
            and _is_number(ack)
            and ack >= at
        )
        if is_confirmed:
            snapshot = {
                "user": user,
                "purpose": purpose,
                "version": version,
                "status": status,
                "event_at": at,
                "confirmed_at": ack,
                "withdrawn_at": withdrawn_at,
            }
            target_state = downstream.get(target)
            if not isinstance(target_state, dict):
                target_state = {}
                downstream[target] = target_state
            target_state[(user, purpose)] = dict(snapshot)
            confirmed.append(target)
            returned_downstream[target] = dict(snapshot)
        else:
            # Leave any previous downstream snapshot exactly as it was.
            unconfirmed.append(target)
            returned_downstream[target] = None

        propagations.append(
            {
                "user": user,
                "purpose": purpose,
                "action": action,
                "version": version,
                "at": at,
                "target": target,
                "confirmed": is_confirmed,
                "confirmed_at": ack if is_confirmed else None,
            }
        )

    return {
        "event": {
            "user": user,
            "purpose": purpose,
            "action": action,
            "version": version,
            "at": at,
        },
        "confirmed": confirmed,
        "unconfirmed": unconfirmed,
        "complete": bool(confirmed) and not unconfirmed,
        "downstream": returned_downstream,
    }


def version_ok(record, required) -> bool:
    """Return True only when the record version is at least the required one.

    Versions are compared component-wise as integers, not as strings or
    prefixes. Missing trailing components count as zero, so 1.0 satisfies 1.0.0
    and 1.0.0 satisfies 1.0, but 1.0 does not satisfy 1.0.1 and 1.9 does not
    satisfy 1.10. required=None means no version requirement and returns True.
    A missing, empty, or malformed version on either side returns False.
    """
    if required is None:
        return True
    if not isinstance(record, dict):
        return False
    record_version = _parse_version(record.get("version"))
    required_version = _parse_version(required)
    if record_version is None or required_version is None:
        return False
    return record_version >= required_version


def expiry_ok(record, now, policy) -> bool:
    """Return True only when consent is still unexpired at now.

    The age is measured from record["confirmed_at"], the last confirmation,
    never from granted_at. With policy["max_age"] measured in seconds, validity
    requires confirmed_at <= now and now - confirmed_at < max_age; the exact
    boundary is already expired because the tolerance is exactly 0.

    A missing or malformed confirmed_at, a missing policy, or a max_age that is
    absent, non-numeric, boolean, non-finite, or not positive returns False.
    There is no implicit permanent consent and no grace period.
    """
    if not isinstance(record, dict) or not isinstance(policy, dict):
        return False
    confirmed_at = record.get("confirmed_at")
    if not _is_finite_number(confirmed_at) or not _is_finite_number(now):
        return False
    max_age = policy.get("max_age", _MISSING)
    if max_age is _MISSING or not _is_finite_number(max_age) or max_age <= 0:
        return False
    if confirmed_at > now:
        return False
    return (now - confirmed_at) < max_age


def validate_policy(policy) -> list[str]:
    """Return stable, ordered, de-duplicated problem codes for a policy.

    A usable policy must contain:
        default_allow: exactly False,
        max_age: a finite positive number of seconds,
        require_propagation_ack: exactly True,
        min_version: optional dotted numeric version.

    Problem codes, in this fixed order:
        default_allow              key is absent or is not exactly False
        missing_expiry             max_age is absent, not a finite positive
                                   number, or is a boolean
        missing_propagation_ack    require_propagation_ack is not exactly True

    An empty list means the policy may be used. Any non-empty list must be
    treated as fail-closed by callers.
    """
    problems = []
    is_mapping = isinstance(policy, dict)

    if not is_mapping or policy.get("default_allow") is not False:
        problems.append("default_allow")

    max_age = policy.get("max_age", _MISSING) if is_mapping else _MISSING
    if max_age is _MISSING or not _is_finite_number(max_age) or max_age <= 0:
        problems.append("missing_expiry")

    if not is_mapping or policy.get("require_propagation_ack") is not True:
        problems.append("missing_propagation_ack")

    return problems


def consent_batch(events, policy, now) -> dict:
    """Process consent operations independently and return per-event results.

    Each event is a dict with:
        action: "record", "withdraw", "granted", or "propagate"
        user, purpose: required
        store: this event's own consent store; absent means a fresh empty store
        version: required for record, optional otherwise
        at: required for record, withdraw, and propagate
        targets, acks: required only for propagate

    Every event is evaluated from an independent deep copy of its own store,
    with the supplied policy attached for granted checks. No consent record,
    status, or downstream snapshot may leak from one event to another, and the
    caller's stores are not mutated. In particular, a later user must never hit
    an earlier user's consent for the same purpose.

    Returns:
        {
            "results": [
                {
                    "action": str,
                    "user": str,
                    "purpose": str,
                    "allowed": bool,
                    "record": dict or None,
                    "propagation": dict or None,
                    "error": str or None,
                },
                ...
            ],
            "ok": bool,
        }

    allowed is True for a stored record, False for a withdrawal, the effective
    authorization decision for granted, and the complete flag for propagate.
    A malformed event produces an error result instead of aborting the batch.
    An event processed in a larger batch must produce exactly the same result
    as when processed alone.
    """
    results = []
    for event in events:
        action = event.get("action") if isinstance(event, dict) else None
        user = event.get("user") if isinstance(event, dict) else None
        purpose = event.get("purpose") if isinstance(event, dict) else None
        try:
            outcome = _process_batch_event(event, policy, now)
        except Exception as exc:  # a malformed event must not abort the batch
            outcome = {
                "action": action,
                "user": user,
                "purpose": purpose,
                "allowed": False,
                "record": None,
                "propagation": None,
                "error": str(exc) or exc.__class__.__name__,
            }
        results.append(outcome)

    return {
        "results": results,
        "ok": all(result["error"] is None for result in results),
    }


def _process_batch_event(event, policy, now) -> dict:
    """Evaluate one batch event against a private copy of its store."""
    if not isinstance(event, dict):
        raise ValueError("event must be a mapping")

    action = event.get("action")
    if action not in ("record", "withdraw", "granted", "propagate"):
        raise ValueError("unknown batch action")
    user = event.get("user")
    purpose = event.get("purpose")
    if user is None or purpose is None:
        raise ValueError("event must contain user and purpose")

    source = event.get("store")
    if source is None:
        store = {"consents": {}, "downstream": {}, "propagations": []}
    else:
        if not isinstance(source, dict):
            raise ValueError("store must be a mapping")
        store = copy.deepcopy(source)
    for key, default in (
        ("consents", {}),
        ("downstream", {}),
        ("propagations", []),
    ):
        if not isinstance(store.get(key), type(default)):
            store[key] = type(default)()
    if policy is not None:
        store["policy"] = policy

    result = {
        "action": action,
        "user": user,
        "purpose": purpose,
        "allowed": False,
        "record": None,
        "propagation": None,
        "error": None,
    }

    if action == "record":
        if "version" not in event:
            raise ValueError("version is required for record")
        if "at" not in event:
            raise ValueError("at is required for record")
        result["record"] = record(
            store, user, purpose, event["version"], event["at"]
        )
        result["allowed"] = True

    elif action == "withdraw":
        if "at" not in event:
            raise ValueError("at is required for withdraw")
        result["record"] = withdraw(store, user, purpose, event["at"])
        result["allowed"] = False

    elif action == "granted":
        at = event["at"] if event.get("at") is not None else now
        result["allowed"] = granted(store, user, purpose, at)

    else:  # propagate
        if "at" not in event:
            raise ValueError("at is required for propagate")
        if "targets" not in event:
            raise ValueError("targets is required for propagate")
        at = event["at"]
        if not _is_finite_number(at):
            raise ValueError("at must be a finite number")

        consent_record = _consents(store).get((user, purpose))
        withdrawn = isinstance(consent_record, dict) and (
            consent_record.get("withdrawn_at") is not None
            or consent_record.get("status") == "withdrawn"
        )
        propagation_action = event.get("propagation_action")
        if propagation_action is None:
            propagation_action = "withdraw" if withdrawn else "grant"
        if propagation_action not in ("grant", "withdraw"):
            raise ValueError("propagation action must be 'grant' or 'withdraw'")

        version = event.get("version")
        if version is None and isinstance(consent_record, dict):
            version = consent_record.get("version")
        propagation_event = {
            "user": user,
            "purpose": purpose,
            "action": propagation_action,
            "version": version,
            "at": at,
            "acks": event.get("acks"),
        }
        propagation = propagate(store, propagation_event, event.get("targets"))
        result["propagation"] = propagation
        result["allowed"] = propagation["complete"]

    return result
