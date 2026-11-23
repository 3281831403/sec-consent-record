"""Consent records with revocation propagation, version gates and expiry gates.

The module is deliberately a specification skeleton: all eight public functions
are unimplemented stubs. Times are caller-supplied seconds since the epoch;
there is no clock read and no randomness. Every temporal comparison is exact:
the tolerance is 0, including propagation acknowledgements and expiry.

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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


def version_ok(record, required) -> bool:
    """Return True only when the record version is at least the required one.

    Versions are compared component-wise as integers, not as strings or
    prefixes. Missing trailing components count as zero, so 1.0 satisfies 1.0.0
    and 1.0.0 satisfies 1.0, but 1.0 does not satisfy 1.0.1 and 1.9 does not
    satisfy 1.10. required=None means no version requirement and returns True.
    A missing, empty, or malformed version on either side returns False.
    """
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError


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
    raise NotImplementedError