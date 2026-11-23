"""Contract tests for engine.privacy.consent.

Ten tests map to the ten seeded defects; five additional tests cover the
healthy-path requirements. All times are explicit. The tests must fail while
the eight public functions remain stubs.
"""

import pytest

from engine.privacy import consent

NOW = 1_700_000_000

POLICY = {
    "default_allow": False,
    "max_age": 3600,
    "require_propagation_ack": True,
    "min_version": "1.0",
}


def new_store():
    return {"consents": {}, "downstream": {}, "propagations": []}


def event(action, user, purpose, *, version="2.0", at=NOW, acks=None):
    value = {
        "user": user,
        "purpose": purpose,
        "action": action,
        "version": version,
        "at": at,
    }
    if acks is not None:
        value["acks"] = dict(acks)
    return value


# Defect 1: absence of a record must not act as consent.
def test_missing_consent_defaults_to_deny():
    store = new_store()
    assert consent.granted(store, "nobody", "ads", NOW) is False


# Defect 2: withdrawal must record when it happened, not just a status flag.
def test_withdraw_writes_withdrawn_at():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)
    result = consent.withdraw(store, "alice", "ads", NOW + 15)
    stored = store["consents"][("alice", "ads")]

    assert result["withdrawn_at"] == NOW + 15
    assert stored["withdrawn_at"] == NOW + 15
    assert stored["status"] == "withdrawn"
    assert stored["granted_at"] == NOW

    with pytest.raises(KeyError):
        consent.withdraw(new_store(), "ghost", "ads", NOW)


# Defect 3: a withdrawal must reach downstream state, not leave a stale grant.
def test_withdraw_propagates_to_downstream():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)
    first = consent.propagate(
        store,
        event("grant", "alice", "ads", acks={"billing": NOW + 1}),
        ["billing"],
    )
    assert first["complete"] is True

    consent.withdraw(store, "alice", "ads", NOW + 10)
    second = consent.propagate(
        store,
        event("withdraw", "alice", "ads", at=NOW + 10, acks={"billing": NOW + 11}),
        ["billing"],
    )

    snapshot = store["downstream"]["billing"][("alice", "ads")]
    assert second["complete"] is True
    assert snapshot["status"] == "withdrawn"
    assert snapshot["withdrawn_at"] == NOW + 10
    assert snapshot["confirmed_at"] == NOW + 11


# Defect 4: missing or invalid target acknowledgements must not be ignored.
def test_propagation_requires_each_target_ack():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)
    consent.withdraw(store, "alice", "ads", NOW + 10)
    stale = {"status": "granted", "version": "1.0", "confirmed_at": NOW}
    store["downstream"]["crm"] = {("alice", "ads"): dict(stale)}

    result = consent.propagate(
        store,
        event(
            "withdraw",
            "alice",
            "ads",
            at=NOW + 10,
            acks={"billing": NOW + 10, "crm": None},
        ),
        ["billing", "crm", "erp"],
    )

    assert result["complete"] is False
    assert result["confirmed"] == ["billing"]
    assert result["unconfirmed"] == ["crm", "erp"]
    assert store["downstream"]["crm"][("alice", "ads")] == stale
    assert ("alice", "ads") not in store["downstream"].get("erp", {})


# Defect 5: version checks must compare numeric components, not prefixes.
def test_version_comparison_is_not_prefix_based():
    assert consent.version_ok({"version": "1.10"}, "1.9") is True
    assert consent.version_ok({"version": "1.0"}, "1.0.1") is False
    assert consent.version_ok({"version": "1.0.1"}, "1.0.10") is False
    assert consent.version_ok({"version": "2.0.0"}, "2.0") is True


# Defect 6: a record for an older version cannot satisfy a raised requirement.
def test_old_consent_not_valid_after_version_upgrade():
    store = new_store()
    store["policy"] = dict(POLICY, min_version="2.0")

    old = consent.record(store, "alice", "ads", "1.9.9", NOW)
    assert old["version"] == "1.9.9"
    assert consent.granted(store, "alice", "ads", NOW + 1) is False

    fresh = consent.record(store, "alice", "ads", "2.0", NOW + 10)
    assert fresh["granted_at"] == NOW + 10
    assert fresh["confirmed_at"] == NOW + 10
    assert consent.granted(store, "alice", "ads", NOW + 11) is True


# Defect 7: a policy without max_age must not make consent permanent.
def test_missing_expiry_is_not_permanent():
    store = new_store()
    stored = consent.record(store, "alice", "ads", "2.0", NOW)
    policy = {"default_allow": False, "require_propagation_ack": True}

    assert "missing_expiry" in consent.validate_policy(policy)
    assert consent.expiry_ok(stored, NOW + 10**9, policy) is False


# Defect 8: expiry must run from the last confirmation, not first creation.
def test_expiry_uses_last_confirmation_not_creation():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)
    consent.record(store, "alice", "ads", "2.0", NOW + 50)
    stored = store["consents"][("alice", "ads")]

    assert stored["granted_at"] == NOW
    assert stored["confirmed_at"] == NOW + 50
    assert consent.expiry_ok(stored, NOW + 120, {"max_age": 100}) is True
    assert consent.expiry_ok(stored, NOW + 150, {"max_age": 100}) is False


# Defect 9: policy validation must reject a default-allow posture.
def test_policy_validation_flags_default_allow():
    allow_by_default = {
        "default_allow": True,
        "max_age": 3600,
        "require_propagation_ack": True,
    }
    missing_key = {"max_age": 3600, "require_propagation_ack": True}

    assert "default_allow" in consent.validate_policy(allow_by_default)
    assert "default_allow" in consent.validate_policy(missing_key)
    assert "default_allow" not in consent.validate_policy(POLICY)
    assert consent.validate_policy(POLICY) == []


# Defect 10: batch state must not leak from one user to the next.
def test_batch_does_not_reuse_consent_between_users():
    alice_store = new_store()
    bob_store = new_store()
    events = [
        {
            "action": "record",
            "user": "alice",
            "purpose": "ads",
            "version": "2.0",
            "at": NOW,
            "store": alice_store,
        },
        {
            "action": "granted",
            "user": "bob",
            "purpose": "ads",
            "at": NOW,
            "store": bob_store,
        },
    ]

    result = consent.consent_batch(events, POLICY, NOW)

    assert result["ok"] is True
    assert result["results"][0]["allowed"] is True
    assert result["results"][0]["record"]["user"] == "alice"
    assert result["results"][1]["allowed"] is False


# Additional test 11: a live grant is readable.
def test_granted_consent_can_read():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)
    assert consent.granted(store, "alice", "ads", NOW) is True


# Additional test 12: unconsented users and purposes are denied.
def test_unconsented_user_is_denied_by_default():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)

    assert consent.granted(store, "bob", "ads", NOW) is False
    assert consent.granted(store, "alice", "payments", NOW) is False


# Additional test 13: revocation takes effect at the withdrawal instant.
def test_withdrawal_takes_effect_immediately():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)
    consent.withdraw(store, "alice", "ads", NOW + 1)

    assert consent.granted(store, "alice", "ads", NOW + 1) is False


# Additional test 14: every acknowledged downstream target sees the withdrawal.
def test_withdrawal_reaches_all_downstream_targets():
    store = new_store()
    consent.record(store, "alice", "ads", "2.0", NOW)
    consent.withdraw(store, "alice", "ads", NOW + 10)
    targets = ["billing", "crm", "erp"]

    result = consent.propagate(
        store,
        event(
            "withdraw",
            "alice",
            "ads",
            at=NOW + 10,
            acks={target: NOW + 11 for target in targets},
        ),
        targets,
    )

    assert result["complete"] is True
    assert result["confirmed"] == targets
    assert result["unconfirmed"] == []
    for target in targets:
        snapshot = store["downstream"][target][("alice", "ads")]
        assert snapshot["status"] == "withdrawn"
        assert snapshot["withdrawn_at"] == NOW + 10


# Additional test 15: a combined batch equals the two independently run batches.
def test_two_batches_match_individual_processing():
    events = []
    for user in ("alice", "bob"):
        events.append(
            {
                "action": "record",
                "user": user,
                "purpose": "ads",
                "version": "2.0",
                "at": NOW,
                "store": new_store(),
            }
        )

    combined = consent.consent_batch(events, POLICY, NOW)
    separate = [
        consent.consent_batch([events[0]], POLICY, NOW)["results"][0],
        consent.consent_batch([events[1]], POLICY, NOW)["results"][0],
    ]

    assert combined["results"] == separate
    assert combined["results"][0]["record"]["user"] == "alice"
    assert combined["results"][1]["record"]["user"] == "bob"
    assert events[0]["store"]["consents"] == {}
    assert events[1]["store"]["consents"] == {}