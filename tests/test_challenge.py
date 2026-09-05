from yunohost_nostr_auth.auth.challenge import ChallengeStore


def test_challenge_is_single_use():
    store = ChallengeStore()
    challenge = store.issue(domain="example.org", action="yunohost-login")

    assert store.consume(challenge.nonce) is not None
    assert store.consume(challenge.nonce) is None


def test_unknown_nonce_is_rejected():
    store = ChallengeStore()
    assert store.consume("does-not-exist") is None
