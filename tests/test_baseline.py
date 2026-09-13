from phantom_hunter.baseline import AllowlistEntry, is_baselined


def test_matches_user_with_no_ip_restriction():
    allowlist = [AllowlistEntry(user="ci-service-account")]
    assert is_baselined("ci-service-account", "10.9.9.9", allowlist)


def test_matches_user_with_matching_ip_prefix():
    allowlist = [AllowlistEntry(user="ci-service-account", ip_prefix="10.0.5.")]
    assert is_baselined("ci-service-account", "10.0.5.20", allowlist)


def test_rejects_matching_user_with_wrong_ip_prefix():
    allowlist = [AllowlistEntry(user="ci-service-account", ip_prefix="10.0.5.")]
    assert not is_baselined("ci-service-account", "203.0.113.9", allowlist)


def test_rejects_unlisted_user():
    allowlist = [AllowlistEntry(user="ci-service-account")]
    assert not is_baselined("attacker", "10.0.5.20", allowlist)


def test_none_user_never_matches():
    allowlist = [AllowlistEntry(user="ci-service-account")]
    assert not is_baselined(None, "10.0.5.20", allowlist)
