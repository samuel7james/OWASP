from owasp_inspector.modules.csrf.patterns import CSRF_ERROR_RE, SUCCESS_RE


def test_success_re_matches_explicit_success_phrases():
    assert SUCCESS_RE.search("Your password changed successfully")
    assert SUCCESS_RE.search('{"success": true}')
    assert SUCCESS_RE.search("Your profile updated")


def test_success_re_does_not_match_unsuccessful_negation():
    # Regression: the legacy pattern list included a bare r'success', which
    # is a literal substring of "unsuccessful" — a page saying the action
    # failed would still "match" a success indicator.
    assert not SUCCESS_RE.search("Update unsuccessful, please try again")
    assert not SUCCESS_RE.search("Your request was not successfully changed")


def test_success_re_does_not_match_email_with_negation_between():
    # Regression: r'email.*updated' with an unbounded wildcard would match
    # straight through a negation word sitting between "email" and "updated".
    assert not SUCCESS_RE.search("Your email address was not updated")
    assert not SUCCESS_RE.search("email update failed")


def test_success_re_matches_email_updated_without_negation():
    assert SUCCESS_RE.search("Your email address has been updated")


def test_csrf_error_re_matches_common_rejection_text():
    assert CSRF_ERROR_RE.search("403 Forbidden: invalid CSRF token")
    assert CSRF_ERROR_RE.search("Request Forgery detected")
