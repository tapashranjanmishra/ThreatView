from types import SimpleNamespace

from app.models import IOCType, ThreatType
from app.services.alert_engine import threat_matches_rule


def make_threat(
    *,
    ioc_type=IOCType.URL,
    threat_type=ThreatType.PHISHING,
    source="openphish",
    country=None,
    industry=None,
    confidence_score=None,
):
    return SimpleNamespace(
        ioc_type=ioc_type,
        threat_type=threat_type,
        source=source,
        country=country,
        industry=industry,
        confidence_score=confidence_score,
    )


def make_rule(conditions):
    return SimpleNamespace(conditions=conditions)


def test_empty_rule_matches_any_threat():
    threat = make_threat()

    rule = make_rule({})

    assert threat_matches_rule(threat, rule) is True


def test_threat_type_matches():
    threat = make_threat(
        threat_type=ThreatType.PHISHING,
    )

    rule = make_rule({
        "threat_type": "phishing",
    })

    assert threat_matches_rule(threat, rule) is True


def test_threat_type_does_not_match():
    threat = make_threat(
        threat_type=ThreatType.PHISHING,
    )

    rule = make_rule({
        "threat_type": "malware",
    })

    assert threat_matches_rule(threat, rule) is False


def test_ioc_type_matches():
    threat = make_threat(
        ioc_type=IOCType.URL,
    )

    rule = make_rule({
        "ioc_type": "url",
    })

    assert threat_matches_rule(threat, rule) is True


def test_ioc_type_does_not_match():
    threat = make_threat(
        ioc_type=IOCType.URL,
    )

    rule = make_rule({
        "ioc_type": "ip",
    })

    assert threat_matches_rule(threat, rule) is False


def test_source_matching_is_case_insensitive():
    threat = make_threat(
        source="OpenPhish",
    )

    rule = make_rule({
        "source": "openphish",
    })

    assert threat_matches_rule(threat, rule) is True


def test_country_matches_case_insensitively():
    threat = make_threat(
        country="IN",
    )

    rule = make_rule({
        "country": "in",
    })

    assert threat_matches_rule(threat, rule) is True


def test_missing_country_does_not_match_country_rule():
    threat = make_threat(
        country=None,
    )

    rule = make_rule({
        "country": "IN",
    })

    assert threat_matches_rule(threat, rule) is False


def test_industry_matches_case_insensitively():
    threat = make_threat(
        industry="Finance",
    )

    rule = make_rule({
        "industry": "finance",
    })

    assert threat_matches_rule(threat, rule) is True


def test_missing_industry_does_not_match_industry_rule():
    threat = make_threat(
        industry=None,
    )

    rule = make_rule({
        "industry": "finance",
    })

    assert threat_matches_rule(threat, rule) is False


def test_minimum_confidence_matches():
    threat = make_threat(
        confidence_score=85,
    )

    rule = make_rule({
        "min_confidence_score": 70,
    })

    assert threat_matches_rule(threat, rule) is True


def test_minimum_confidence_rejects_lower_score():
    threat = make_threat(
        confidence_score=65,
    )

    rule = make_rule({
        "min_confidence_score": 70,
    })

    assert threat_matches_rule(threat, rule) is False


def test_missing_confidence_does_not_match_minimum_confidence():
    threat = make_threat(
        confidence_score=None,
    )

    rule = make_rule({
        "min_confidence_score": 70,
    })

    assert threat_matches_rule(threat, rule) is False


def test_multiple_conditions_must_all_match():
    threat = make_threat(
        ioc_type=IOCType.URL,
        threat_type=ThreatType.PHISHING,
        source="openphish",
    )

    rule = make_rule({
        "ioc_type": "url",
        "threat_type": "phishing",
        "source": "openphish",
    })

    assert threat_matches_rule(threat, rule) is True


def test_multiple_conditions_fail_when_one_condition_does_not_match():
    threat = make_threat(
        ioc_type=IOCType.URL,
        threat_type=ThreatType.PHISHING,
        source="openphish",
    )

    rule = make_rule({
        "ioc_type": "url",
        "threat_type": "malware",
        "source": "openphish",
    })

    assert threat_matches_rule(threat, rule) is False