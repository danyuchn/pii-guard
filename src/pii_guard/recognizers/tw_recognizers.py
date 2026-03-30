"""Factory for all Taiwan-specific PII recognizers."""

from __future__ import annotations

from presidio_analyzer import EntityRecognizer

from pii_guard.recognizers.tw_business_recognizer import TwBusinessIdRecognizer
from pii_guard.recognizers.tw_id_recognizer import (
    TwArcRecognizer,
    TwNationalIdRecognizer,
    TwPassportRecognizer,
)
from pii_guard.recognizers.tw_misc_recognizers import TwCreditCardRecognizer, TwEmailRecognizer
from pii_guard.recognizers.tw_phone_recognizer import TwLandlineRecognizer, TwMobileRecognizer


def get_all_tw_recognizers() -> list[EntityRecognizer]:
    """Return all Taiwan-specific recognizer instances."""
    return [
        TwNationalIdRecognizer(),
        TwArcRecognizer(),
        TwPassportRecognizer(),
        TwMobileRecognizer(),
        TwLandlineRecognizer(),
        TwBusinessIdRecognizer(),
        TwEmailRecognizer(),
        TwCreditCardRecognizer(),
    ]


# All entity types provided by Taiwan recognizers
TW_ENTITY_TYPES: list[str] = [
    "TW_NATIONAL_ID",
    "TW_ARC",
    "TW_PASSPORT",
    "TW_MOBILE",
    "TW_LANDLINE",
    "TW_BUSINESS_ID",
    "EMAIL_ADDRESS",
    "CREDIT_CARD",
]
