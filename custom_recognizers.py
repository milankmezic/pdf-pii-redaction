from presidio_analyzer import PatternRecognizer, Pattern

def get_custom_recognizers():
    return [
        PatternRecognizer(
            supported_entity="US_SSN",
            patterns=[
                Pattern(name="ssn", regex=r"\b\d{3}-\d{2}-\d{4}\b", score=0.85)
            ]
        ),
        PatternRecognizer(
            supported_entity="MEDICAL_RECORD",
            patterns=[
                Pattern(name="mrn", regex=r"\bMRN[- ]?\d{5,}\b", score=0.85)
            ]
        ),
        PatternRecognizer(
            supported_entity="DEVICE_ID",
            patterns=[
                Pattern(name="device_id", regex=r"\b[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\b", score=0.85)
            ]
        ),
        PatternRecognizer(
            supported_entity="LICENSE_PLATE",
            patterns=[
                Pattern(name="plate", regex=r"\b[A-Z]{3}-\d{3,4}\b", score=0.85)
            ]
        ),
        PatternRecognizer(
            supported_entity="FULL_ADDRESS",
            patterns=[
                Pattern(name="address_with_zip", regex=r"\d{1,5} [\w\s]{3,},? [A-Z]{2} \d{5}", score=0.8),
                Pattern(name="address_without_zip", regex=r"\d{1,5} [\w\s]{3,},? [A-Z]{2}", score=0.7),
                Pattern(name="street_address", regex=r"\d{1,5} [\w\s]{3,}", score=0.6),
                Pattern(name="postal_code", regex=r"\b[A-Z]{2} \d{5}\b", score=0.8),
                Pattern(name="postal_code_alt", regex=r"\b\d{5}\b", score=0.6)
            ]
        ),
        PatternRecognizer(
            supported_entity="POSTAL_CODE",
            patterns=[
                Pattern(name="us_zip", regex=r"\b[A-Z]{2} \d{5}\b", score=0.8),
                Pattern(name="us_zip_alt", regex=r"\b\d{5}\b", score=0.6),
                Pattern(name="canada_postal", regex=r"\b[A-Z]\d[A-Z] \d[A-Z]\d\b", score=0.8)
            ]
        )
    ] 