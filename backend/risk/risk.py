class RiskEngine:
    """
    Converts policy-flagged entities into a risk level.
    """

    RISK_RULES = {
        "CREDIT_CARD": "CRITICAL",
        "US_SSN": "HIGH",
        "PHONE_NUMBER": "MEDIUM",
        "EMAIL_ADDRESS": "LOW",
        "PERSON": "LOW",
        "IN_AADHAAR": "HIGH",
        "IN_PAN": "HIGH",
        "IN_IFSC": "MEDIUM",
        "CREDENTIAL_TOKEN": "CRITICAL",
    }

    PRIORITY = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    def calculate(self, flagged_entities: list[dict]) -> str:
        if not flagged_entities:
            return "LOW"

        highest_risk = "LOW"

        for entity in flagged_entities:
            entity_type = entity["entity_type"]
            risk = self.RISK_RULES.get(entity_type, "MEDIUM")

            if self.PRIORITY[risk] > self.PRIORITY[highest_risk]:
                highest_risk = risk

        return highest_risk
