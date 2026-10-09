class DecisionEngine:
    """
    Converts a risk level into an enforcement decision.
    """

    def decide(self, risk: str) -> str:
        if risk == "CRITICAL":
            return "BLOCK"

        if risk == "HIGH":
            return "BLOCK"

        if risk == "MEDIUM":
            return "REDACT"

        return "ALLOW"