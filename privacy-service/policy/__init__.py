import json
from pathlib import Path


class PolicyEngine:
    """
    Applies organization policy to scanner results.
    """

    def __init__(self):
        policy_file = Path(__file__).with_name("policy.json")

        with open(policy_file, "r", encoding="utf-8") as file:
            self.policy = json.load(file)

    def evaluate(self, entities: list[dict]) -> list[dict]:
        rules = self.policy.get("rules", {})
        flagged_entities = []

        for entity in entities:
            entity_type = entity["entity_type"]
            rule = rules.get(entity_type)

            if rule and rule.get("sensitive", False):
                flagged_entities.append(
                    {
                        **entity,
                        "sensitive": True,
                        "label": rule.get("label", entity_type),
                    }
                )

        return flagged_entities