from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

# Use the model that is actually installed in this environment instead of
# Presidio's default (en_core_web_lg), which is a ~560 MB download.
NLP_CONFIG = {
    "nlp_engine_name": "spacy",
    "models": [
        {"lang_code": "en", "model_name": "en_core_web_sm"},
    ],
}


class Scanner:
    """
    Detects sensitive entities in text using Microsoft Presidio.
    """

    def __init__(self):
        provider = NlpEngineProvider(nlp_configuration=NLP_CONFIG)
        self.analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())

        self.entities_to_detect = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "PERSON",
        ]

    def scan(self, text: str) -> list[dict]:
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=self.entities_to_detect,
        )

        entities = []

        for result in results:
            entities.append(
                {
                    "entity_type": result.entity_type,
                    "text": text[result.start:result.end],
                    "start": result.start,
                    "end": result.end,
                }
            )

        return entities