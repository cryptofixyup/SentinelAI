from pydantic import ValidationError

from services.llm.schemas import RiskAnalysis


class InvalidModelOutput(ValueError):
    """Raised when provider output is absent, malformed, or violates the schema."""


def validate_analysis_json(raw: str) -> RiskAnalysis:
    try:
        return RiskAnalysis.model_validate_json(raw)
    except (ValidationError, ValueError) as exc:
        raise InvalidModelOutput("provider returned invalid risk-analysis JSON") from exc
