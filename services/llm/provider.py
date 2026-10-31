from __future__ import annotations

from typing import Protocol

from services.llm.schemas import RiskAnalysis, RiskAnalysisContext


class AnalysisProvider(Protocol):
    async def analyze(self, context: RiskAnalysisContext) -> RiskAnalysis:
        """Return explanatory text only; implementations cannot enforce decisions."""
