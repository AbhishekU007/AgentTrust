from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List
from pydantic import BaseModel


class ToolCall(BaseModel):
    tool: str
    args: Dict[str, Any]


class LLMOutput(BaseModel):
    calls: List[ToolCall]
    recommend: List[str]


@dataclass
class LLMClient:
    """Simple LLM client interface used by AIRequester and providers."""

    def interpret(self, prompt: str) -> LLMOutput:
        raise NotImplementedError()
