from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Language(str, Enum):
    c = "c"
    cpp = "cpp"
    python = "python"


Severity = Literal["low", "medium", "high"]


class Location(BaseModel):
    file: str = "input"
    line: int = Field(ge=1)
    column: int = Field(ge=1)


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    cwe: list[str] = Field(default_factory=list)
    message: str
    explanation: str
    location: Location
    snippet: str | None = None
    trace: list[dict[str, Any]] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    language: Language
    code: str


class AnalyzeResponse(BaseModel):
    language: Language
    findings: list[Finding]
    html_report: str
