from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SourceLineMap:
    lines: list[str]

    @classmethod
    def from_text(cls, text: str) -> "SourceLineMap":
        return cls(lines=text.splitlines())

    def get_line(self, line_1_based: int) -> str:
        idx = max(1, line_1_based) - 1
        if idx < 0 or idx >= len(self.lines):
            return ""
        return self.lines[idx]

