from __future__ import annotations

import ast

from app.analyzers.common import SourceLineMap
from app.models import Finding, Location


_CTYPES_SINKS = {
    ("ctypes", "memmove"): ("PY.CTYPES.MEMMOVE", "Copie mémoire via ctypes.memmove", "high", ["CWE-120", "CWE-122"]),
    ("ctypes", "memset"): ("PY.CTYPES.MEMSET", "Écriture mémoire via ctypes.memset", "high", ["CWE-120", "CWE-122"]),
    ("ctypes", "string_at"): ("PY.CTYPES.STRING_AT", "Lecture mémoire via ctypes.string_at", "medium", ["CWE-126", "CWE-127"]),
}


def _loc(node: ast.AST) -> Location | None:
    line = getattr(node, "lineno", None)
    col = getattr(node, "col_offset", None)
    if not line or col is None:
        return None
    return Location(line=max(1, int(line)), column=max(1, int(col) + 1))


class _ImportTracker(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: dict[str, str] = {}  # local_name -> fully_qualified module

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.names[alias.asname or alias.name] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for alias in node.names:
            full = f"{mod}.{alias.name}" if mod else alias.name
            self.names[alias.asname or alias.name] = full


def _resolve_call_name(node: ast.Call) -> tuple[str | None, str | None]:
    """
    Retourne (module_or_base, func) pour patterns du style:
    - ctypes.memmove(...)
    - memmove(...) si import direct
    """
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return node.func.value.id, node.func.attr
    if isinstance(node.func, ast.Name):
        return None, node.func.id
    return None, None


def analyze_python(code: str) -> list[Finding]:
    srcmap = SourceLineMap.from_text(code)
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        # On retourne un finding "info" pour expliquer l'échec; utile en UI.
        line = max(1, int(getattr(e, "lineno", 1) or 1))
        col = max(1, int((getattr(e, "offset", 1) or 1)))
        return [
            Finding(
                rule_id="PY.PARSE.ERROR",
                title="Erreur de parsing Python",
                severity="low",
                cwe=[],
                message="Le code Python n'a pas pu être analysé (syntax error).",
                explanation=str(e),
                location=Location(line=line, column=col),
                snippet=srcmap.get_line(line).strip() or None,
                trace=[{"kind": "note", "detail": "corriger la syntaxe pour activer l’analyse"}],
            )
        ]

    imports = _ImportTracker()
    imports.visit(tree)

    findings: list[Finding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        base, func = _resolve_call_name(node)
        loc = _loc(node)
        if not loc or not func:
            continue

        snippet = srcmap.get_line(loc.line).strip() or None

        # ctypes.*
        if base:
            # Map local alias to module if possible (ex: import ctypes as c -> base="c")
            mod = imports.names.get(base, base)
            key = (mod.split(".")[0], func) if "." in mod else (mod, func)
            if key in _CTYPES_SINKS:
                rule_id, title, severity, cwe = _CTYPES_SINKS[key]
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        title=title,
                        severity=severity,  # type: ignore[arg-type]
                        cwe=cwe,
                        message=f"Appel à {base}.{func}() pouvant provoquer des accès mémoire non sûrs.",
                        explanation=(
                            "Les appels ctypes opèrent au niveau mémoire natif. Si les tailles/offsets "
                            "sont incorrects ou contrôlés par une entrée, cela peut provoquer overflow/over-read."
                        ),
                        location=loc,
                        snippet=snippet,
                        trace=[
                            {"kind": "sink", "detail": f"appel à {base}.{func}()", "location": loc.model_dump()},
                            {"kind": "note", "detail": "risque typique via bindings natifs (ctypes)"},
                        ],
                    )
                )
                continue

        # import direct: from ctypes import memmove
        if not base and func in {"memmove", "memset", "string_at"}:
            # Check if this name is imported from ctypes
            full = imports.names.get(func, "")
            if full.startswith("ctypes."):
                # Reuse same mapping
                key = ("ctypes", func)
                if key in _CTYPES_SINKS:
                    rule_id, title, severity, cwe = _CTYPES_SINKS[key]
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            title=title,
                            severity=severity,  # type: ignore[arg-type]
                            cwe=cwe,
                            message=f"Appel à {func}() (importé de ctypes) pouvant provoquer des accès mémoire non sûrs.",
                            explanation=(
                                "Les appels ctypes opèrent au niveau mémoire natif. Valider tailles/offsets "
                                "et s'assurer que la destination a la capacité attendue."
                            ),
                            location=loc,
                            snippet=snippet,
                            trace=[{"kind": "sink", "detail": f"appel à {func}()", "location": loc.model_dump()}],
                        )
                    )
                    continue

        # struct.unpack_from / pack_into
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"unpack_from", "pack_into"}:
            # Heuristique: ces APIs dépendent d'un buffer + offset; risques d'over-read/over-write si non contrôlé
            findings.append(
                Finding(
                    rule_id=f"PY.STRUCT.{node.func.attr.upper()}",
                    title=f"struct.{node.func.attr}: vérifier buffer/offset",
                    severity="medium",
                    cwe=["CWE-126", "CWE-127", "CWE-120"],
                    message=f"Appel à struct.{node.func.attr}() pouvant lire/écrire hors limites.",
                    explanation=(
                        "Vérifier que le buffer a une longueur suffisante pour le format demandé "
                        "et que l'offset est borné (len(buffer))."
                    ),
                    location=loc,
                    snippet=snippet,
                    trace=[{"kind": "sink", "detail": f"appel à struct.{node.func.attr}()", "location": loc.model_dump()}],
                )
            )
            continue

        # bytearray / memoryview slicing with user-controlled indices (heuristique légère)
        if isinstance(node.func, ast.Name) and node.func.id in {"bytearray", "memoryview"}:
            findings.append(
                Finding(
                    rule_id="PY.BUFFER.PRIMITIVE.REVIEW",
                    title="Primitives buffer: vérifier tailles/indices",
                    severity="low",
                    cwe=["CWE-126", "CWE-127"],
                    message=f"Usage de {node.func.id}(): vérifier les tailles et indices si données externes.",
                    explanation=(
                        "Python protège contre l’overflow natif, mais des erreurs d’indices/longueurs "
                        "peuvent conduire à over-read/bugs logiques, ou devenir critiques via extensions natives."
                    ),
                    location=loc,
                    snippet=snippet,
                    trace=[{"kind": "note", "detail": "heuristique (signal faible)"}],
                )
            )

    return findings

