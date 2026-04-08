from __future__ import annotations

import os
import pathlib
import re
from typing import Iterable

from clang import cindex

from app.analyzers.common import SourceLineMap
from app.models import Finding, Location


def _configure_libclang_if_needed() -> None:
    """
    Best-effort configuration:
    - If user sets LIBCLANG_FILE, we use it.
    - Else if LIBCLANG_PATH is set, we point to it.
    - Else, rely on default discovery.
    """

    # 1) Explicit env wins.
    lib_file = os.environ.get("LIBCLANG_FILE")
    if lib_file:
        cindex.Config.set_library_file(lib_file)
        return

    lib_path = os.environ.get("LIBCLANG_PATH")
    if lib_path:
        cindex.Config.set_library_path(lib_path)
        return

    # 2) If installed via `pip install libclang`, use the bundled libclang.
    try:
        import clang  # type: ignore

        native = pathlib.Path(clang.__file__).resolve().parent / "native"
        candidate = native / "libclang.dylib"
        if candidate.exists():
            cindex.Config.set_library_file(str(candidate))
            return
    except Exception:
        pass


_DANGEROUS_CALLS: dict[str, dict[str, object]] = {
    "strcpy": {
        "rule_id": "C_CXX.STRCPY",
        "title": "Copie non bornée via strcpy",
        "severity": "high",
        "cwe": ["CWE-120", "CWE-121", "CWE-122"],
        "message": "Appel à strcpy() sans vérification de taille.",
    },
    "strcat": {
        "rule_id": "C_CXX.STRCAT",
        "title": "Concaténation non bornée via strcat",
        "severity": "high",
        "cwe": ["CWE-120", "CWE-121", "CWE-122"],
        "message": "Appel à strcat() sans vérification de taille.",
    },
    "gets": {
        "rule_id": "C_CXX.GETS",
        "title": "Lecture non bornée via gets",
        "severity": "high",
        "cwe": ["CWE-120", "CWE-121"],
        "message": "gets() est intrinsèquement dangereux (aucune limite de taille).",
    },
    "sprintf": {
        "rule_id": "C_CXX.SPRINTF",
        "title": "Écriture potentiellement non bornée via sprintf",
        "severity": "high",
        "cwe": ["CWE-120", "CWE-121", "CWE-122"],
        "message": "sprintf() peut écrire au-delà du buffer destination.",
    },
    "vsprintf": {
        "rule_id": "C_CXX.VSPRINTF",
        "title": "Écriture potentiellement non bornée via vsprintf",
        "severity": "high",
        "cwe": ["CWE-120", "CWE-121", "CWE-122"],
        "message": "vsprintf() peut écrire au-delà du buffer destination.",
    },
}


def _iter_cursors(root: cindex.Cursor) -> Iterable[cindex.Cursor]:
    stack = [root]
    while stack:
        cur = stack.pop()
        yield cur
        try:
            stack.extend(list(cur.get_children()))
        except Exception:
            continue


def _cursor_location(cur: cindex.Cursor) -> Location | None:
    loc = cur.location
    if not loc or not loc.file:
        # Unsaved / macro expansions can land here; we still try to report line/col.
        if loc and loc.line and loc.column:
            return Location(line=max(1, loc.line), column=max(1, loc.column))
        return None
    return Location(file=str(loc.file), line=max(1, loc.line), column=max(1, loc.column))


def _is_stack_array_decl(expr: cindex.Cursor) -> bool:
    """
    Heuristique: si l'argument est un DeclRefExpr vers un VarDecl dont le type est ConstantArray.
    """
    try:
        if expr.kind != cindex.CursorKind.DECL_REF_EXPR:
            return False
        ref = expr.referenced
        if not ref:
            return False
        if ref.kind != cindex.CursorKind.VAR_DECL:
            return False
        t = ref.type
        return t.kind == cindex.TypeKind.CONSTANTARRAY
    except Exception:
        return False


def analyze_c_cpp(code: str, language: str) -> list[Finding]:
    _configure_libclang_if_needed()

    idx = cindex.Index.create()
    srcmap = SourceLineMap.from_text(code)

    args = ["-fsyntax-only"]
    if language == "c":
        args += ["-x", "c", "-std=c11"]
    else:
        args += ["-x", "c++", "-std=c++17"]

    tu = idx.parse(
        path="input",
        args=args,
        unsaved_files=[("input", code)],
        options=(
            cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
            | cindex.TranslationUnit.PARSE_INCOMPLETE
        ),
    )

    findings: list[Finding] = []

    # Index des tableaux locaux de taille fixe: name -> size
    fixed_arrays: dict[str, int] = {}
    for cur in _iter_cursors(tu.cursor):
        if cur.kind != cindex.CursorKind.VAR_DECL:
            continue
        try:
            t = cur.type
            if t.kind == cindex.TypeKind.CONSTANTARRAY:
                # clang: get_array_size() existe sur le type ConstantArray
                size = int(t.get_array_size())  # type: ignore[attr-defined]
                name = (cur.spelling or "").strip()
                if name and size > 0:
                    fixed_arrays[name] = size
        except Exception:
            continue

    def _extract_int_literal(expr: cindex.Cursor) -> int | None:
        try:
            if expr.kind == cindex.CursorKind.INTEGER_LITERAL:
                tokens = [t.spelling for t in expr.get_tokens()]
                if tokens:
                    return int(tokens[0], 0)
        except Exception:
            return None
        return None

    def _is_var_ref(expr: cindex.Cursor, name: str) -> bool:
        try:
            if expr.kind == cindex.CursorKind.DECL_REF_EXPR:
                return (expr.spelling or "").strip() == name
        except Exception:
            return False
        return False

    def _find_oob_in_forstmt(for_cur: cindex.Cursor) -> Finding | None:
        """
        Heuristique ciblée: détecte le pattern
          char buffer[N];
          for (i = 0; i <= N; i++) buffer[i] = ...

        Si condition i <= N et buffer taille N -> écriture 1 octet hors limites (index N).
        """
        loc = _cursor_location(for_cur)
        if not loc:
            return None

        # On récupère la ligne du for() et on essaye d’identifier "i <= <const>"
        for_line = srcmap.get_line(loc.line)
        if "<=" not in for_line:
            return None

        m = re.search(r"\bfor\s*\(\s*([A-Za-z_]\w*)\s*=\s*\d+\s*;\s*\1\s*<=\s*(\d+)\s*;", for_line)
        if not m:
            return None
        idx_var = m.group(1)
        bound = int(m.group(2))

        # Cherche dans le corps une écriture buffer[idx_var] = ...
        body_text = "\n".join(srcmap.get_line(i) for i in range(loc.line, loc.line + 20))
        for arr_name, arr_size in fixed_arrays.items():
            if bound == arr_size and re.search(rf"\b{re.escape(arr_name)}\s*\[\s*{re.escape(idx_var)}\s*\]\s*=", body_text):
                line = srcmap.get_line(loc.line).strip()
                return Finding(
                    rule_id="C_CXX.LOOP.OOB.WRITE",
                    title="Écriture hors limites dans une boucle",
                    severity="high",
                    cwe=["CWE-121", "CWE-122", "CWE-120"],
                    message=f"Boucle avec condition `{idx_var} <= {bound}` sur `{arr_name}[{arr_size}]` (index {arr_size} hors limites).",
                    explanation=(
                        f"Le tableau `{arr_name}` a une taille {arr_size}, donc les indices valides sont 0..{arr_size-1}. "
                        f"Avec `{idx_var} <= {bound}`, la boucle peut écrire à l’index {arr_size}, ce qui dépasse le buffer."
                    ),
                    location=loc,
                    snippet=line or None,
                    trace=[
                        {"kind": "source", "detail": "borne de boucle (condition <=)", "location": loc.model_dump()},
                        {"kind": "sink", "detail": f"écriture {arr_name}[{idx_var}] potentiellement hors limites"},
                    ],
                )
        return None

    # Détection OOB dans boucles `for`
    for cur in _iter_cursors(tu.cursor):
        if cur.kind == cindex.CursorKind.FOR_STMT:
            f = _find_oob_in_forstmt(cur)
            if f:
                findings.append(f)

    for cur in _iter_cursors(tu.cursor):
        if cur.kind != cindex.CursorKind.CALL_EXPR:
            continue

        callee = None
        try:
            callee = cur.displayname.split("(")[0]
        except Exception:
            callee = cur.spelling or cur.displayname
        callee = (callee or "").strip()
        if callee not in _DANGEROUS_CALLS and callee not in ("memcpy", "memmove", "snprintf", "strncpy"):
            continue

        loc = _cursor_location(cur)
        if not loc:
            continue

        line = srcmap.get_line(loc.line)
        snippet = line.strip() if line else None

        # Extract arguments cursors (best-effort; sometimes libclang omits children on parse errors)
        args_cursors = list(cur.get_arguments()) if hasattr(cur, "get_arguments") else []

        if callee in _DANGEROUS_CALLS:
            meta = _DANGEROUS_CALLS[callee]
            dest_hint = ""
            if args_cursors:
                dest_hint = " La destination semble être un tableau de taille fixe." if _is_stack_array_decl(args_cursors[0]) else ""

            findings.append(
                Finding(
                    rule_id=str(meta["rule_id"]),
                    title=str(meta["title"]),
                    severity=str(meta["severity"]),  # type: ignore[arg-type]
                    cwe=list(meta["cwe"]),  # type: ignore[arg-type]
                    message=str(meta["message"]),
                    explanation=(
                        f"{meta['message']}{dest_hint} "
                        "Sans borne explicite, la taille copiée/écrite peut dépasser la capacité du buffer."
                    ),
                    location=loc,
                    snippet=snippet,
                    trace=[
                        {"kind": "sink", "detail": f"appel à {callee}()", "location": loc.model_dump()},
                        {"kind": "note", "detail": "analyse statique heuristique (fichier seul, sans build context)"},
                    ],
                )
            )
            continue

        # Heuristiques supplémentaires
        if callee == "strncpy":
            # Peut être safe ou non; on alerte si l’argument n°3 n’est pas clairement sizeof(dest)-1
            dest_name = None
            if args_cursors:
                try:
                    dest_name = args_cursors[0].spelling or args_cursors[0].displayname
                except Exception:
                    dest_name = None
            dest_name = (dest_name or "").strip() or None
            if not dest_name and snippet:
                m = re.search(r"\bstrncpy\s*\(\s*([A-Za-z_]\w*)\s*,", snippet)
                if m:
                    dest_name = m.group(1)

            # Heuristique simple: si on voit une terminaison explicite du style
            #   dest[sizeof(dest)-1] = 0 / '\0';
            # juste après l'appel, on baisse fortement le signal.
            tail_lines = "\n".join(srcmap.get_line(i) for i in range(loc.line + 1, loc.line + 4))
            has_explicit_nul = False
            if dest_name:
                pat = re.compile(
                    rf"\b{re.escape(dest_name)}\s*\[\s*sizeof\s*\(\s*{re.escape(dest_name)}\s*\)\s*-\s*1\s*\]\s*=\s*(0|'\\0')\s*;"
                )
                has_explicit_nul = bool(pat.search(tail_lines))

            severity = "low" if has_explicit_nul else "medium"
            cwe = ["CWE-120", "CWE-121", "CWE-122"]
            msg = (
                "strncpy(): vérifier la borne et la terminaison NUL."
                if has_explicit_nul
                else "strncpy() peut laisser le buffer non terminé ou tronquer sans terminaison NUL."
            )
            expl = (
                "Une terminaison explicite a été repérée juste après l'appel, ce qui réduit le risque. "
                "Confirmer que la borne passée à strncpy() correspond bien à la capacité du buffer."
                if has_explicit_nul
                else "Même si strncpy() borne la copie, elle ne garantit pas la terminaison NUL si la source est trop longue. "
                "Ajouter/valider la terminaison explicite et vérifier la borne."
            )
            findings.append(
                Finding(
                    rule_id="C_CXX.STRNCPY.CHECK",
                    title="Usage de strncpy à vérifier",
                    severity=severity,
                    cwe=cwe,
                    message=msg,
                    explanation=expl,
                    location=loc,
                    snippet=snippet,
                    trace=[{"kind": "sink", "detail": "appel à strncpy()", "location": loc.model_dump()}],
                )
            )
            continue

        if callee in ("memcpy", "memmove"):
            severity = "medium"
            cwe = ["CWE-120", "CWE-121", "CWE-122", "CWE-190"]
            msg = f"{callee}() dépend d'une taille (3e argument) potentiellement incorrecte."
            expl = (
                "Si la taille est dérivée d'une entrée ou d'un calcul pouvant déborder (integer overflow), "
                "ou si elle dépasse la capacité de la destination, cela peut provoquer un overflow."
            )
            findings.append(
                Finding(
                    rule_id=f"C_CXX.{callee.upper()}.SIZE",
                    title=f"Taille de copie à vérifier ({callee})",
                    severity=severity,
                    cwe=cwe,
                    message=msg,
                    explanation=expl,
                    location=loc,
                    snippet=snippet,
                    trace=[{"kind": "sink", "detail": f"appel à {callee}()", "location": loc.model_dump()}],
                )
            )
            continue

        if callee == "snprintf":
            # généralement safe si size = sizeof(dest); mais on ne peut pas être sûr sans dataflow
            findings.append(
                Finding(
                    rule_id="C_CXX.SNPRINTF.REVIEW",
                    title="snprintf: vérifier la taille passée",
                    severity="low",
                    cwe=["CWE-120", "CWE-121", "CWE-122"],
                    message="snprintf() est plus sûr que sprintf(), mais dépend de la taille fournie.",
                    explanation=(
                        "Confirmer que le 2e argument est la capacité réelle du buffer destination "
                        "(ex: sizeof(dest)) et que la valeur de retour est gérée si nécessaire."
                    ),
                    location=loc,
                    snippet=snippet,
                    trace=[{"kind": "sink", "detail": "appel à snprintf()", "location": loc.model_dump()}],
                )
            )

    return findings

