# DetectionApp — Détection de risques de buffer overflow

Web app locale (offline) qui analyse **un fichier** en **C/C++** (via **libclang**) ou **Python** (via `ast`) et produit:
- un résultat lisible dans l’UI
- un export **JSON**
- un **rapport HTML**

## Prérequis

- Python 3.10+
- Clang/LLVM installé localement (pour l’analyse C/C++)
  - macOS (Homebrew): `brew install llvm`
  - Ubuntu/Debian: `sudo apt-get install clang libclang-dev`
  - Windows: LLVM installer

### libclang (important)
Le paquet `clang` (bindings Python) a besoin de trouver **libclang**.

Options (au choix):
- Définir la variable d’environnement `LIBCLANG_PATH` vers le dossier qui contient `libclang` / `libclang.dylib` / `libclang.dll`
- Ou définir `LIBCLANG_FILE` vers le fichier exact de la librairie.

Exemple macOS (Homebrew):

```bash
export LIBCLANG_PATH="$(brew --prefix llvm)/lib"
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Lancer

```bash
uvicorn app.main:app --reload --port 8000
```

Puis ouvrir `http://127.0.0.1:8000`.

## Notes
- Le code est analysé “tel quel” (pas de `-I`/`-D` fournis). Les diagnostics de parsing sont tolérés, l’outil essaie quand même d’extraire des appels dangereux.
- Les “traces” sont des explications **heuristiques** (offline, sans build context).

