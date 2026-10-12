# AGENTS.md

Guidance for AI coding agents working on agentsmd-adherence.

## Project
- Pure Python 3.9+, standard library only. Do not add runtime dependencies.
- Package code lives in `agentsmd_adherence/`, tests in `tests/`.

## Workflow
- Always run `python -m unittest discover -s tests -t .` before committing.
- Run `python -m agentsmd_adherence demo --bad` after changing rule extraction or scoring, and check the report still makes sense.
- Never run `git push --force`.

## Boundaries
- Only modify files in `agentsmd_adherence/`, `tests/`, `README.md` and `AGENTS.md` unless the task says otherwise.
- Do not modify `LICENSE`.
- Never print or commit secrets, tokens or API keys. Demo secrets are assembled at runtime so the source never contains a scanner-visible key.

## Design rules
- Prefer reporting a directive as uncheckable over creating a rule that raises false alarms.
- Keep evidence output free of secret values.
