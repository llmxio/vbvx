# Contribution Harness

## Commit Messages

- Use short conventional-style subjects such as `fix: ...` and `refactor: ...`.
- Keep commit messages imperative and scoped.

## Pull Requests

Pull requests should include:

- The behavior change.
- Test commands run.
- Related issues, when any.
- Any layout or ABI-impacting header changes.
- Generated documentation updates only when docs output is intentionally part
  of the change.

## Agent Rules

- Do not run Git commands that modify history, the index, or branches unless
  the user explicitly requests them.
- Keep root `AGENTS.md` as an index and maintain detailed rules in the
  matching `docs/harness-*.md` file.
