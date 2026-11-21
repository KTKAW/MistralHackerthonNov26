# Agent Configuration

## Agent skills

### Issue tracker

Local markdown under `.scratch/` (one feature per directory; spec at `.scratch/<feature>/spec.md`, tickets at `.scratch/<feature>/issues/NN-<slug>.md`). See `docs/agents/issue-tracker.md`.

### Triage labels

The five canonical triage roles, used as `Status:` lines in ticket files: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: `GLOSSARY.md` and `docs/adr/` at the repo root. See `docs/agents/domain.md`.

## Skills

Agent skills live in `.vibe/skills/` (from [mattpocock/skills](https://github.com/mattpocock/skills)). Run `/setup-matt-pocock-skills` to reconfigure the issue tracker, triage labels, or domain doc layout. Update skills by re-copying from the upstream repo.

`.vibe/`, `AGENTS.md`, `docs/agents/` and `.scratch/` are tracked in git and shared with the team.
