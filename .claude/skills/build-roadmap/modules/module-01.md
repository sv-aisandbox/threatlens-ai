# Module 01 — Repository and workspace (Roadmap Phase 0)

**Duration:** ~½ week · **Checkpoint:** none (foundation) · **Depends on:** nothing
**Goal:** a clean repo Claude Code can work in safely.

## Required MCPs
| MCP | Why | Required? |
|---|---|---|
| GitHub MCP | Create/inspect repo, branch protection, PRs | Recommended (or use `gh` CLI) |
| Filesystem (built-in tools) | Scaffold folders and docs | Built in |

## Accounts / manual actions
- **A1 (you):** GitHub account with 2FA; create repo `threatlens-ai` (private until demo).

## Tasks
- [x] 0.1 **(you)** Create the GitHub repo; clone it; open it in VS Code.
- [x] 0.2 **(Claude)** Create the folder skeleton from spec §11. Only folders that Modules 02–10 use (no empty future-scope modules).
- [x] 0.3 **(Claude)** Move the spec to `docs/PROJECT_SPEC.md`; add `docs/ROADMAP.md`.
- [x] 0.4 **(Claude)** Add `CLAUDE.md` from spec §21.2, plus pointers to the roadmap and the ADR folder.
- [x] 0.5 **(Claude)** Add `.gitignore` (Java, Python, Node, `.env`, IDE files), `.gitattributes` (`* text=auto eol=lf`), `.editorconfig`, `.env.example` (placeholders only).
- [x] 0.6 **(Claude)** `README.md`: purpose, safety boundary, empty "Quick start".
- [x] 0.7 **(Claude)** ADR 0001 — toolchain and pinned versions (JDK 21, Python 3.12+ with uv, Node LTS with pnpm, Maven wrapper).
- [ ] 0.8 **(you)** Enable branch protection on `main` and GitHub secret scanning / push protection.

## Toolchain (Windows 11)
Git (`core.autocrlf=input`), Docker Desktop (WSL 2, ≥ 8 GB RAM), JDK 21 Temurin, Python 3.12+ + uv, Node LTS + pnpm. VS Code extensions per spec §11.

## Best practices for this module
- Never commit `.env` or real keys; commit placeholders only.
- Branch-per-task, small PRs, Conventional Commits.

## Done when
First commit is on `main`, `.env` is ignored, `git status` is clean.
