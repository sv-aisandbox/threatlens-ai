# ADR 0001 - Toolchain and pinned versions

- Status: Accepted
- Date: 2026-11-15

## Context
The project spans a Java backend, a Python intelligence service and MCP servers, and a web frontend, developed on Windows 11 with Docker for shared infrastructure. Everyone (and CI) needs the same toolchain.

## Decision
| Area | Choice | Pin |
|---|---|---|
| Java | JDK 21 (Temurin, LTS) | Major 21; exact patch recorded when installed |
| Build (Java) | Maven via the Maven Wrapper (`mvnw`) | Wrapper version committed with `backend/` |
| Python | 3.12 or newer | `.python-version` and `requires-python` set when the service is scaffolded |
| Python packaging | uv | Lockfile (`uv.lock`) committed |
| Node | Current LTS | `.nvmrc` / `engines` set when the frontend is scaffolded |
| Node packaging | pnpm | `packageManager` field and lockfile committed |
| Containers | Docker Desktop (WSL 2, at least 8 GB RAM) | Image tags pinned in `docker-compose.yml` (never `latest`) |
| Git | `core.autocrlf=input`, repo enforces LF via `.gitattributes` | - |

Exact patch versions are recorded in each component's own lockfile or wrapper when it is scaffolded, so they are verified against what is actually installed.

## Consequences
- Reproducible builds; CI mirrors these versions.
- Upgrading a major version requires a new ADR.

## Status of local installation (2026-11-15)
Installed: Git, GitHub CLI, Python 3.13. Not yet installed: JDK 21, uv, Node LTS, pnpm, Docker Desktop. These are needed from Module 02 onward (Docker) and Modules 03 to 09.
