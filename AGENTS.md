# AGENTS.md - development guide

## Setup

```bash
# Install dependencies
pip install argon2-cffi cryptography platformdirs

# Install the package in editable mode
pip install -e .
```

## Lint / typecheck

This project intentionally has no third-party linter config. Run
`python -c "import csp; import csp.auth; import csp.features; import csp.web; import csp.cli"` to verify imports.

## Run from source

```bash
PYTHONPATH=src python -m csp
```

Opens the web interface at `http://127.0.0.1:8899`. The first visit
runs the setup wizard in the browser. After that, every visit requires
a login.

## Coding conventions

- No third-party runtime deps beyond `argon2-cffi`, `cryptography`,
  `platformdirs`.
- All file writes go through `csp.io_utils.atomic_write`.
- All sensitive file writes are followed by `csp.io_utils.fs_perms.private_file`.
- All errors inherit from `csp.errors.CSPError`.
- No comments in code unless the user explicitly asks.
- No emojis.

## Project layout

```
src/csp/
  cli.py            # argparse entry; starts the web server
  paths.py          # cross-platform data directory
  errors.py
  crypto/           # kdf, aead, vault_file, memzero
  auth/             # users, session, lockout, recovery, login, vault_store
  features/         # vault, incidents, fim, hashdb, logs
  web/              # HTTP server, REST API, static SPA frontend
  io_utils/         # atomic_write, fs_perms
```
