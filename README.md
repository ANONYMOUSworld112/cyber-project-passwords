# cyber-project-passwords

A fully offline, multi-user cybersecurity platform with a strict
authentication model. Every byte stays on your machine. Nothing is
uploaded, nothing is shared, nothing phones home.

The default command starts an interactive shell (REPL). Inside the
REPL, all data is decrypted in memory. To see data you must unlock the
vault with your password. Locking the session, exiting, or starting a
new process requires you to log in again.

## Features

- **Local credential vault** — store passwords, notes, URLs.
- **Incident tracker** — record and close security incidents.
- **File integrity monitor (FIM)** — hash a directory tree, then
  detect added/removed/changed files.
- **Local hash database** — import a list of SHA-256 hashes, look up
  a file or hash, all offline.
- **Log analyzer** — summarize syslog / leveled / key=value log files
  and store the runs inside the encrypted vault.

## Security model

- **Argon2id** key derivation (`m = 64 MiB, t = 3, p = 1` floor).
- **AES-256-GCM** for at-rest encryption of all sensitive files.
- **Passwords, recovery answers, vault contents, FIM baselines, hash
  databases, log runs, and incidents** are all sealed inside per-user
  encrypted files (`vault.enc`).
- **No key on disk.** The derived key lives in process memory only.
  It is wiped on lock, on exit, and on signal.
- **No master password, no admin bypass, no cloud backup, no
  telemetry.** If both the password and the hint answer are
  forgotten, the data is permanently inaccessible.
- **Single-viewer lock.** A lock file (`lock.json`) prevents more
  than one `csp` REPL from being active at a time. A stale lock can
  only be removed with `csp lock --force`.
- **Per-user progressive lockout** after 5 / 10 / 20 failed attempts.
- **Atomic file writes** (write-temp + rename) and owner-only
  permissions (`0600` on POSIX) on every sensitive file.
- **Decoy-resistant design**: the hint answer is hashed with its own
  Argon2id; the vault is encrypted with the password-derived key.
  Knowing the answer alone is *not* enough to decrypt the vault.

## Data directory

Resolved by `platformdirs`. Override with `CSP_DATA_DIR=/some/path`.

- Windows: `%LOCALAPPDATA%\cyber-project-passwords\`
- Linux: `$XDG_DATA_HOME/cyber-project-passwords/`
- macOS: `~/Library/Application Support/cyber-project-passwords/`

Layout:

```
master.json         # user list (no secrets)
lock.json           # active session lock (no secrets)
lockout.json        # per-user failed-attempt counter (no secrets)
users/<name>/
  profile_pw.enc    # sealed profile
  hint_pub.enc      # sealed hint question / answer hash
  vault.enc         # all user data
hashdb/sources.json # non-sensitive import metadata
```

## Install and run

```bash
pip install -e .[dev]
python -m cspcsp
```

The first launch detects an empty data directory and starts the
first-time setup wizard. After that, every launch requires a login.

## Commands

### One-shot (no unlock required)

- `csp setup` — first-time setup wizard.
- `csp recover` — reset a password via the hint question/answer.
- `csp lock --force` — clear a stale lock from a crashed process.
- `csp reset` — wipe all local data (requires typing `WIPE`).
- `csp --version` / `csp --help`

### Inside the REPL

```
login <user>          # prompts for password; acquires the process lock
lock                  # wipe in-memory key, return to login prompt
switch <user>         # lock + login as another user
passwd                # change current user's password
whoami
status
user list | add | remove <name>
vault add | list | get | edit | delete | genpw
incident add | list | get | edit | close
fim baseline <path>
fim scan [path]
fim watch add | remove | list
hashdb import <file> [malicious|clean]
hashdb lookup <sha256|file>
hashdb sources
logs analyze <file>
logs runs
export                # intentionally disabled; prints explanation
exit | quit | Ctrl-D
```

## Recovery policy

If you forget your password, run `csp recover` and answer your hint
question. The hint answer is verified, then you can set a new
password. **The previous vault contents cannot be recovered** because
the vault was encrypted with the old password-derived key, which we
no longer have. The vault is reset to empty under the new password.

If you forget both the password and the hint answer, the data is
permanently inaccessible. There is no recovery. Use `csp reset` to
wipe everything and start over.

## Tests

```bash
PYTHONPATH=src python -m pytest tests/
```

The tests use `CSP_DATA_DIR` to redirect to a temporary directory; no
test ever touches your real data.

## License

MIT
