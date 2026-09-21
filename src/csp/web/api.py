from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional, Tuple

from csp.auth import (
    list_users,
    user_exists,
    add_user_to_master,
    remove_user,
    first_run,
)
from csp.auth.login import unlock
from csp.auth.lockout import check_lock, clear_lockout
from csp.auth.password_check import (
    password_strength_score,
    validate_password,
    validate_username,
)
from csp.auth.recovery import (
    RecoveryContext,
    complete_recovery,
    start_recovery,
    write_initial_blobs,
)
from csp.auth.users import load_master
from csp.auth.vault_store import load_vault, save_vault
from csp.crypto.kdf import derive_key_with_params, make_kdf_params
from csp.crypto.memzero import SecretBuffer
from csp.crypto.vault_file import read_vault_file, write_vault_file
from csp.errors import CSPError
from csp.features import (
    add_credential,
    add_incident,
    close_incident,
    delete_credential,
    fim_baseline,
    fim_scan,
    fim_watch_add,
    fim_watch_list,
    fim_watch_remove,
    generate_password,
    get_credential,
    get_incident,
    hash_file,
    hashdb_import,
    hashdb_list_sources,
    hashdb_lookup,
    list_credentials,
    list_incidents,
    list_log_runs,
    logs_analyze,
    search_credentials,
    update_credential,
    update_incident,
)
from csp.paths import data_dir, profile_pw_file, vault_file

from csp.web.session import (
    create_session,
    destroy_session,
    get_session,
    wipe_all as wipe_all_sessions,
)

_ROUTES: Dict[Tuple[str, str], Callable] = {}


def route(method: str, path: str):
    def decorator(fn):
        _ROUTES[(method, path)] = fn
        return fn
    return decorator


def _require_auth(handler: BaseHTTPRequestHandler) -> Any:
    token = _get_token(handler)
    if token is None:
        handler._send_json({"error": "not authenticated"}, 401)
        return None
    sess = get_session(token)
    if sess is None:
        handler._send_json({"error": "session expired"}, 401)
        return None
    return sess


def _get_token(handler: BaseHTTPRequestHandler) -> Optional[str]:
    cookie = handler.headers.get("Cookie", "")
    for part in cookie.split(";"):
        part = part.strip()
        if part.startswith("csp_session="):
            return part[12:]
    return None


def _cookie_set(token: str) -> str:
    return f"csp_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=86400"


def _cookie_clear() -> str:
    return "csp_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"


def _read_body(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        handler._send_json({"error": f"invalid JSON body: {e}"}, 400)
        return None


def _send(handler: BaseHTTPRequestHandler, data: Any, status: int = 200, headers: Optional[dict] = None) -> None:
    handler._send_json(data, status, headers)


def _error(handler: BaseHTTPRequestHandler, msg: str, status: int = 400) -> None:
    handler._send_json({"error": msg}, status)


def _handle_csp_error(handler: BaseHTTPRequestHandler, fn: Callable) -> None:
    try:
        fn()
    except CSPError as e:
        _error(handler, str(e))


# ---- Setup ----

@route("GET", "/api/setup/status")
def handle_setup_status(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    m = load_master()
    _send(handler, {"first_run": m.first_run or not m.users, "users": m.users})


@route("POST", "/api/setup")
def handle_setup(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if not first_run():
        _error(handler, "setup already completed", 403)
        return
    data = _read_body(handler)
    if data is None:
        return
    username = data.get("username", "")
    password = data.get("password", "")
    question = data.get("hint_question", "")
    answer = data.get("hint_answer", "")
    err = validate_username(username)
    if err:
        _error(handler, err)
        return
    if user_exists(username):
        _error(handler, "username already exists")
        return
    err = validate_password(password, username)
    if err:
        _error(handler, err)
        return
    if not question.strip():
        _error(handler, "hint question must not be empty")
        return
    if not answer.strip():
        _error(handler, "hint answer must not be empty")
        return
    try:
        write_initial_blobs(username, password, question.strip(), answer)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, {"status": "ok", "username": username})


# ---- Auth ----

@route("POST", "/api/login")
def handle_login(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    data = _read_body(handler)
    if data is None:
        return
    username = data.get("username", "")
    password = data.get("password", "")
    try:
        session, _ = unlock(username, password)
    except CSPError as e:
        _error(handler, "invalid username or password", 401)
        return
    token = create_session(session)
    _send(handler, {"status": "ok", "user": username}, headers={"Set-Cookie": _cookie_set(token)})


@route("POST", "/api/logout")
def handle_logout(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    token = _get_token(handler)
    if token:
        destroy_session(token)
    _send(handler, {"status": "ok"}, headers={"Set-Cookie": _cookie_clear()})


@route("GET", "/api/status")
def handle_status(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    token = _get_token(handler)
    if token is None:
        _send(handler, {"user": None})
        return
    sess = get_session(token)
    if sess is None:
        _send(handler, {"user": None})
        return
    _send(handler, {"user": sess.user})


@route("POST", "/api/passwd")
def handle_passwd(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    sess = _require_auth(handler)
    if sess is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    old = data.get("old_password", "")
    new = data.get("new_password", "")
    from csp.auth.login import _read_kdf_from_profile_pw
    kdf = _read_kdf_from_profile_pw(sess.user)
    old_buf = SecretBuffer(derive_key_with_params(old, kdf))
    try:
        try:
            read_vault_file(profile_pw_file(sess.user), old_buf.get())
        except CSPError:
            _error(handler, "current password is incorrect")
            return
        try:
            payload = read_vault_file(vault_file(sess.user), old_buf.get())
        except CSPError:
            _error(handler, "failed to read existing vault")
            return
    finally:
        old_buf.wipe()
    err = validate_password(new, sess.user)
    if err:
        _error(handler, err)
        return
    new_kdf = make_kdf_params()
    new_buf = SecretBuffer(derive_key_with_params(new, new_kdf))
    try:
        write_vault_file(
            profile_pw_file(sess.user),
            {"v": 1, "kind": "profile_pw"},
            new_kdf,
            new_buf.get(),
        )
        write_vault_file(
            vault_file(sess.user),
            payload,
            new_kdf,
            new_buf.get(),
        )
    finally:
        new_buf.wipe()
    sess.key.wipe()
    sess.kdf = new_kdf
    sess.key = SecretBuffer(derive_key_with_params(new, new_kdf))
    sess._vault_cache = payload
    _send(handler, {"status": "ok"})


# ---- Users ----

@route("GET", "/api/users")
def handle_list_users(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    _send(handler, list_users())


@route("POST", "/api/users")
def handle_add_user(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    username = data.get("username", "")
    password = data.get("password", "")
    question = data.get("hint_question", "")
    answer = data.get("hint_answer", "")
    err = validate_username(username)
    if err:
        _error(handler, err)
        return
    if user_exists(username):
        _error(handler, "username already exists")
        return
    err = validate_password(password, username)
    if err:
        _error(handler, err)
        return
    if not question.strip():
        _error(handler, "hint question must not be empty")
        return
    if not answer.strip():
        _error(handler, "hint answer must not be empty")
        return
    try:
        write_initial_blobs(username, password, question.strip(), answer)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, {"status": "ok", "username": username})


@route("DELETE", "/api/users/{name}")
def handle_remove_user(handler: BaseHTTPRequestHandler, parts: List[str]) -> None:
    sess = _require_auth(handler)
    if sess is None:
        return
    name = parts[3]
    if name not in list_users():
        _error(handler, f"unknown user: {name}", 404)
        return
    if name == sess.user:
        _error(handler, "cannot remove the currently logged-in user")
        return
    remove_user(name)
    _send(handler, {"status": "ok"})


# ---- Recovery ----

@route("POST", "/api/recovery/start")
def handle_recovery_start(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    data = _read_body(handler)
    if data is None:
        return
    username = data.get("username", "")
    answer = data.get("answer", "")
    if not user_exists(username):
        _error(handler, f"unknown user: {username}", 404)
        return
    try:
        ctx = start_recovery(username, answer)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, {"hint_question": ctx.hint_question})


@route("POST", "/api/recovery/complete")
def handle_recovery_complete(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    data = _read_body(handler)
    if data is None:
        return
    username = data.get("username", "")
    answer = data.get("answer", "")
    new_password = data.get("new_password", "")
    if not user_exists(username):
        _error(handler, f"unknown user: {username}", 404)
        return
    try:
        ctx = RecoveryContext(username=username, hint_question="")
        complete_recovery(ctx, answer, new_password)
    except CSPError as e:
        _error(handler, str(e))
        return
    clear_lockout(username)
    _send(handler, {"status": "ok"})


# ---- System reset ----

@route("POST", "/api/reset")
def handle_reset(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    data = _read_body(handler)
    if data is None:
        return
    if data.get("confirm") not in ("RESET", "WIPE"):
        _error(handler, "confirmation required: confirm='RESET'", 400)
        return
    import shutil
    d = data_dir()
    errors = []
    for child in d.iterdir():
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink()
        except OSError as e:
            errors.append(str(e))
    wipe_all_sessions()
    from csp.auth.session import set_session
    set_session(None)
    _send(handler, {"status": "ok", "errors": errors})


# ---- Vault ----

@route("GET", "/api/vault/credentials")
def handle_vault_list(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(handler.path).query)
    query = qs.get("search", [None])[0]
    show_pw = qs.get("show_passwords", ["false"])[0] == "true"
    items = search_credentials(query) if query else list_credentials()
    if not show_pw:
        items = [{k: v for k, v in c.items() if k != "password"} for c in items]
    _send(handler, items)


@route("POST", "/api/vault/credentials")
def handle_vault_add(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    try:
        cred = add_credential(
            data.get("title", ""),
            data.get("username", ""),
            data.get("password", ""),
            data.get("url", ""),
            data.get("notes", ""),
        )
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, cred, 201)


@route("GET", "/api/vault/credentials/{id}")
def handle_vault_get(handler: BaseHTTPRequestHandler, parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    try:
        cred = get_credential(parts[3])
    except CSPError as e:
        _error(handler, str(e), 404)
        return
    _send(handler, cred)


@route("PUT", "/api/vault/credentials/{id}")
def handle_vault_update(handler: BaseHTTPRequestHandler, parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    try:
        cred = update_credential(
            parts[3],
            title=data.get("title"),
            username=data.get("username"),
            password=data.get("password"),
            url=data.get("url"),
            notes=data.get("notes"),
        )
    except CSPError as e:
        _error(handler, str(e), 404)
        return
    _send(handler, cred)


@route("DELETE", "/api/vault/credentials/{id}")
def handle_vault_delete(handler: BaseHTTPRequestHandler, parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    try:
        delete_credential(parts[3])
    except CSPError as e:
        _error(handler, str(e), 404)
        return
    _send(handler, {"status": "ok"})


@route("GET", "/api/vault/genpw")
def handle_vault_genpw(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(handler.path).query)
    length_s = qs.get("length", ["20"])[0]
    try:
        length = int(length_s)
    except ValueError:
        _error(handler, "length must be an integer")
        return
    try:
        pw = generate_password(length)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, {"password": pw})


# ---- Incidents ----

@route("GET", "/api/incidents")
def handle_incident_list(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(handler.path).query)
    open_only = qs.get("open_only", ["false"])[0] == "true"
    items = list_incidents(include_closed=not open_only)
    _send(handler, items)


@route("POST", "/api/incidents")
def handle_incident_add(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    try:
        inc = add_incident(
            data.get("title", ""),
            data.get("severity", "med"),
            data.get("notes", ""),
        )
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, inc, 201)


@route("GET", "/api/incidents/{id}")
def handle_incident_get(handler: BaseHTTPRequestHandler, parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    try:
        inc = get_incident(parts[2])
    except CSPError as e:
        _error(handler, str(e), 404)
        return
    _send(handler, inc)


@route("PUT", "/api/incidents/{id}")
def handle_incident_update(handler: BaseHTTPRequestHandler, parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    try:
        inc = update_incident(
            parts[2],
            title=data.get("title"),
            severity=data.get("severity"),
            notes=data.get("notes"),
        )
    except CSPError as e:
        _error(handler, str(e), 404)
        return
    _send(handler, inc)


@route("POST", "/api/incidents/{id}/close")
def handle_incident_close(handler: BaseHTTPRequestHandler, parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    try:
        inc = close_incident(parts[2])
    except CSPError as e:
        _error(handler, str(e), 404)
        return
    _send(handler, inc)


# ---- FIM ----

@route("POST", "/api/fim/baseline")
def handle_fim_baseline(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    root = data.get("path", "")
    if not root:
        _error(handler, "path is required")
        return
    try:
        res = fim_baseline(root)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, res)


@route("POST", "/api/fim/scan")
def handle_fim_scan(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    try:
        res = fim_scan(data.get("path"))
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, res)


@route("GET", "/api/fim/watches")
def handle_fim_watch_list(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    _send(handler, fim_watch_list())


@route("POST", "/api/fim/watches")
def handle_fim_watch_add(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    path = data.get("path", "")
    if not path:
        _error(handler, "path is required")
        return
    try:
        fim_watch_add(path)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, {"status": "ok"})


@route("DELETE", "/api/fim/watches")
def handle_fim_watch_remove(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    path = data.get("path", "")
    if not path:
        _error(handler, "path is required")
        return
    try:
        fim_watch_remove(path)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, {"status": "ok"})


# ---- HashDB ----

@route("POST", "/api/hashdb/import")
def handle_hashdb_import(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    path = data.get("path", "")
    kind = data.get("label_kind", "malicious")
    if not path:
        _error(handler, "path is required")
        return
    try:
        res = hashdb_import(path, kind)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, res)


@route("GET", "/api/hashdb/lookup")
def handle_hashdb_lookup(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    from urllib.parse import urlparse, parse_qs
    qs = parse_qs(urlparse(handler.path).query)
    target = qs.get("hash", [None])[0]
    if target is None:
        file_path = qs.get("file", [None])[0]
        if file_path is None:
            _error(handler, "provide ?hash=... or ?file=...")
            return
        try:
            target = hash_file(file_path)
        except CSPError as e:
            _error(handler, str(e))
            return
    try:
        res = hashdb_lookup(target)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, res)


@route("GET", "/api/hashdb/sources")
def handle_hashdb_sources(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    _send(handler, hashdb_list_sources())


# ---- Logs ----

@route("POST", "/api/logs/analyze")
def handle_logs_analyze(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    data = _read_body(handler)
    if data is None:
        return
    path = data.get("path", "")
    if not path:
        _error(handler, "path is required")
        return
    try:
        summary = logs_analyze(path)
    except CSPError as e:
        _error(handler, str(e))
        return
    _send(handler, summary)


@route("GET", "/api/logs/runs")
def handle_logs_runs(handler: BaseHTTPRequestHandler, _parts: List[str]) -> None:
    if _require_auth(handler) is None:
        return
    _send(handler, list_log_runs())


# ---- Router ----

def dispatch(handler: BaseHTTPRequestHandler, method: str, parts: List[str]) -> bool:
    path = "/" + "/".join(parts) if parts else "/"
    token = _get_token(handler)
    sess = get_session(token) if token else None
    from csp.auth.session import bind_session
    with bind_session(sess):
        for (m, pattern), fn in _ROUTES.items():
            if m != method:
                continue
            pattern_parts = pattern.strip("/").split("/")
            if len(pattern_parts) != len(parts):
                continue
            match = True
            for i, (pp, ap) in enumerate(zip(pattern_parts, parts)):
                if pp.startswith("{") and pp.endswith("}"):
                    continue
                if pp != ap:
                    match = False
                    break
            if match:
                fn(handler, parts)
                return True
        return False
