from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from csp.auth import (
    LockoutState,
    clear_lockout,
    get_lockout_state,
    list_users,
    register_failure,
    register_success,
    start_recovery,
    complete_recovery,
    unlock,
    unlock_with_session_install,
    user_exists,
    write_initial_blobs,
)
from csp.auth.session import current_session, set_session
from csp.errors import (
    AuthError,
    LockedOutError,
    UserError,
)
from csp.paths import (
    data_dir,
    lockout_file,
    master_file,
    profile_pw_file,
    user_dir,
    vault_file,
    hint_pub_file,
)


def _bootstrap_user(tmp_data_dir: Path, username: str = "alice", password: str = "Sup3rSecretPw!"):
    write_initial_blobs(
        username=username,
        password=password,
        hint_question="What is my recovery phrase?",
        hint_answer="fluffy unicorn",
    )


# --- users --------------------------------------------------------------


def test_first_run_then_user_exists(tmp_data_dir: Path):
    from csp.auth.users import first_run
    assert first_run() is True
    _bootstrap_user(tmp_data_dir)
    assert first_run() is False
    assert user_exists("alice")


def test_remove_user_wipes_dir(tmp_data_dir: Path):
    _bootstrap_user(tmp_data_dir)
    assert user_dir("alice").exists()
    from csp.auth.users import remove_user
    remove_user("alice")
    assert not user_dir("alice").exists()
    assert not user_exists("alice")


def test_invalid_username_rejected(tmp_data_dir: Path):
    from csp.auth.password_check import validate_username
    assert validate_username("ab") is not None
    assert validate_username("Bad Name!") is not None
    assert validate_username("good_name-1") is None


def test_password_policy(tmp_data_dir: Path):
    from csp.auth.password_check import validate_password
    assert validate_password("short") is not None
    assert validate_password("alllowercase12") is not None
    assert validate_password("GoodPass1234!") is None
    assert validate_password("GoodPass1234!", username="goodpass1234!") is not None


def test_normalize_answer():
    from csp.auth.password_check import normalize_answer
    assert normalize_answer("  Fluffy   UNICORN  ") == "fluffy unicorn"


# --- lockout -------------------------------------------------------------


def test_lockout_thresholds(tmp_data_dir: Path):
    state = LockoutState(fails=0, lock_until=None)
    for _ in range(5):
        state = register_failure("bob")
    assert state.lock_until is not None
    assert state.lock_until > time.time()

    clear_lockout("bob")
    for _ in range(5):
        state = register_failure("bob")
    for _ in range(5):
        state = register_failure("bob")
    assert state.fails == 10
    assert state.lock_until is not None
    assert state.lock_until - time.time() > 1000


def test_lockout_check_raises(tmp_data_dir: Path):
    for _ in range(5):
        register_failure("carol")
    with pytest.raises(LockedOutError):
        from csp.auth.lockout import check_lock
        check_lock("carol")


def test_lockout_state_persists(tmp_data_dir: Path):
    for _ in range(5):
        register_failure("dave")
    st = get_lockout_state("dave")
    assert st.fails == 5
    assert st.lock_until is not None


# --- login / unlock ------------------------------------------------------


def test_unlock_success_and_failure(tmp_data_dir: Path):
    _bootstrap_user(tmp_data_dir, password="GoodPass1234!")
    session, payload = unlock("alice", "GoodPass1234!")
    assert session.user == "alice"
    assert isinstance(payload, dict)
    session.wipe()
    with pytest.raises(AuthError):
        unlock("alice", "wrong-password")
    st = get_lockout_state("alice")
    assert st.fails == 1


def test_unlock_unknown_user(tmp_data_dir: Path):
    with pytest.raises(UserError):
        unlock("nobody", "x")


# --- recovery ------------------------------------------------------------


def test_recovery_flow(tmp_data_dir: Path):
    _bootstrap_user(tmp_data_dir, password="OldPass1234!!")
    with pytest.raises(AuthError):
        start_recovery("alice", "wrong answer")
    ctx = start_recovery("alice", "fluffy unicorn")
    assert ctx.hint_question.startswith("What")
    complete_recovery(ctx, "fluffy unicorn", "NewPass1234!!")
    with pytest.raises(AuthError):
        unlock("alice", "OldPass1234!!")
    session, _ = unlock("alice", "NewPass1234!!")
    session.wipe()


def test_recovery_unknown_user(tmp_data_dir: Path):
    with pytest.raises(UserError):
        start_recovery("ghost", "x")
