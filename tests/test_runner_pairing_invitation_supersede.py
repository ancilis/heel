"""A fresh runner pairing invitation atomically supersedes an unused one.

Every case uses production-style file-backed SQLite.  Assertions compare
classifications and booleans; generated invitation tokens are never printed.
"""
import base64
import http.client
import json
import sqlite3
import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import canonical_bytes
from heel.runner.identity import runner_phrase_words
from heel.saas.canary_store import CanaryStore
from heel.saas.http_api import ControlPlane, serve
from heel.saas.runner_auth import RunnerAuthError, RunnerAuthStore, initialize_runner_auth_schema

PEPPER = b"p" * 32
PHRASE = " ".join(runner_phrase_words()[:6])


def _database(path, workspaces=("wsA", "wsB")):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY)")
    conn.executemany("INSERT INTO workspaces VALUES(?)", [(ws,) for ws in workspaces])
    conn.commit()
    CanaryStore(conn)
    initialize_runner_auth_schema(conn)
    return conn


def _store(tmp_path, instant):
    conn = _database(str(tmp_path / "control.sqlite3"))
    return conn, RunnerAuthStore(conn, pepper=PEPPER, now=lambda: instant[0])


def _key():
    private = Ed25519PrivateKey.generate()
    return private, base64.b64encode(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _exchange(store, token, public=None, protocol=True):
    public = public or _key()[1]
    extra = {"control_protocol": "heel.runner-control.v2", "exchange_digest": "a" * 64} if protocol else {}
    return store.exchange(token, public, PHRASE, display_name="Runner", runner_version="v3", adapters={}, **extra)


def _refused(store, token):
    try:
        _exchange(store, token)
    except RunnerAuthError as error:
        return str(error) == "invalid pairing"
    return False


def _rows(conn, workspace):
    return conn.execute(
        "SELECT pairing_id,runner_id,invitation_hash,status,created_at,expires_at,display_name,fingerprint,key_id "
        "FROM canary_runner_pairings WHERE workspace_id=? ORDER BY pairing_id", (workspace,),
    ).fetchall()


def _invited(conn, workspace):
    return [row for row in _rows(conn, workspace) if row[3] == "invited"]


def test_repeated_invite_in_one_workspace_supersedes_the_unused_invitation(tmp_path):
    conn, store = _store(tmp_path, [1_000.0])
    first = store.invite("wsA")
    second = store.invite("wsA")
    assert first.token != second.token
    invited = _invited(conn, "wsA")
    assert len(invited) == 1 and invited[0][1] == ""
    assert _refused(store, first.token)
    pending = _exchange(store, second.token)
    assert pending.status == "pending" and pending.runner_id.startswith("runr_")
    assert _invited(conn, "wsA") == []


def test_invite_after_exchange_preserves_claimed_pairings_and_attribution(tmp_path):
    instant = [1_000.0]
    conn, store = _store(tmp_path, instant)
    pending = _exchange(store, store.invite("wsA").token)
    approved = _exchange(store, store.invite("wsA").token)
    store.approve("wsA", approved.pairing_id, phrase=PHRASE, fingerprint=approved.fingerprint, actor="owner")
    private, public = _key()
    claimed = _exchange(store, store.invite("wsA").token, public, protocol=False)
    store.approve("wsA", claimed.pairing_id, phrase=PHRASE, fingerprint=claimed.fingerprint, actor="owner")
    row = conn.execute("SELECT activation_challenge FROM canary_runner_pairings WHERE pairing_id=?", (claimed.pairing_id,)).fetchone()
    proof = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id": claimed.pairing_id, "challenge": row[0]})
    store.activate(claimed.pairing_id, base64.b64encode(private.sign(proof)).decode())
    # A thirty-day activation receipt cascades with its pairing row; seed one so any
    # deletion of the activated pairing would be observable.
    conn.execute(
        "INSERT INTO canary_runner_pairing_activation_receipts(pairing_id,request_digest,response_ciphertext,created_at,expires_at) "
        "VALUES(?,?,?,?,?)", (claimed.pairing_id, "b" * 64, "sealed", instant[0], instant[0] + 30 * 86400),
    )
    conn.commit()
    receipts = conn.execute("SELECT * FROM canary_runner_pairing_activation_receipts ORDER BY pairing_id").fetchall()
    before = {row[0]: row for row in _rows(conn, "wsA")}
    assert {before[p][3] for p in (pending.pairing_id, approved.pairing_id, claimed.pairing_id)} == {"pending", "approved", "activated"}
    assert len(receipts) == 1

    store.invite("wsA")
    store.invite("wsA")
    after = {row[0]: row for row in _rows(conn, "wsA")}
    for pairing in (pending, approved, claimed):
        assert after[pairing.pairing_id] == before[pairing.pairing_id]
        assert after[pairing.pairing_id][1] == pairing.runner_id
    assert conn.execute("SELECT * FROM canary_runner_pairing_activation_receipts ORDER BY pairing_id").fetchall() == receipts
    assert len(_invited(conn, "wsA")) == 1

    # Past the ten-minute challenge deadline but inside the thirty-day receipt window,
    # neither the sweep nor supersession touches the activated pairing or its receipt.
    instant[0] += 11 * 60
    store.invite("wsA")
    assert {row[0]: row for row in _rows(conn, "wsA")}[claimed.pairing_id] == before[claimed.pairing_id]
    assert conn.execute("SELECT * FROM canary_runner_pairing_activation_receipts ORDER BY pairing_id").fetchall() == receipts


def test_invite_in_one_workspace_never_supersedes_another_workspace(tmp_path):
    conn, store = _store(tmp_path, [1_000.0])
    other = store.invite("wsA")
    other_rows = _rows(conn, "wsA")
    store.invite("wsB")
    store.invite("wsB")
    assert _rows(conn, "wsA") == other_rows and len(other_rows) == 1
    assert len(_invited(conn, "wsB")) == 1
    assert _exchange(store, other.token).status == "pending"


def test_concurrent_invites_on_separate_connections_leave_exactly_one_usable_invitation(tmp_path):
    path = str(tmp_path / "control.sqlite3")
    _database(path).close()
    rounds = 20
    for _ in range(rounds):
        barrier, results = threading.Barrier(2), {}

        def worker(name):
            conn = sqlite3.connect(path, timeout=10)
            try:
                store = RunnerAuthStore(conn, pepper=PEPPER)
                barrier.wait()
                results[name] = ("ok", store.invite("wsA").token)
            except Exception as error:  # classification only; never the token
                results[name] = ("error", type(error).__name__)
            finally:
                conn.close()

        threads = [threading.Thread(target=worker, args=(name,)) for name in ("one", "two")]
        for thread in threads: thread.start()
        for thread in threads: thread.join(30)
        assert [results.get(name, ("missing",))[0] for name in ("one", "two")] == ["ok", "ok"]
        check = sqlite3.connect(path)
        try:
            assert len(_invited(check, "wsA")) == 1
            verifier = RunnerAuthStore(check, pepper=PEPPER)
            tokens = [results[name][1] for name in ("one", "two")]
            usable = [not _refused(verifier, token) for token in tokens]
            assert sorted(usable) == [False, True]
        finally:
            check.close()
    final = sqlite3.connect(path)
    try:
        assert final.execute("SELECT COUNT(*) FROM canary_runner_pairings WHERE status='pending'").fetchone()[0] == rounds
    finally:
        final.close()


class _Http:
    def __init__(self, directory):
        self.cp = ControlPlane(
            str(Path(directory) / "control.sqlite3"), device_token_pepper=b"d" * 32, runner_auth_pepper=b"r" * 32,
            enable_device_auth=True, public_origin="https://heel.test",
        )
        self.server = serve(self.cp)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()

    def request(self, method, path, body, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1])
        try:
            conn.request(method, path, json.dumps(body, separators=(",", ":")).encode(), {"Content-Type": "application/json", **(headers or {})})
            response = conn.getresponse(); raw = response.read()
            return response.status, json.loads(raw), response.getheader("Set-Cookie")
        finally:
            conn.close()

    def owner(self, email):
        status, signup, cookie = self.request("POST", "/v1/signup", {"email": email, "password": "correct-horse-battery"})
        assert status in (200, 201)
        return signup["workspace_id"], {"Cookie": cookie.split(";", 1)[0], "Origin": "https://heel.test", "X-Heel-Internal-Origin": "same-origin"}

    def invite(self, workspace, browser):
        return self.request("POST", f"/v1/workspaces/{workspace}/runner-pairings", {"schema_version": "heel.runner-pairing-invite.v1"}, browser)[:2]

    def exchange(self, token):
        body = {"schema_version": "heel.runner-pairing-exchange.v3", "invitation_token": token, "public_key_b64": _key()[1],
                "pairing_phrase": PHRASE, "display_name": "Runner HTTP", "runner_version": "v3", "adapters": {},
                "control_protocol": "heel.runner-control.v2"}
        return self.request("POST", "/v1/runner-pairings/exchange", body)[:2]

    def close(self):
        self.server.shutdown(); self.server.server_close()


@pytest.fixture
def live(tmp_path):
    http_plane = _Http(tmp_path)
    try:
        yield http_plane
    finally:
        http_plane.close()


def test_superseded_and_consumed_invitation_tokens_are_refused_on_replay(live):
    workspace, browser = live.owner("replay@example.test")
    _, old = live.invite(workspace, browser)
    _, fresh = live.invite(workspace, browser)
    def outcome(token):
        status, body = live.exchange(token)
        return status, body.get("code") if status == 400 else body.get("status")
    refused = (400, "invalid_runner_pairing")
    assert outcome(old["invitation_token"]) == refused
    assert outcome(fresh["invitation_token"]) == (201, "pending")
    assert outcome(fresh["invitation_token"]) == refused
    assert outcome(old["invitation_token"]) == refused


def test_http_second_invitation_post_in_one_workspace_returns_201(live):
    workspace, browser = live.owner("second@example.test")
    statuses = []
    for _ in range(3):
        status, body = live.invite(workspace, browser)
        statuses.append(status)
        assert status == 201 and set(body) == {"schema_version", "invitation_token", "expires_at"}
        assert body["schema_version"] == "heel.runner-pairing-invitation.v1"
    assert statuses == [201, 201, 201]
    invited = live.cp.store.conn.execute(
        "SELECT COUNT(*) FROM canary_runner_pairings WHERE workspace_id=? AND status='invited'", (workspace,),
    ).fetchone()[0]
    assert invited == 1
