"""Minimal cloud backup/restore server for ClinicManager installs.

Each ClinicManager install can optionally push an *already client-side encrypted*
database backup here, and later pull it back down onto a replacement PC. This
server never sees plaintext - it only ever stores/returns whatever encrypted
bytes the client sends. Backed by Postgres (point it at a free Neon project
via DATABASE_URL - Neon's free tier does not expire, unlike Render's own free
Postgres which is deleted after 30+14 days).

Run locally against a real Postgres for testing:
    DATABASE_URL=postgresql://user:pass@host/dbname python3 app.py

Deploy: see README.md in this folder.
"""

from __future__ import annotations

import base64
import os

import psycopg2
import psycopg2.extras
from flask import Flask, Response, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "")
# Max encrypted blob size accepted per backup (bytes). Keeps a single runaway
# upload from blowing through Neon's free-tier storage cap on its own.
MAX_BACKUP_BYTES = int(os.getenv("MAX_BACKUP_BYTES", str(200 * 1024 * 1024)))


def get_db():
    if "db" not in g:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is not configured")
        g.db = psycopg2.connect(DATABASE_URL)
        with g.db.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS backups (
                    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
                    encrypted_blob BYTEA NOT NULL,
                    size INTEGER NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            # Short-lived device pairing (6-digit connect code). Stores only a
            # hash of the code and a blob the client encrypted with a key
            # derived from the code itself - the server never sees the code or
            # the credential (zero-knowledge, like the backups themselves).
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS pairings (
                    code_hash TEXT PRIMARY KEY,
                    blob BYTEA NOT NULL,
                    salt TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            # Row-level change log: the real-time multi-device sync engine.
            # Each row is one create/update/delete on one table on one
            # device. table_name/row_sync_id/op/device_id/created_at stay in
            # the clear (the server needs them to order and route changes);
            # payload is the actual field values, Fernet-encrypted client-side
            # with the same per-account key as /backup - the server still
            # never sees plaintext.
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS change_log (
                    seq BIGSERIAL PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    table_name TEXT NOT NULL,
                    row_sync_id TEXT NOT NULL,
                    op TEXT NOT NULL,
                    payload BYTEA,
                    device_id TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
            cur.execute(
                "CREATE INDEX IF NOT EXISTS ix_change_log_account_seq ON change_log (account_id, seq)"
            )
            # How far each device has read. Without this the change log can
            # only grow: there is no way to know whether a row still has a
            # reader, and deleting one that does loses it for that device
            # permanently and silently - the worst failure this system has.
            #
            # With it, a change can be dropped once every device that is still
            # turning up has read it, which for a clinic with two devices used
            # daily is almost immediately.
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS device_cursors (
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    device_id TEXT NOT NULL,
                    last_seq BIGINT NOT NULL DEFAULT 0,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (account_id, device_id)
                )
                """
            )
            # Per-member key envelopes: the clinic's cloud credentials,
            # encrypted client-side with a key derived from that one staff
            # member's own login password. It is what lets someone sign in on
            # a brand-new device with just their email and password and have
            # the clinic's data appear - no cloud password to hand around, no
            # per-device setup.
            #
            # The server stores ciphertext and a salt, exactly as it does for
            # backups: it cannot open an envelope, because it never sees the
            # member's password. Losing this table costs convenience (devices
            # must pair with a code again), not data.
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS key_envelopes (
                    member_email TEXT PRIMARY KEY,
                    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                    blob BYTEA NOT NULL,
                    salt TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )
        g.db.commit()
    return g.db


# Best-effort in-memory per-IP throttle on pair claims, so a 6-digit code space
# can't be brute-forced within its short lifetime. Per-instance only (fine for
# the single free-tier instance); the short TTL + single-use are the real caps.
_pair_claim_hits: dict = {}
_PAIR_CLAIM_MAX_PER_MIN = 12


def _pair_claim_rate_limited(ip: str) -> bool:
    import time as _t
    now = _t.time()
    window = [t for t in _pair_claim_hits.get(ip, []) if now - t < 60]
    window.append(now)
    _pair_claim_hits[ip] = window
    return len(window) > _PAIR_CLAIM_MAX_PER_MIN


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _get_account_by_username(username: str):
    db = get_db()
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT id, username, password_hash, salt FROM accounts WHERE username = %s",
            (username,),
        )
        return cur.fetchone()


def require_account_auth(view):
    """Verify HTTP Basic Auth against the accounts table; attaches g.account."""

    def wrapped(*args, **kwargs):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return jsonify({"error": "authentication required"}), 401

        account = _get_account_by_username(auth.username)
        if not account or not check_password_hash(account["password_hash"], auth.password):
            return jsonify({"error": "invalid credentials"}), 401

        g.account = account
        return view(*args, **kwargs)

    wrapped.__name__ = view.__name__
    return wrapped


# In-process rate limit for the one unauthenticated endpoint that returns
# anything derived from an account. Per email and per IP: a single server
# process backs this deployment, so a dict is enough and a Redis dependency
# would be ceremony. Worst case on a restart is a counter reset, not a bypass
# of the encryption itself.
_ENVELOPE_FETCH_ATTEMPTS: dict[str, list[float]] = {}
_ENVELOPE_FETCH_WINDOW_SECONDS = 300
_ENVELOPE_FETCH_MAX = 10


def _allow_envelope_fetch(member_email: str, remote_addr: str) -> bool:
    import time

    now = time.time()
    for key in (f"email:{member_email}", f"ip:{remote_addr}"):
        hits = [t for t in _ENVELOPE_FETCH_ATTEMPTS.get(key, []) if now - t < _ENVELOPE_FETCH_WINDOW_SECONDS]
        if len(hits) >= _ENVELOPE_FETCH_MAX:
            _ENVELOPE_FETCH_ATTEMPTS[key] = hits
            return False
        hits.append(now)
        _ENVELOPE_FETCH_ATTEMPTS[key] = hits
    return True


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    salt = (data.get("salt") or "").strip()

    if not username or not password or not salt:
        return jsonify({"error": "username, password, and salt are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    if _get_account_by_username(username):
        return jsonify({"error": "username already taken"}), 409

    db = get_db()
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO accounts (username, password_hash, salt) VALUES (%s, %s, %s)",
            (username, generate_password_hash(password), salt),
        )
    db.commit()
    return jsonify({"ok": True}), 201


@app.route("/login", methods=["POST"])
@require_account_auth
def login():
    return jsonify({"ok": True, "username": g.account["username"], "salt": g.account["salt"]})


@app.route("/backup", methods=["PUT"])
@require_account_auth
def upload_backup():
    encrypted = request.get_data(cache=False)
    if not encrypted:
        return jsonify({"error": "empty backup body"}), 400
    if len(encrypted) > MAX_BACKUP_BYTES:
        return jsonify({"error": "backup too large"}), 413

    db = get_db()
    with db.cursor() as cur:
        # Returns updated_at so the client can record *this server's* timestamp
        # for the push. Without it the client had to fall back on its own clock,
        # and any skew made the copy it had just uploaded look newer than its
        # own last-sync marker - so the device immediately re-downloaded and
        # restored its own backup.
        cur.execute(
            """
            INSERT INTO backups (account_id, encrypted_blob, size, updated_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (account_id) DO UPDATE
            SET encrypted_blob = EXCLUDED.encrypted_blob, size = EXCLUDED.size, updated_at = now()
            RETURNING updated_at
            """,
            (g.account["id"], psycopg2.Binary(encrypted), len(encrypted)),
        )
        updated_at = cur.fetchone()[0]
    db.commit()
    return jsonify({"ok": True, "size": len(encrypted), "updated_at": updated_at.isoformat()})


@app.route("/backup", methods=["GET"])
@require_account_auth
def download_backup():
    db = get_db()
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT encrypted_blob, updated_at FROM backups WHERE account_id = %s",
            (g.account["id"],),
        )
        row = cur.fetchone()

    if not row:
        return jsonify({"error": "no backup found for this account"}), 404

    response = Response(bytes(row["encrypted_blob"]), mimetype="application/octet-stream")
    response.headers["X-Backup-Salt"] = g.account["salt"]
    response.headers["X-Backup-Updated-At"] = row["updated_at"].isoformat()
    return response


@app.route("/status", methods=["GET"])
@require_account_auth
def backup_status():
    db = get_db()
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            "SELECT size, updated_at FROM backups WHERE account_id = %s",
            (g.account["id"],),
        )
        row = cur.fetchone()

    if not row:
        return jsonify({"has_backup": False})
    return jsonify(
        {
            "has_backup": True,
            "size": row["size"],
            "updated_at": row["updated_at"].isoformat(),
            "salt": g.account["salt"],
        }
    )


@app.route("/pair/create", methods=["POST"])
@require_account_auth
def pair_create():
    """Admin device stores a short-lived pairing: the code's hash plus a blob it
    encrypted with a key derived from the (6-digit) code. The raw code is shared
    out-of-band with the staff member; the server never learns it."""
    import base64
    from datetime import datetime, timedelta, timezone

    data = request.get_json(silent=True) or {}
    code_hash = (data.get("code_hash") or "").strip()
    blob_b64 = data.get("blob") or ""
    salt = (data.get("salt") or "").strip()
    ttl = int(data.get("ttl") or 600)
    ttl = max(60, min(ttl, 1800))
    if not code_hash or not blob_b64 or not salt:
        return jsonify({"error": "code_hash, blob, and salt are required"}), 400
    try:
        blob = base64.b64decode(blob_b64)
    except Exception:
        return jsonify({"error": "invalid blob"}), 400

    expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    db = get_db()
    with db.cursor() as cur:
        cur.execute("DELETE FROM pairings WHERE expires_at < now()")
        cur.execute(
            """
            INSERT INTO pairings (code_hash, blob, salt, expires_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (code_hash) DO UPDATE
            SET blob = EXCLUDED.blob, salt = EXCLUDED.salt, expires_at = EXCLUDED.expires_at
            """,
            (code_hash, psycopg2.Binary(blob), salt, expires_at),
        )
    db.commit()
    return jsonify({"ok": True})


@app.route("/pair/claim", methods=["POST"])
def pair_claim():
    """Staff device redeems a pairing by the code's hash (unauthenticated - it
    has no account creds yet). Single-use: the pairing is deleted on claim. The
    returned blob is only decryptable with the raw code the staff member typed."""
    import base64

    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    if _pair_claim_rate_limited(ip):
        return jsonify({"error": "too many attempts, slow down"}), 429

    data = request.get_json(silent=True) or {}
    code_hash = (data.get("code_hash") or "").strip()
    if not code_hash:
        return jsonify({"error": "code_hash is required"}), 400

    db = get_db()
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("DELETE FROM pairings WHERE expires_at < now()")
        cur.execute(
            "SELECT blob, salt FROM pairings WHERE code_hash = %s AND expires_at >= now()",
            (code_hash,),
        )
        row = cur.fetchone()
        if row:
            cur.execute("DELETE FROM pairings WHERE code_hash = %s", (code_hash,))
    db.commit()

    if not row:
        return jsonify({"error": "invalid or expired code"}), 404
    return jsonify(
        {"blob": base64.b64encode(bytes(row["blob"])).decode("ascii"), "salt": row["salt"]}
    )


# Max change entries accepted in one /sync/push call - keeps one runaway
# client batch (e.g. a bulk import) from blocking on one giant transaction.
MAX_SYNC_PUSH_BATCH = 500


@app.route("/keys/envelope", methods=["POST"])
@require_account_auth
def keys_envelope_put():
    """Store (or replace) one staff member's envelope.

    Called by an already-connected device that has both the clinic's cloud
    credentials and, for a moment, that member's own password - when an admin
    creates their login, when they change their password, or when they sign in.
    The blob arrives already encrypted; this endpoint is storage, not crypto.
    """
    import base64

    data = request.get_json(silent=True) or {}
    member_email = (data.get("member_email") or "").strip().lower()[:255]
    blob_b64 = data.get("blob") or ""
    salt = (data.get("salt") or "").strip()
    if "@" not in member_email or not blob_b64 or not salt:
        return jsonify({"error": "member_email, blob, and salt are required"}), 400
    try:
        blob = base64.b64decode(blob_b64)
    except Exception:
        return jsonify({"error": "invalid blob"}), 400
    if len(blob) > 8192:
        return jsonify({"error": "blob too large"}), 400

    db = get_db()
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO key_envelopes (member_email, account_id, blob, salt, updated_at)
            VALUES (%s, %s, %s, %s, now())
            ON CONFLICT (member_email) DO UPDATE
            SET account_id = EXCLUDED.account_id,
                blob = EXCLUDED.blob,
                salt = EXCLUDED.salt,
                updated_at = now()
            """,
            (member_email, g.account["id"], psycopg2.Binary(blob), salt),
        )
    db.commit()
    return jsonify({"ok": True})


@app.route("/keys/envelope/fetch", methods=["POST"])
def keys_envelope_fetch():
    """Hand back one member's envelope, by email.

    Deliberately unauthenticated: the caller is a device that has nothing yet -
    that is the whole point. What it gets is ciphertext plus a salt, useless
    without the member's own password, which the server has never seen. The
    risk this carries is an offline guessing attack on a weak password by
    someone who knows a staff email, which is why the KDF is deliberately slow
    (see _derive_backup_key on the client) and why this is rate limited.
    """
    data = request.get_json(silent=True) or {}
    member_email = (data.get("member_email") or "").strip().lower()[:255]
    if "@" not in member_email:
        return jsonify({"error": "member_email is required"}), 400

    if not _allow_envelope_fetch(member_email, request.remote_addr or ""):
        return jsonify({"error": "too many attempts, try again shortly"}), 429

    db = get_db()
    with db.cursor() as cur:
        cur.execute(
            """
            SELECT e.blob, e.salt, a.username
            FROM key_envelopes e
            JOIN accounts a ON a.id = e.account_id
            WHERE e.member_email = %s
            """,
            (member_email,),
        )
        row = cur.fetchone()
    if not row:
        return jsonify({"error": "not found"}), 404

    import base64

    blob, salt, account_username = row
    return jsonify({
        "blob": base64.b64encode(bytes(blob)).decode("ascii"),
        "salt": salt,
        "account_username": account_username,
    })


@app.route("/sync/push", methods=["POST"])
@require_account_auth
def sync_push():
    """Accept a batch of row-level changes from one device, in order, and
    hand back the seq assigned to each so the client can mark them pushed."""
    data = request.get_json(silent=True) or {}
    changes = data.get("changes")
    if not isinstance(changes, list) or not changes:
        return jsonify({"error": "changes must be a non-empty list"}), 400
    if len(changes) > MAX_SYNC_PUSH_BATCH:
        return jsonify({"error": f"at most {MAX_SYNC_PUSH_BATCH} changes per push"}), 413

    rows = []
    for change in changes:
        table_name = (change.get("table_name") or "").strip()
        row_sync_id = (change.get("row_sync_id") or "").strip()
        op = (change.get("op") or "").strip()
        device_id = (change.get("device_id") or "").strip()
        if not table_name or not row_sync_id or op not in {"insert", "update", "delete"} or not device_id:
            return jsonify({"error": "each change needs table_name, row_sync_id, a valid op, and device_id"}), 400
        payload_b64 = change.get("payload")
        payload = base64.b64decode(payload_b64) if payload_b64 else None
        rows.append((g.account["id"], table_name, row_sync_id, op, payload, device_id))

    db = get_db()
    seqs = []
    with db.cursor() as cur:
        for row in rows:
            cur.execute(
                """
                INSERT INTO change_log (account_id, table_name, row_sync_id, op, payload, device_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING seq
                """,
                row,
            )
            seqs.append(cur.fetchone()[0])
    db.commit()
    _prune_change_log(db, g.account["id"])
    return jsonify({"ok": True, "seqs": seqs})


# Max change entries returned in one /sync/pull call - a device that's been
# offline a long time (or a brand-new device bootstrapping since=0) pages
# through history instead of pulling an unbounded result set in one response.
MAX_SYNC_PULL_BATCH = 500


# A device that has not pulled in this long stops holding the log open. A
# phone that was lost or replaced would otherwise pin every change ever made,
# forever, on the strength of a cursor nobody is behind any more.
DEVICE_CURSOR_ACTIVE_DAYS = int(os.getenv("SYNC_DEVICE_ACTIVE_DAYS", "60") or 60)
# Even once every device has read a change, it is kept this long. Nothing
# depends on it, but a log with some history in it is worth a great deal the
# day something needs explaining, and the cost is small.
CHANGE_LOG_GRACE_DAYS = int(os.getenv("SYNC_CHANGE_LOG_GRACE_DAYS", "7") or 7)


def _prune_change_log(db, account_id: int) -> int:
    """Drop changes every active device has already read.

    The rule is deliberately conservative, because the failure it risks is the
    one that cannot be undone: delete a change before its device reads it and
    that device never learns about it. So a row goes only when it is behind
    *every* cursor - not the average, not most of them - and only once it is
    also older than the grace window.

    A device that has not been seen for DEVICE_CURSOR_ACTIVE_DAYS is left out
    of that minimum. It can then fall off the end of the log, which is exactly
    why /sync/pull reports where the log begins: that device is told to take
    the whole database instead of pretending it can catch up."""
    try:
        with db.cursor() as cur:
            cur.execute(
                """
                SELECT COALESCE(MIN(last_seq), 0) AS floor_seq, COUNT(*) AS devices
                FROM device_cursors
                WHERE account_id = %s
                  AND updated_at > now() - INTERVAL '%s days'
                """,
                (account_id, DEVICE_CURSOR_ACTIVE_DAYS),
            )
            row = cur.fetchone()
            floor_seq, devices = row[0], row[1]
            # No device has ever reported a position: nothing is provably read,
            # so nothing may be deleted.
            if not devices or not floor_seq:
                return 0

            cur.execute(
                """
                DELETE FROM change_log
                WHERE account_id = %s
                  AND seq <= %s
                  AND created_at < now() - INTERVAL '%s days'
                """,
                (account_id, floor_seq, CHANGE_LOG_GRACE_DAYS),
            )
            removed = cur.rowcount or 0
        db.commit()
        return removed
    except Exception:
        # Housekeeping must never cost a clinic its push. The log being larger
        # than it needs to be is a bill; a failed push is lost work.
        try:
            db.rollback()
        except Exception:
            pass
        app.logger.exception("Pruning the change log failed for account %s", account_id)
        return 0


@app.route("/sync/pull", methods=["GET"])
@require_account_auth
def sync_pull():
    """Return this account's changes after `since` (0 = everything - used by
    a brand-new device's bootstrap, which is otherwise identical to any other
    pull), oldest first, capped at MAX_SYNC_PULL_BATCH so the client knows to
    keep paging via the returned `latest_seq` vs its own last-applied seq."""
    try:
        since = int(request.args.get("since", "0"))
    except ValueError:
        return jsonify({"error": "since must be an integer"}), 400

    device_id = (request.args.get("device_id") or "").strip()
    db = get_db()
    if device_id:
        # Recorded before the read, deliberately: `since` is what this device
        # has finished applying, so it is safe to mark as read even if the
        # page it is about to fetch never arrives. Overstating it is the one
        # thing that could get a change pruned before its reader saw it.
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO device_cursors (account_id, device_id, last_seq, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (account_id, device_id) DO UPDATE
                SET last_seq = GREATEST(device_cursors.last_seq, EXCLUDED.last_seq),
                    updated_at = now()
                """,
                (g.account["id"], device_id, since),
            )
        db.commit()
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT seq, table_name, row_sync_id, op, payload, device_id, created_at
            FROM change_log
            WHERE account_id = %s AND seq > %s
            ORDER BY seq ASC
            LIMIT %s
            """,
            (g.account["id"], since, MAX_SYNC_PULL_BATCH),
        )
        rows = cur.fetchall()

        # The high-water mark for this account, independent of what was asked
        # for. A device stores how far it has read; if this database is ever
        # rebuilt (a restore, a migration, a free instance being reclaimed)
        # seq restarts at 1 while devices still hold the old, much larger
        # number. They would then ask for changes after a seq that will not
        # exist again for months, receive nothing, and sync would be dead
        # silently and permanently. Telling them where the log actually ends
        # is what lets them notice.
        cur.execute(
            """
            SELECT COALESCE(MAX(seq), 0) AS max_seq, COALESCE(MIN(seq), 0) AS min_seq
            FROM change_log WHERE account_id = %s
            """,
            (g.account["id"],),
        )
        bounds = cur.fetchone()
        account_max_seq = bounds["max_seq"]
        # Where the log now begins. A device below this has missed changes
        # that were pruned before it read them and cannot catch up from the
        # log at all - it needs the whole database instead, and has to be told
        # so rather than quietly carrying on a few hundred rows short.
        account_min_seq = bounds["min_seq"]

    changes = [
        {
            "seq": row["seq"],
            "table_name": row["table_name"],
            "row_sync_id": row["row_sync_id"],
            "op": row["op"],
            "payload": base64.b64encode(bytes(row["payload"])).decode("ascii") if row["payload"] else None,
            "device_id": row["device_id"],
            "created_at": row["created_at"].isoformat(),
        }
        for row in rows
    ]
    latest_seq = changes[-1]["seq"] if changes else since
    return jsonify({
        "changes": changes,
        "latest_seq": latest_seq,
        "account_max_seq": account_max_seq,
        "account_min_seq": account_min_seq,
    })


@app.route("/")
def index():
    # Render's uptime pings and stray browser hits land on / , not /health -
    # a 404 here is harmless but shows up as noise in the deploy log on every
    # single ping. This just gives them something other than a 404.
    return jsonify({"service": "clinicmanager-cloud-backup", "ok": True})


@app.route("/health")
def health():
    return jsonify({"ok": True})


# Entitlement service: /entitlement, /billing/play/*, /admin/*. Lives in its own
# module because it has nothing to do with backup storage - it just happens to
# be the one server every install already talks to.
from entitlements import register_entitlement_routes  # noqa: E402

register_entitlement_routes(app, get_db)

# Message-credit wallet: /wallet/*. Same reasoning as entitlements - the wallet
# has to be server-owned so two devices for one clinic share one balance, and
# the actual send happens here so gateway API keys never ship inside the app.
from message_credits import register_wallet_routes  # noqa: E402

register_wallet_routes(app, get_db)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "8001"))
    app.run(host="0.0.0.0", port=port)
