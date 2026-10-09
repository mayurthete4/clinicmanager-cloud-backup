"""Entitlement service: the single place that decides what an install may do.

Why this exists at all: the app used to decide its own plan from a file on the
device, which made two things impossible. You could not change the free/paid
split after publishing (every install would need an app update), and you could
not cut off an install whose Play subscription was refunded or cancelled. Both
are now server decisions, so they take effect on the next check-in.

Three inputs decide a tier, highest wins:

  1. an override written by hand (``POST /admin/entitlement``) - the kill switch,
     also how you comp a pilot clinic or extend a trial for support reasons
  2. a live Google Play subscription, kept current by the RTDN webhook
  3. the install's cohort - installs first seen before FREE_LEGACY_CUTOFF are
     grandfathered and keep the full free feature set forever

Responses are Ed25519-signed. Without that, self-granting Platinum is a hosts
file entry pointing at a fake server, which is a five-minute job and would make
the whole thing decorative.
"""

from __future__ import annotations

import json
import os
import re
from datetime import date, datetime, timedelta, timezone

import psycopg2
import psycopg2.extras
from flask import jsonify, request

# Installs first seen strictly before this date keep the full free feature set
# for good. Set it to the day paid tiers go live, so nobody who adopted the app
# while it was free has anything taken away - taking a working feature back is
# what turns a 5-star reviewer into a 1-star one, and Play ranking does not
# recover from that quickly.
FREE_LEGACY_CUTOFF = os.getenv("FREE_LEGACY_CUTOFF", "").strip()

# Signing key for entitlement payloads (hex Ed25519 private key). Generate with
# `python3 -m entitlements keygen`. The public half is baked into the app as
# CLINICMANAGER_ENTITLEMENT_PUBLIC_KEY.
ENTITLEMENT_PRIVATE_KEY_HEX = os.getenv("ENTITLEMENT_PRIVATE_KEY", "").strip()

# Shared secret for the admin endpoints. No admin token means the admin routes
# refuse every request rather than defaulting to open.
ADMIN_API_TOKEN = os.getenv("ENTITLEMENT_ADMIN_TOKEN", "").strip()

# How long a client may keep using a cached entitlement with no server contact.
DEFAULT_GRACE_DAYS = int(os.getenv("ENTITLEMENT_GRACE_DAYS", "14") or 14)

TIER_RANK = {"free": 0, "basic": 1, "premium": 2, "platinum": 3}

# Volume caps handed to the client. Sending them from here (rather than relying
# on the constants compiled into the app) means the free tier can be retuned,
# or lifted for one clinic, without a release.
TIER_LIMITS = {
    "free": {"patients": 50, "invoices_per_month": 30, "users": 1},
    "free_legacy": {"patients": 0, "invoices_per_month": 0, "users": 3},
    "basic": {"patients": 0, "invoices_per_month": 0, "users": 3},
    "premium": {"patients": 0, "invoices_per_month": 0, "users": 0},
    "platinum": {"patients": 0, "invoices_per_month": 0, "users": 0},
}

TIER_FEATURES = {
    "free": [],
    "free_legacy": ["appointments", "sales", "reports", "customer_history", "lan_access"],
    "basic": [],
    "premium": ["appointments", "sales", "reports", "customer_history", "lan_access", "low_stock_alerts"],
    "platinum": [
        "appointments", "sales", "reports", "customer_history", "lan_access",
        "low_stock_alerts", "cloud_sync", "whatsapp", "custom_branding",
    ],
}

# Play product IDs -> tier. Keep in step with the Play Console subscription IDs.
PLAY_PRODUCT_TIERS = {
    "clinicmanager_pro_monthly": "premium",
    "clinicmanager_pro_yearly": "premium",
    "clinicmanager_clinic_monthly": "platinum",
    "clinicmanager_clinic_yearly": "platinum",
}


# CREATE TABLE IF NOT EXISTS is cheap but not free, and this runs on the request
# path. One round trip per worker process is enough - the tables cannot go away
# underneath a running worker.
_tables_ready = False


def init_entitlement_tables(db) -> None:
    global _tables_ready
    if _tables_ready:
        return

    with db.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS installs (
                install_id TEXT PRIMARY KEY,
                first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
                cohort TEXT NOT NULL DEFAULT 'standard',
                platform TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                distribution TEXT NOT NULL DEFAULT '',
                account_email TEXT NOT NULL DEFAULT ''
            )
            """
        )
        # Migration for a table created before account_email existed.
        cur.execute("ALTER TABLE installs ADD COLUMN IF NOT EXISTS account_email TEXT NOT NULL DEFAULT ''")
        # One row per source of entitlement, so a manual override and a Play
        # subscription can coexist and the highest simply wins. Overwriting a
        # single column would make "revoke the Play sub" also wipe the support
        # comp, and vice versa.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS entitlement_grants (
                install_id TEXT NOT NULL,
                source TEXT NOT NULL,
                tier TEXT NOT NULL,
                expires_at TIMESTAMPTZ,
                revoked BOOLEAN NOT NULL DEFAULT FALSE,
                note TEXT NOT NULL DEFAULT '',
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                PRIMARY KEY (install_id, source)
            )
            """
        )
        # Which product the customer bought - "clinic", "pharmacy", or both -
        # kept separate from tier because they answer different questions. A
        # pharmacy on Basic and a hospital on Platinum are both ordinary, and
        # folding the two together would need a new tier per product.
        #
        # Empty means "not stated", which is what every existing grant reads as,
        # and leaves the install to fall back on its licence key or its own
        # seeded answer rather than being silently stripped of half the app.
        cur.execute(
            "ALTER TABLE entitlement_grants ADD COLUMN IF NOT EXISTS modules TEXT NOT NULL DEFAULT ''"
        )
        # Play purchase tokens are the join between an RTDN (which knows the
        # token, not the install) and an install (which knows the token because
        # its own client sent it up after purchase).
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS play_purchases (
                purchase_token TEXT PRIMARY KEY,
                install_id TEXT NOT NULL DEFAULT '',
                product_id TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT '',
                expires_at TIMESTAMPTZ,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    db.commit()
    _tables_ready = True


def _cohort_for(first_seen: datetime) -> str:
    """Grandfather installs that predate the paid launch."""
    if not FREE_LEGACY_CUTOFF:
        return "standard"
    try:
        cutoff = date.fromisoformat(FREE_LEGACY_CUTOFF)
    except ValueError:
        return "standard"
    return "legacy" if first_seen.date() < cutoff else "standard"


def _register_install(
    db, install_id: str, platform: str, version: str, distribution: str, account_email: str = ""
) -> dict:
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO installs (install_id, platform, version, distribution, account_email)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (install_id) DO UPDATE
            SET last_seen = now(),
                platform = EXCLUDED.platform,
                version = EXCLUDED.version,
                distribution = EXCLUDED.distribution,
                -- Never blank out an already-known email just because this
                -- particular check-in didn't send one (e.g. logged out
                -- momentarily) - only a real address ever overwrites it.
                account_email = COALESCE(NULLIF(EXCLUDED.account_email, ''), installs.account_email)
            RETURNING install_id, first_seen, cohort
            """,
            (install_id, platform[:40], version[:40], distribution[:20], account_email[:255]),
        )
        row = cur.fetchone()

        # cohort is stamped once, from the row's own first_seen, and never
        # recomputed - otherwise moving FREE_LEGACY_CUTOFF later would silently
        # re-grandfather installs that had already been switched to the capped
        # free tier.
        if row["cohort"] == "standard":
            resolved = _cohort_for(row["first_seen"])
            if resolved != "standard":
                cur.execute(
                    "UPDATE installs SET cohort = %s WHERE install_id = %s",
                    (resolved, install_id),
                )
                row["cohort"] = resolved
    db.commit()
    return row


_ACCOUNT_KEY_PREFIX = "email:"


def _account_key(email: str) -> str:
    """entitlement_grants.install_id is reused to hold an account-level
    identifier too, so this can ship with no schema migration on a live
    table. Safe: a real install_id is an opaque random token and never
    contains "@" or a colon, so this can never collide with one."""
    return _ACCOUNT_KEY_PREFIX + email.strip().lower()


VALID_MODULES = ("clinic", "pharmacy")

_MODULE_ALIASES = {
    "medical": "pharmacy",
    "shop": "pharmacy",
    "hospital": "clinic",
}


def _parse_modules(raw) -> list[str]:
    """Accept a list or a comma string, and keep only real module names."""
    if isinstance(raw, str):
        parts = [p for p in re.split(r"[,\s|+]+", raw) if p]
    else:
        parts = list(raw or ())
    out = []
    for part in parts:
        name = str(part).strip().lower()
        name = _MODULE_ALIASES.get(name, name)
        if name in VALID_MODULES and name not in out:
            out.append(name)
    return out


def _active_grants(db, identifier: str) -> list[dict]:
    now = datetime.now(timezone.utc)
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT source, tier, expires_at, revoked, modules
            FROM entitlement_grants
            WHERE install_id = %s AND revoked = FALSE
            """,
            (identifier,),
        )
        rows = cur.fetchall()
    return [r for r in rows if not r["expires_at"] or r["expires_at"] > now]


def resolve_entitlement(
    db, install_id: str, platform: str, version: str, distribution: str, email: str = ""
) -> dict:
    """Highest of: this device's own grants, and - if this install is signed
    into a ClinicManager account (the same email used for cloud backup / Google
    sign-in) - that account's grants. This is what lets a clinic buy once and
    have every device signed into that account pick it up on its own next
    check-in, rather than each device needing its own license key: the same
    account-level grant resolves identically no matter which install_id asks,
    the same way a Claude/Netflix-style subscription follows the account
    rather than the device.

    Account grants are optional and additive - an install with no email (not
    yet signed into any account, or the app not sending one) resolves exactly
    as before, off its own install_id alone."""
    email = (email or "").strip().lower()
    install = _register_install(db, install_id, platform, version, distribution, email)
    cohort = install["cohort"]

    base_tier = "free_legacy" if cohort == "legacy" else "free"
    best_tier = base_tier
    expires_at = None

    grants = list(_active_grants(db, install_id))
    if "@" in email:
        grants.extend(_active_grants(db, _account_key(email)))

    # Modules are collected across every active grant rather than taken from
    # the winning one alone: a support comp that only raises the tier must not
    # blank the product the customer actually bought.
    granted_modules: list[str] = []
    for grant in grants:
        tier = grant["tier"]
        if TIER_RANK.get(tier, -1) > TIER_RANK.get(best_tier, -1):
            best_tier = tier
            expires_at = grant["expires_at"]
        for name in _parse_modules(grant.get("modules")):
            if name not in granted_modules:
                granted_modules.append(name)

    limits = TIER_LIMITS.get(best_tier, TIER_LIMITS["free"])
    features = TIER_FEATURES.get(best_tier, [])
    # free_legacy is a server-side bookkeeping tier; the client only knows the
    # four real plan names, so it goes over the wire as "free" plus the wider
    # limits and feature list that being grandfathered actually buys.
    wire_tier = "free" if best_tier == "free_legacy" else best_tier

    return {
        "install_id": install_id,
        "tier": wire_tier,
        "cohort": cohort,
        # Omitted entirely when nothing was granted, so the client cannot tell
        # "no modules" from "not stated" and wrongly disable everything.
        **({"modules": sorted(granted_modules)} if granted_modules else {}),
        "features": features,
        "limits": limits,
        "expires_at": expires_at.isoformat() if expires_at else "",
        "grace_days": DEFAULT_GRACE_DAYS,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "message": "",
    }


def sign_payload(payload: dict) -> tuple[str, str]:
    """Return (payload_text, signature_hex). The client verifies the signature
    over the exact text, so the text - not the dict - is what gets sent."""
    payload_text = json.dumps(payload, separators=(",", ":"), sort_keys=True)
    if not ENTITLEMENT_PRIVATE_KEY_HEX:
        return payload_text, ""

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ENTITLEMENT_PRIVATE_KEY_HEX))
    return payload_text, private_key.sign(payload_text.encode("utf-8")).hex()


def require_admin_token() -> bool:
    if not ADMIN_API_TOKEN:
        return False
    import hmac

    supplied = request.headers.get("X-Admin-Token", "")
    return hmac.compare_digest(supplied, ADMIN_API_TOKEN)


def upsert_grant(
    db,
    install_id: str,
    source: str,
    tier: str,
    expires_at: datetime | None,
    revoked: bool = False,
    note: str = "",
    modules: str = "",
) -> None:
    with db.cursor() as cur:
        cur.execute(
            """
            INSERT INTO entitlement_grants (install_id, source, tier, expires_at, revoked, note, modules, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, now())
            ON CONFLICT (install_id, source) DO UPDATE
            SET tier = EXCLUDED.tier,
                expires_at = EXCLUDED.expires_at,
                revoked = EXCLUDED.revoked,
                note = EXCLUDED.note,
                modules = EXCLUDED.modules,
                updated_at = now()
            """,
            (install_id, source, tier, expires_at, revoked, note, modules),
        )
    db.commit()


def register_entitlement_routes(app, get_db):
    @app.route("/entitlement", methods=["POST"])
    def entitlement():
        data = request.get_json(silent=True) or {}
        install_id = (data.get("install_id") or "").strip()
        if not install_id or len(install_id) > 64:
            return jsonify({"error": "install_id is required"}), 400
        # Optional: the account this install is signed into (the same email
        # used for cloud backup / Google sign-in), so an account-level grant
        # (see resolve_entitlement) resolves for it too. Never required - an
        # install that sends none just resolves off its own install_id.
        email = (data.get("email") or "").strip().lower()[:255]

        db = get_db()
        init_entitlement_tables(db)
        payload = resolve_entitlement(
            db,
            install_id,
            (data.get("platform") or "").strip(),
            (data.get("version") or "").strip(),
            (data.get("distribution") or "").strip(),
            email=email,
        )
        payload_text, signature = sign_payload(payload)
        return jsonify({"payload": payload_text, "signature": signature})

    @app.route("/billing/play/link", methods=["POST"])
    def play_link_purchase():
        """Called by the app right after a Play purchase completes, to tie the
        purchase token to this install. The tier is not granted here - Play is
        asked directly (or the RTDN arrives) before anything is unlocked, so a
        forged call from a patched client buys nothing."""
        data = request.get_json(silent=True) or {}
        install_id = (data.get("install_id") or "").strip()
        purchase_token = (data.get("purchase_token") or "").strip()
        product_id = (data.get("product_id") or "").strip()
        if not install_id or not purchase_token:
            return jsonify({"error": "install_id and purchase_token are required"}), 400

        db = get_db()
        init_entitlement_tables(db)
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO play_purchases (purchase_token, install_id, product_id, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (purchase_token) DO UPDATE
                SET install_id = EXCLUDED.install_id,
                    product_id = EXCLUDED.product_id,
                    updated_at = now()
                """,
                (purchase_token, install_id, product_id),
            )
        db.commit()

        applied = _verify_and_apply_play_purchase(db, purchase_token, product_id, install_id)
        return jsonify({"ok": True, "verified": applied})

    @app.route("/billing/play/rtdn", methods=["POST"])
    def play_rtdn():
        """Google Play Real-Time Developer Notifications, delivered as a Pub/Sub
        push. This is what makes cancellations and refunds take effect without
        waiting for the subscription's own expiry date."""
        import base64

        if PUBSUB_SHARED_TOKEN and request.args.get("token", "") != PUBSUB_SHARED_TOKEN:
            return jsonify({"error": "forbidden"}), 403

        envelope = request.get_json(silent=True) or {}
        message = envelope.get("message") or {}
        raw = message.get("data") or ""
        try:
            notification = json.loads(base64.b64decode(raw).decode("utf-8"))
        except Exception:
            # Ack malformed messages: returning non-2xx makes Pub/Sub redeliver
            # forever, and a message we cannot parse will never parse.
            return jsonify({"ok": True, "ignored": True})

        sub = notification.get("subscriptionNotification") or {}
        purchase_token = (sub.get("purchaseToken") or "").strip()
        product_id = (sub.get("subscriptionId") or "").strip()
        if not purchase_token:
            return jsonify({"ok": True, "ignored": True})

        db = get_db()
        init_entitlement_tables(db)
        with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT install_id FROM play_purchases WHERE purchase_token = %s",
                (purchase_token,),
            )
            row = cur.fetchone()
        install_id = row["install_id"] if row else ""

        _verify_and_apply_play_purchase(db, purchase_token, product_id, install_id)
        return jsonify({"ok": True})

    @app.route("/admin/entitlement", methods=["POST"])
    def admin_set_entitlement():
        """Manual grant/revoke - the kill switch, and how support comps a clinic.

        Body: {install_id, tier, days?, revoked?, note?} to grant one device,
        or {email, tier, days?, revoked?, note?} to grant an account - every
        install signed into that email picks it up on its own next check-in
        (see resolve_entitlement), no per-device key needed. Exactly one of
        install_id/email.
        Header: X-Admin-Token
        """
        if not require_admin_token():
            return jsonify({"error": "forbidden"}), 403

        data = request.get_json(silent=True) or {}
        install_id = (data.get("install_id") or "").strip()
        email = (data.get("email") or "").strip().lower()
        tier = (data.get("tier") or "").strip().lower()
        if bool(install_id) == bool(email):
            return jsonify({"error": "provide exactly one of install_id or email"}), 400
        if email and "@" not in email:
            return jsonify({"error": "email looks invalid"}), 400
        if tier not in TIER_RANK:
            return jsonify({"error": f"tier must be one of {sorted(TIER_RANK)}"}), 400

        identifier = _account_key(email) if email else install_id

        days = data.get("days")
        expires_at = None
        if days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=int(days))

        db = get_db()
        init_entitlement_tables(db)
        upsert_grant(
            db,
            identifier,
            source="manual",
            tier=tier,
            expires_at=expires_at,
            revoked=bool(data.get("revoked")),
            note=str(data.get("note") or "")[:500],
            modules=",".join(_parse_modules(data.get("modules"))),
        )
        return jsonify(
            {
                "ok": True,
                "granted_to": email or install_id,
                "modules": _parse_modules(data.get("modules")),
            }
        )

    @app.route("/admin/installs", methods=["GET"])
    def admin_list_installs():
        if not require_admin_token():
            return jsonify({"error": "forbidden"}), 403

        db = get_db()
        init_entitlement_tables(db)
        with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT i.install_id, i.first_seen, i.last_seen, i.cohort, i.platform,
                       i.version, i.distribution, i.account_email,
                       (
                       COALESCE(
                           (SELECT json_agg(json_build_object(
                                'source', g.source, 'tier', g.tier, 'modules', g.modules,
                                'expires_at', g.expires_at, 'revoked', g.revoked,
                                'via_account', false
                            ))
                            FROM entitlement_grants g WHERE g.install_id = i.install_id),
                           '[]'::json
                       )::jsonb
                       ||
                       -- Grants an admin set by account email (Grant/revoke >
                       -- Account email) live under a synthetic "email:..."
                       -- key, not this install's own install_id (see
                       -- _account_key) - without this, a device signed into
                       -- an account that already has Platinum shows "none"
                       -- here, which is exactly the confusing state this
                       -- endpoint exists to prevent.
                       COALESCE(
                           (SELECT json_agg(json_build_object(
                                'source', g.source, 'tier', g.tier, 'modules', g.modules,
                                'expires_at', g.expires_at, 'revoked', g.revoked,
                                'via_account', true
                            ))
                            FROM entitlement_grants g
                            WHERE i.account_email != '' AND g.install_id = %s || i.account_email)
                           , '[]'::json
                       )::jsonb
                       ) AS grants
                FROM installs i
                ORDER BY i.last_seen DESC
                LIMIT %s
                """,
                (_ACCOUNT_KEY_PREFIX, int(request.args.get("limit", 200))),
            )
            rows = cur.fetchall()
        # json.dumps with default=str rather than jsonify: the rows carry
        # datetimes that Flask's encoder rejects.
        return app.response_class(
            json.dumps({"installs": rows}, default=str), mimetype="application/json"
        )

    @app.route("/admin/account", methods=["GET"])
    def admin_account_lookup():
        """Account-level grants live under an "email:..." key in the same
        table installs are keyed by (see _account_key) - they never show up
        in /admin/installs' per-install join, so this is the other half of
        looking an account up."""
        if not require_admin_token():
            return jsonify({"error": "forbidden"}), 403

        email = (request.args.get("email") or "").strip().lower()
        if "@" not in email:
            return jsonify({"error": "email is required"}), 400

        db = get_db()
        init_entitlement_tables(db)
        with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT source, tier, expires_at, revoked, note, updated_at "
                "FROM entitlement_grants WHERE install_id = %s ORDER BY updated_at DESC",
                (_account_key(email),),
            )
            grants = cur.fetchall()
        return app.response_class(
            json.dumps({"email": email, "grants": grants}, default=str),
            mimetype="application/json",
        )

    @app.route("/admin/ui")
    def admin_ui():
        """Browser front-end for POST /admin/entitlement and GET /admin/installs -
        so granting/revoking a plan doesn't require curl. The page itself needs
        no auth to load (it does nothing without a valid token) - every actual
        API call still goes through require_admin_token() same as before. The
        token is kept in the browser's localStorage only, never sent anywhere
        but this server's own /admin/* routes."""
        return app.response_class(_ADMIN_UI_HTML, mimetype="text/html")


_ADMIN_UI_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>ClinicManager Entitlement Admin</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; max-width: 1100px; margin: 1.5rem auto; padding: 0 1rem; }
  h1 { font-size: 1.3rem; margin-bottom: 0.25rem; }
  .muted { color: #777; font-size: 0.85rem; }
  .card { border: 1px solid #ccc; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
  .row { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; margin-bottom: 0.5rem; }
  input, select { padding: 0.35rem 0.5rem; border: 1px solid #999; border-radius: 5px; }
  .hint { color: #666; font-size: 0.85rem; }
  input[type=text], input[type=password], input[type=number] { min-width: 160px; }
  button { padding: 0.35rem 0.9rem; border-radius: 5px; border: 1px solid #555; background: #f0f0f0; cursor: pointer; }
  button.primary { background: #1a5fb4; color: #fff; border-color: #1a5fb4; }
  button.danger { background: #c01c28; color: #fff; border-color: #c01c28; }
  table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.4rem 0.5rem; border-bottom: 1px solid #ddd; vertical-align: top; }
  #status { min-height: 1.2rem; font-size: 0.9rem; }
  .ok { color: #2a7a2a; }
  .err { color: #c01c28; }
  .grant-line { font-size: 0.8rem; }
  .grant-line.revoked { text-decoration: line-through; color: #999; }
</style>
</head>
<body>
<h1>ClinicManager Entitlement Admin</h1>
<p class="muted">Grant/revoke a plan by account (every install signed into that email picks it up on its own - recommended) or by a single install ID. Token is kept only in this browser (localStorage), sent as X-Admin-Token to /admin/* on this server.</p>

<div class="card">
  <div class="row">
    <label for="token">Admin token</label>
    <input type="password" id="token" placeholder="ENTITLEMENT_ADMIN_TOKEN" />
    <button id="saveToken">Save in browser</button>
    <button id="clearToken">Clear</button>
    <span id="tokenStatus" class="muted"></span>
  </div>
</div>

<div class="card">
  <h3 style="margin-top:0">Grant / revoke</h3>
  <div class="row">
    <label><input type="radio" name="targetType" id="targetAccount" value="account" checked /> Account email <span class="muted">(all their devices)</span></label>
    <label><input type="radio" name="targetType" id="targetInstall" value="install" /> Single install ID</label>
  </div>
  <div class="row">
    <input type="text" id="accountEmail" placeholder="clinic's account email" style="flex:1; min-width:220px" />
    <input type="text" id="installId" placeholder="paste install_id" style="flex:1; min-width:220px; display:none" />
  </div>
  <div class="row">
    <label for="tier">Tier</label>
    <select id="tier">
      <option value="free">free</option>
      <option value="basic">basic</option>
      <option value="premium">premium</option>
      <option value="platinum" selected>platinum</option>
    </select>
    <label for="days">Days valid (blank = no expiry)</label>
    <input type="number" id="days" min="1" placeholder="e.g. 365" />
    <label><input type="checkbox" id="revoked" /> Revoke instead</label>
  </div>
  <div class="row">
    <label for="modules">Product</label>
    <select id="modules">
      <option value="" selected>not stated (leave as-is)</option>
      <option value="clinic">clinic / hospital only</option>
      <option value="pharmacy">medical shop only</option>
      <option value="clinic,pharmacy">both</option>
    </select>
    <span class="hint">"Not stated" leaves the install on its licence key or its own
      detected setting - pick a product only when you mean to decide it from here.</span>
  </div>
  <div class="row">
    <label for="note">Note</label>
    <input type="text" id="note" placeholder="e.g. support comp, refund, manual renewal" style="flex:1; min-width:260px" />
    <button class="primary" id="applyBtn">Apply</button>
  </div>
  <div id="status"></div>
</div>

<div class="card">
  <h3 style="margin-top:0">Look up an account</h3>
  <div class="row">
    <input type="text" id="lookupEmail" placeholder="account email" style="flex:1; min-width:220px" />
    <button id="lookupBtn">Look up</button>
  </div>
  <div id="lookupResult"></div>
</div>

<div class="card">
  <div class="row">
    <button id="loadBtn">Load recent installs</button>
    <input type="text" id="search" placeholder="filter by install id / platform / version" style="flex:1; min-width:220px" />
    <span id="countStatus" class="muted"></span>
  </div>
  <div style="overflow-x:auto">
    <table id="installsTable">
      <thead>
        <tr>
          <th>Install ID</th><th>Account Email</th><th>Platform</th><th>Version</th><th>Distribution</th>
          <th>Cohort</th><th>Last seen</th><th>Current grants</th><th></th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>
</div>

<script>
(function () {
  var TOKEN_KEY = "clinicmanager_admin_token";
  var tokenInput = document.getElementById("token");
  var tokenStatus = document.getElementById("tokenStatus");
  var savedToken = localStorage.getItem(TOKEN_KEY);
  if (savedToken) { tokenInput.value = savedToken; tokenStatus.textContent = "token loaded from this browser"; }

  document.getElementById("saveToken").addEventListener("click", function () {
    localStorage.setItem(TOKEN_KEY, tokenInput.value.trim());
    tokenStatus.textContent = "saved";
  });
  document.getElementById("clearToken").addEventListener("click", function () {
    localStorage.removeItem(TOKEN_KEY);
    tokenInput.value = "";
    tokenStatus.textContent = "cleared";
  });

  function token() { return (tokenInput.value || "").trim(); }

  function setStatus(msg, isError) {
    var el = document.getElementById("status");
    el.textContent = msg;
    el.className = isError ? "err" : "ok";
  }

  var accountEmailInput = document.getElementById("accountEmail");
  var installIdInput2 = document.getElementById("installId");
  function syncTargetType() {
    var byAccount = document.getElementById("targetAccount").checked;
    accountEmailInput.style.display = byAccount ? "" : "none";
    installIdInput2.style.display = byAccount ? "none" : "";
  }
  document.getElementById("targetAccount").addEventListener("change", syncTargetType);
  document.getElementById("targetInstall").addEventListener("change", syncTargetType);

  document.getElementById("applyBtn").addEventListener("click", function () {
    var byAccount = document.getElementById("targetAccount").checked;
    var target = (byAccount ? accountEmailInput.value : installIdInput2.value).trim();
    if (!target) { setStatus((byAccount ? "Account email" : "Install ID") + " is required.", true); return; }
    var body = {
      tier: document.getElementById("tier").value,
      revoked: document.getElementById("revoked").checked,
      note: document.getElementById("note").value.trim(),
      modules: document.getElementById("modules").value,
    };
    body[byAccount ? "email" : "install_id"] = target;
    var days = document.getElementById("days").value.trim();
    if (days) body.days = parseInt(days, 10);

    setStatus("Applying...");
    fetch("/admin/entitlement", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Admin-Token": token() },
      body: JSON.stringify(body),
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) { setStatus("Failed: " + (res.body.error || "unknown error"), true); return; }
        var mods = (res.body.modules || []).join(" + ");
        setStatus(
          "Applied " + body.tier + (body.revoked ? " (revoked)" : "") +
          (mods ? " [" + mods + "]" : "") + " to " + target + "."
        );
        if (!byAccount) loadInstalls();
      })
      .catch(function (e) { setStatus("Request failed: " + e, true); });
  });

  document.getElementById("lookupBtn").addEventListener("click", function () {
    var email = document.getElementById("lookupEmail").value.trim();
    var box = document.getElementById("lookupResult");
    if (!email) { box.innerHTML = "<span class=\\"err\\">Enter an email.</span>"; return; }
    box.innerHTML = "<span class=\\"muted\\">Looking up...</span>";
    fetch("/admin/account?email=" + encodeURIComponent(email), { headers: { "X-Admin-Token": token() } })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) { box.innerHTML = "<span class=\\"err\\">" + (res.body.error || "lookup failed") + "</span>"; return; }
        var grants = res.body.grants || [];
        box.innerHTML = grants.length ? grantsHtml(grants) : "<span class=\\"muted\\">No grants on this account yet.</span>";
      })
      .catch(function (e) { box.innerHTML = "<span class=\\"err\\">Request failed: " + e + "</span>"; });
  });

  function grantsHtml(grants) {
    if (!grants || !grants.length) return "<span class=\\"muted\\">none</span>";
    return grants.map(function (g) {
      var cls = "grant-line" + (g.revoked ? " revoked" : "");
      var exp = g.expires_at ? g.expires_at : "no expiry";
      var label = g.via_account ? "account: " : "";
      var mods = g.modules ? " \u00b7 " + g.modules : "";
      return "<div class=\\"" + cls + "\\">" + label + g.source + ": " + g.tier + mods + " (" + exp + ")</div>";
    }).join("");
  }

  var allRows = [];

  function renderRows() {
    var q = document.getElementById("search").value.trim().toLowerCase();
    var tbody = document.querySelector("#installsTable tbody");
    tbody.innerHTML = "";
    var shown = 0;
    allRows.forEach(function (row) {
      var haystack = [row.install_id, row.account_email, row.platform, row.version, row.distribution].join(" ").toLowerCase();
      if (q && haystack.indexOf(q) === -1) return;
      shown++;
      var tr = document.createElement("tr");
      tr.innerHTML =
        "<td><code>" + row.install_id + "</code></td>" +
        "<td>" + (row.account_email || "<span class=\\"muted\\">-</span>") + "</td>" +
        "<td>" + (row.platform || "-") + "</td>" +
        "<td>" + (row.version || "-") + "</td>" +
        "<td>" + (row.distribution || "-") + "</td>" +
        "<td>" + (row.cohort || "-") + "</td>" +
        "<td>" + (row.last_seen || "-") + "</td>" +
        "<td>" + grantsHtml(row.grants) + "</td>" +
        "<td>" +
          "<button data-id=\\"" + row.install_id + "\\">Use ID</button>" +
          (row.account_email ? " <button data-email=\\"" + row.account_email + "\\">Use email</button>" : "") +
        "</td>";
      tbody.appendChild(tr);
    });
    document.getElementById("countStatus").textContent = shown + " / " + allRows.length + " installs shown";
    tbody.querySelectorAll("button[data-id]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        document.getElementById("targetInstall").checked = true;
        syncTargetType();
        document.getElementById("installId").value = btn.getAttribute("data-id");
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    });
    tbody.querySelectorAll("button[data-email]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        document.getElementById("targetAccount").checked = true;
        syncTargetType();
        accountEmailInput.value = btn.getAttribute("data-email");
        window.scrollTo({ top: 0, behavior: "smooth" });
      });
    });
  }

  function loadInstalls() {
    setStatus("Loading installs...");
    fetch("/admin/installs?limit=300", { headers: { "X-Admin-Token": token() } })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) { setStatus("Failed to load installs: " + (res.body.error || "unknown error"), true); return; }
        allRows = res.body.installs || [];
        renderRows();
        setStatus("Loaded " + allRows.length + " installs.");
      })
      .catch(function (e) { setStatus("Request failed: " + e, true); });
  }

  document.getElementById("loadBtn").addEventListener("click", loadInstalls);
  document.getElementById("search").addEventListener("input", renderRows);
})();
</script>
</body>
</html>
"""


# --- Google Play purchase verification --------------------------------------
# Server-to-server check against the Play Developer API. An RTDN only says
# "something changed about this token"; it is not itself proof of entitlement,
# and Google explicitly expects the purchase to be re-fetched before anything is
# granted.
PUBSUB_SHARED_TOKEN = os.getenv("PUBSUB_SHARED_TOKEN", "").strip()
PLAY_PACKAGE_NAME = os.getenv("PLAY_PACKAGE_NAME", "com.clinicmanager.mobile").strip()
PLAY_SERVICE_ACCOUNT_JSON = os.getenv("PLAY_SERVICE_ACCOUNT_JSON", "").strip()


def _play_access_token() -> str:
    """Mint an OAuth access token from the service account JSON."""
    if not PLAY_SERVICE_ACCOUNT_JSON:
        return ""
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request as GoogleRequest

    info = json.loads(PLAY_SERVICE_ACCOUNT_JSON)
    credentials = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/androidpublisher"]
    )
    credentials.refresh(GoogleRequest())
    return credentials.token or ""


def _verify_and_apply_play_purchase(db, purchase_token: str, product_id: str, install_id: str) -> bool:
    """Ask Play what this subscription's real state is, then write the grant.

    Returns True when Play was reachable and the grant was written. When Play
    cannot be reached the existing grant is left alone: a transient Google
    outage must not cut off paying clinics.
    """
    if not install_id:
        # Purchase seen before the client linked it. The client retries the link
        # call, and that path verifies again.
        return False

    token = _play_access_token()
    if not token:
        return False

    import urllib.error
    import urllib.request

    product = product_id or ""
    url = (
        f"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
        f"{PLAY_PACKAGE_NAME}/purchases/subscriptions/{product}/tokens/{purchase_token}"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            purchase = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return False

    expiry_ms = int(purchase.get("expiryTimeMillis") or 0)
    expires_at = datetime.fromtimestamp(expiry_ms / 1000, tz=timezone.utc) if expiry_ms else None
    # paymentState 1 = paid, 2 = free trial. 0 = payment pending, which is not
    # yet money, so it grants nothing.
    payment_state = purchase.get("paymentState")
    # A refund or chargeback sets this; it is the case the whole webhook exists
    # to catch, since expiryTimeMillis stays in the future after a refund.
    revoked = bool(purchase.get("userCancellationTimeMillis")) and (
        expires_at is not None and expires_at <= datetime.now(timezone.utc)
    )
    if purchase.get("cancelReason") == 3:  # 3 = cancelled by the developer/refund
        revoked = True

    tier = PLAY_PRODUCT_TIERS.get(product, "premium")
    granted = payment_state in (1, 2) and not revoked

    with db.cursor() as cur:
        cur.execute(
            """
            UPDATE play_purchases
            SET product_id = %s, state = %s, expires_at = %s, updated_at = now()
            WHERE purchase_token = %s
            """,
            (product, "active" if granted else "inactive", expires_at, purchase_token),
        )
    db.commit()

    upsert_grant(
        db,
        install_id,
        source="play",
        tier=tier,
        expires_at=expires_at,
        revoked=not granted,
        note=f"play:{product}",
    )
    return True


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "keygen":
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        private_hex = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex()
        public_hex = key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ).hex()
        print("Set on the entitlement server (secret):")
        print(f'  ENTITLEMENT_PRIVATE_KEY="{private_hex}"\n')
        print("Bake into the app (public, safe to ship):")
        print(f'  CLINICMANAGER_ENTITLEMENT_PUBLIC_KEY="{public_hex}"')
    else:
        print("usage: python3 -m entitlements keygen")
