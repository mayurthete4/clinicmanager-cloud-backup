"""Prepaid message-credit wallet, and the actual WhatsApp/SMS send path.

Why this lives on the server, not in each install's local SQLite: a clinic
often runs more than one device (PC + phone), and a wallet keyed to the local
database would let each device believe it has the clinic's full balance -
spend from one, the other still shows the old number. Centralizing it here
mirrors why entitlement itself is server-owned: one source of truth per
clinic, reachable from every device.

Sending itself happens here too, not on the client, for a simpler reason: a
gateway API key (Gupshup/Twilio/MSG91) is a secret that must never ship inside
an app a customer's device can decompile. The client only ever asks this
server to send a message and deduct one credit; it never talks to the gateway
directly.

Nothing here is wired to a real gateway yet - MESSAGE_GATEWAY_PROVIDER
defaults to "none", which fails sends with a clear reason instead of quietly
pretending to have sent something. Wiring a real provider is one function
(`_send_via_gateway`) plus the account credentials, both described below.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
from flask import jsonify, request

# Which gateway actually sends the message. "none" (the default) means no
# vendor account has been wired up yet - sends fail with a clear, honest error
# rather than silently no-oping or fake-succeeding.
MESSAGE_GATEWAY_PROVIDER = os.getenv("MESSAGE_GATEWAY_PROVIDER", "none").strip().lower()

# Per-credit prices you sell at, in your smallest currency unit (paise for
# INR), keyed by channel - WhatsApp and SMS cost different amounts from most
# gateways. Used only to label ledger entries for later margin reporting; the
# actual charge to the clinic is whatever top-up pack they bought.
CREDIT_COST_PAISE = {
    "WhatsApp": int(os.getenv("MESSAGE_CREDIT_COST_WHATSAPP_PAISE", "20") or 20),
    "SMS": int(os.getenv("MESSAGE_CREDIT_COST_SMS_PAISE", "15") or 15),
}

ADMIN_API_TOKEN = os.getenv("ENTITLEMENT_ADMIN_TOKEN", "").strip()

# Play consumable product IDs -> credit count. Keep in step with the
# Play Console in-app product catalog.
PLAY_CREDIT_PACKS = {
    "clinicmanager_credits_100": 100,
    "clinicmanager_credits_500": 500,
    "clinicmanager_credits_2000": 2000,
}

_tables_ready = False


def init_wallet_tables(db) -> None:
    global _tables_ready
    if _tables_ready:
        return

    with db.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS message_wallets (
                install_id TEXT PRIMARY KEY,
                balance INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        # An append-only ledger, not just a running balance, so a disputed
        # charge or a "where did my credits go" support question has an answer
        # - the balance column is a cache of SUM(delta), rebuildable from this.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS message_ledger (
                id SERIAL PRIMARY KEY,
                install_id TEXT NOT NULL,
                delta INTEGER NOT NULL,
                reason TEXT NOT NULL,
                channel TEXT NOT NULL DEFAULT '',
                reference TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        # Play consumable purchase tokens are single-use: without recording
        # which ones were already credited, replaying the same purchase (a
        # retried client request, or a redelivered RTDN) would top up twice.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS credit_purchases (
                purchase_token TEXT PRIMARY KEY,
                install_id TEXT NOT NULL DEFAULT '',
                product_id TEXT NOT NULL DEFAULT '',
                credited BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
    db.commit()
    _tables_ready = True


def _get_balance(db, install_id: str) -> int:
    with db.cursor() as cur:
        cur.execute("SELECT balance FROM message_wallets WHERE install_id = %s", (install_id,))
        row = cur.fetchone()
    return int(row[0]) if row else 0


def _apply_ledger_entry(db, install_id: str, delta: int, reason: str, channel: str = "", reference: str = "") -> int:
    """Insert the ledger row and adjust the balance atomically, returning the
    new balance. Balance is clamped at 0 - a send that raced a concurrent
    debit to below zero is a bug to notice, not a wallet to overdraw."""
    with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            INSERT INTO message_wallets (install_id, balance, updated_at)
            VALUES (%s, GREATEST(0, %s), now())
            ON CONFLICT (install_id) DO UPDATE
            SET balance = GREATEST(0, message_wallets.balance + %s), updated_at = now()
            RETURNING balance
            """,
            (install_id, delta, delta),
        )
        new_balance = int(cur.fetchone()["balance"])
        cur.execute(
            """
            INSERT INTO message_ledger (install_id, delta, reason, channel, reference)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (install_id, delta, reason, channel, reference),
        )
    db.commit()
    return new_balance


def _send_via_gateway(channel: str, to: str, message: str) -> tuple[bool, str, str]:
    """Dispatch through whichever provider MESSAGE_GATEWAY_PROVIDER names.
    Returns (ok, provider_message_id, error).

    To wire a real vendor: add a branch here that makes the HTTP call (Gupshup,
    Twilio, MSG91 all have a single-endpoint send API), keep the credentials in
    env vars alongside MESSAGE_GATEWAY_PROVIDER, and flip that env var to the
    provider's name. Nothing else in this file or the client needs to change.
    """
    if MESSAGE_GATEWAY_PROVIDER == "none":
        return False, "", (
            "No message gateway is configured (MESSAGE_GATEWAY_PROVIDER=none). "
            "Wire a WhatsApp/SMS provider before sends can go through the wallet."
        )

    # Real providers get added here as their accounts are set up. Deliberately
    # not stubbed further than this: a fake "always succeeds" branch would
    # burn clinics' credits sending nothing and be far worse than the honest
    # "not configured yet" error above.
    return False, "", f"Unknown MESSAGE_GATEWAY_PROVIDER '{MESSAGE_GATEWAY_PROVIDER}'."


def register_wallet_routes(app, get_db):
    @app.route("/wallet/balance", methods=["POST"])
    def wallet_balance():
        data = request.get_json(silent=True) or {}
        install_id = (data.get("install_id") or "").strip()
        if not install_id:
            return jsonify({"error": "install_id is required"}), 400

        db = get_db()
        init_wallet_tables(db)
        return jsonify({"balance": _get_balance(db, install_id)})

    @app.route("/wallet/send", methods=["POST"])
    def wallet_send():
        """Send one message and deduct one credit, atomically: the deduction
        and the ledger entry only happen if the gateway actually accepted the
        message. A failed send must never cost the clinic a credit."""
        data = request.get_json(silent=True) or {}
        install_id = (data.get("install_id") or "").strip()
        channel = (data.get("channel") or "").strip()
        to = (data.get("to") or "").strip()
        message = (data.get("message") or "").strip()

        if not install_id or not to or not message:
            return jsonify({"error": "install_id, to and message are required"}), 400
        if channel not in CREDIT_COST_PAISE:
            return jsonify({"error": f"channel must be one of {sorted(CREDIT_COST_PAISE)}"}), 400

        db = get_db()
        init_wallet_tables(db)
        balance = _get_balance(db, install_id)
        if balance <= 0:
            return jsonify({"ok": False, "error": "insufficient_credits", "balance": balance}), 402

        ok, provider_message_id, error = _send_via_gateway(channel, to, message)
        if not ok:
            # No charge on failure - the whole point of checking balance before
            # calling the gateway, then only deducting after it succeeds.
            return jsonify({"ok": False, "error": error, "balance": balance}), 502

        new_balance = _apply_ledger_entry(
            db, install_id, -1, "send", channel=channel, reference=provider_message_id
        )
        return jsonify({"ok": True, "balance": new_balance, "provider_message_id": provider_message_id})

    @app.route("/wallet/topup", methods=["POST"])
    def wallet_admin_topup():
        """Manual top-up - how a direct-sale clinic (no Play Billing) buys
        credits: they pay you out of band, you run this. Body:
        {install_id, credits, reference?, note?}. Header: X-Admin-Token."""
        import hmac

        if not ADMIN_API_TOKEN or not hmac.compare_digest(
            request.headers.get("X-Admin-Token", ""), ADMIN_API_TOKEN
        ):
            return jsonify({"error": "forbidden"}), 403

        data = request.get_json(silent=True) or {}
        install_id = (data.get("install_id") or "").strip()
        credits = data.get("credits")
        if not install_id or not isinstance(credits, int) or credits <= 0:
            return jsonify({"error": "install_id and a positive integer credits are required"}), 400

        db = get_db()
        init_wallet_tables(db)
        new_balance = _apply_ledger_entry(
            db, install_id, credits, "manual_topup", reference=str(data.get("reference") or "")[:200]
        )
        return jsonify({"ok": True, "balance": new_balance})

    @app.route("/wallet/play_topup", methods=["POST"])
    def wallet_play_topup():
        """Credit a wallet from a verified Play consumable purchase. Body:
        {install_id, purchase_token, product_id}. Verifies against the Play
        Developer API before crediting anything - the same rule the
        subscription entitlement flow follows, and for the same reason: a
        client claiming "I bought credits" is not proof, only Google's own API
        response is."""
        data = request.get_json(silent=True) or {}
        install_id = (data.get("install_id") or "").strip()
        purchase_token = (data.get("purchase_token") or "").strip()
        product_id = (data.get("product_id") or "").strip()
        if not install_id or not purchase_token or product_id not in PLAY_CREDIT_PACKS:
            return jsonify({"error": "install_id, purchase_token and a known product_id are required"}), 400

        db = get_db()
        init_wallet_tables(db)

        with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT credited FROM credit_purchases WHERE purchase_token = %s", (purchase_token,)
            )
            existing = cur.fetchone()
        if existing and existing["credited"]:
            # Already credited - a retried client call or redelivered
            # notification must not double the top-up.
            return jsonify({"ok": True, "balance": _get_balance(db, install_id), "already_credited": True})

        verified = _verify_play_consumable(purchase_token, product_id)
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO credit_purchases (purchase_token, install_id, product_id, credited)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (purchase_token) DO UPDATE
                SET install_id = EXCLUDED.install_id, product_id = EXCLUDED.product_id,
                    credited = credit_purchases.credited OR EXCLUDED.credited
                """,
                (purchase_token, install_id, product_id, verified),
            )
        db.commit()

        if not verified:
            return jsonify({"ok": False, "error": "purchase_not_verified"}), 402

        new_balance = _apply_ledger_entry(
            db, install_id, PLAY_CREDIT_PACKS[product_id], "play_purchase", reference=purchase_token
        )
        return jsonify({"ok": True, "balance": new_balance})

    @app.route("/admin/wallet/<install_id>", methods=["GET"])
    def admin_wallet_ledger(install_id):
        if not ADMIN_API_TOKEN or request.headers.get("X-Admin-Token", "") != ADMIN_API_TOKEN:
            return jsonify({"error": "forbidden"}), 403

        db = get_db()
        init_wallet_tables(db)
        with db.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT delta, reason, channel, reference, created_at FROM message_ledger "
                "WHERE install_id = %s ORDER BY created_at DESC LIMIT %s",
                (install_id, int(request.args.get("limit", 100))),
            )
            rows = cur.fetchall()
        return app.response_class(
            json.dumps({"balance": _get_balance(db, install_id), "ledger": rows}, default=str),
            mimetype="application/json",
        )


def _verify_play_consumable(purchase_token: str, product_id: str) -> bool:
    """Same shape as entitlements._verify_and_apply_play_purchase, but for a
    one-time consumable rather than a subscription: check purchaseState is
    PURCHASED (0), then acknowledge/consume so Play doesn't auto-refund it."""
    from entitlements import PLAY_PACKAGE_NAME, _play_access_token

    token = _play_access_token()
    if not token:
        return False

    import urllib.error
    import urllib.request

    url = (
        f"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
        f"{PLAY_PACKAGE_NAME}/purchases/products/{product_id}/tokens/{purchase_token}"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            purchase = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
        return False

    if int(purchase.get("purchaseState", -1)) != 0:
        return False

    consume_url = (
        f"https://androidpublisher.googleapis.com/androidpublisher/v3/applications/"
        f"{PLAY_PACKAGE_NAME}/purchases/products/{product_id}/tokens/{purchase_token}:consume"
    )
    consume_req = urllib.request.Request(
        consume_url, headers={"Authorization": f"Bearer {token}"}, method="POST", data=b""
    )
    try:
        with urllib.request.urlopen(consume_req, timeout=20):
            pass
    except (urllib.error.URLError, urllib.error.HTTPError, OSError):
        # Verified but not consumed is still a valid, once-only purchase from
        # our side (credit_purchases.credited guards the replay) - Play retries
        # consumption failures on its own, this is not fatal to crediting.
        pass

    return True
