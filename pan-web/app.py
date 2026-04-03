"""
app.py  —  PAN Vault Web Service
Run:  python3 app.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, render_template
from tokenization_service import TokenizationService
from pan_encryptor import EncryptionError

app = Flask(__name__)
svc = TokenizationService()


# ── API routes ────────────────────────────────────────────────────────────────

@app.post("/api/tokenize")
def tokenize():
    pan = (request.json or {}).get("pan", "").strip()
    try:
        rec = svc.tokenize(pan)
        return jsonify({
            "token":       rec.token,
            "masked_pan":  rec.masked_pan,
            "card_scheme": rec.card_scheme,
            "iv":          rec.iv,
            "cipher_text": rec.cipher_text,
            "auth_tag":    rec.auth_tag,
        })
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.post("/api/detokenize")
def detokenize():
    token = (request.json or {}).get("token", "").strip()
    try:
        with svc.detokenize(token) as card:
            pan = card.pan
        return jsonify({"pan": pan})
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    except EncryptionError as e:
        return jsonify({"error": str(e)}), 400


@app.delete("/api/revoke/<token>")
def revoke(token):
    removed = svc.revoke_token(token)
    if removed:
        return jsonify({"ok": True})
    return jsonify({"error": "Token not found"}), 404


@app.get("/api/vault")
def vault():
    return jsonify([
        {
            "token":       t,
            "masked_pan":  r.masked_pan,
            "card_scheme": r.card_scheme,
        }
        for t, r in svc.vault_snapshot().items()
    ])


@app.get("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True, port=5050)
