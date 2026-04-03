# PAN Vault — Web UI

Credit-card encryption & tokenization service with a browser interface.

## Run

```bash
pip install -r requirements.txt
python3 app.py
# Open http://localhost:5050
```

## API

| Method | Path | Body | Description |
|--------|------|------|-------------|
| POST | `/api/tokenize` | `{"pan":"..."}` | Encrypt & tokenize a PAN |
| POST | `/api/detokenize` | `{"token":"..."}` | Decrypt by token |
| DELETE | `/api/revoke/:token` | — | Revoke a token |
| GET | `/api/vault` | — | List all vault records |
