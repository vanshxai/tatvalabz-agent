# TatvaLabz Local Agent (MVP)

This is the local desktop bridge for TatvaLabz.

## What works in this MVP

- Local agent daemon on `127.0.0.1:8787`
- Persistent local config (`agent/.agent-state/config.json` by default)
- Signed pair / unpair API (Phase 2)
- Permission config API
- Heartbeat worker to cloud backend endpoint
- WebSocket control channel with reconnect (`/api/agent/ws`)

## Run

```bash
cd agent
npm start
```

Optional: override config home

```bash
TATVALABZ_AGENT_HOME=/path/to/agent-data npm start
```

## Local API

### Health

```bash
curl http://127.0.0.1:8787/health
```

### Pair

Signed pairing (recommended):

```bash
export AGENT_PAIR_SECRET='your-shared-secret'

# 1) Start agent with secret
AGENT_PAIR_SECRET="$AGENT_PAIR_SECRET" npm start
```

In a second terminal:

```bash
# 2) Generate a signed test payload (simulates web backend signing)
curl -X POST http://127.0.0.1:8787/pair/sign-test \
  -H 'content-type: application/json' \
  -d '{"pairingCode":"demo-123","backendUrl":"https://your-backend.example.com"}'

# 3) Use signed payload with /pair/signed
curl -X POST http://127.0.0.1:8787/pair/signed \
  -H 'content-type: application/json' \
  -d '{"pairingCode":"demo-123","backendUrl":"https://your-backend.example.com","expiresAt":"...","nonce":"...","signature":"..."}'
```

Legacy insecure pairing (for local only):

```bash
ALLOW_INSECURE_PAIR=1 npm start
curl -X POST http://127.0.0.1:8787/pair \
  -H 'content-type: application/json' \
  -d '{"pairingCode":"abc123","backendUrl":"https://your-backend.example.com"}'
```

### Update permissions

```bash
curl -X POST http://127.0.0.1:8787/permissions \
  -H 'content-type: application/json' \
  -d '{"permissions":{"network":true,"serial":true}}'
```

### Unpair

```bash
curl -X POST http://127.0.0.1:8787/unpair
```

## Next steps

- Replace shared-secret signing with backend-issued short-lived JWT device token
- Move from HTTP+WS to gRPC stream transport
- Add connector runtime (Modbus, serial)
- Add job runner sandbox for compute workloads

## What To Verify

1. Agent process is up
2. `GET /health` returns `ok: true`
3. After signed pair, `/status` shows:
  - `paired: true`
  - `securePairingEnabled: true`
  - `controlChannel.connected` eventually true (when backend WS endpoint exists)
4. `POST /permissions` updates are reflected in `/status`
