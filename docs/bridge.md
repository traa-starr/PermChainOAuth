# OAuth Bridge (Flow A: User-Mints, No Relayer)

This bridge uses an OAuth-ish pattern where:
- **On-chain receipt** = durable grant record.
- **JWT access token** = fast API credential.

The server never mints and never needs an on-chain wallet private key.

Scope hashes use domain-separated v1 hashing everywhere:
- Solidity: `scopeHash(scope)` from `PermissionReceipt`
- Node: `hashScope(scope)` from `server.js`
- Digest rule: `keccak256("PERMCHAIN_SCOPE_V1:" + scope)`

## Run

```bash
npm install
RPC_URL=https://sepolia.infura.io/v3/<key> \
CHAIN_ID=11155111 \
CONTRACT_ADDRESS=0xYourPermissionReceipt \
JWT_ALG=RS256 \
JWT_KID=bridge-key-2026-01 \
JWT_PRIVATE_KEY_PEM="$(cat ./jwt-private.pem)" \
SIWE_DOMAIN=localhost \
node server.js
```

## Env vars

- `RPC_URL` (required)
- `CHAIN_ID` (default `11155111`)
- `CONTRACT_ADDRESS` (required)
- `JWT_ALG` (default `RS256`)
- `JWT_PRIVATE_KEY_PEM` (required when `JWT_ALG=RS256`; PEM string used to sign access tokens)
- `JWT_KID` (required when `JWT_ALG=RS256`; active signing key id)
- `JWT_PUBLIC_KEYS_JSON` (optional JSON array of `{ "kid": "...", "publicKeyPem": "..." }` for verification during rotation)
- `JWT_SECRET` (required only when using non-RS256 HMAC modes)
- `SIWE_DOMAIN` (default `localhost`)
- `TOKEN_TTL_SECONDS` (default `900`)
- `RECEIPT_TTL_SECONDS` (default `3600`)
- `REQUIRED_SCOPE` (default `ai:train_data`)
- `PORT` (default `3001`)

## JWKS endpoint

The bridge publishes verification keys at:

- `GET /.well-known/jwks.json`

Response shape:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "bridge-key-2026-01",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

`keys` includes the active signing key (`JWT_KID`) and any additional keys supplied via `JWT_PUBLIC_KEYS_JSON`.

## JWT headers

Access tokens are signed with a JOSE header that includes key id:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "bridge-key-2026-01"
}
```

## End-to-end flow

### 1) Get nonce for authorize
```bash
curl -s http://localhost:3001/nonce \
  -H 'content-type: application/json' \
  -d '{"address":"0xGranter","purpose":"authorize"}'
```

### 2) Authorize (SIWE + mint intent)
```bash
curl -s http://localhost:3001/authorize \
  -H 'content-type: application/json' \
  -d '{
    "siweMessage":"<EIP-4361 with authorize nonce>",
    "siweSignature":"0x...",
    "grantee":"0xGrantee",
    "scopes":["ai:train_data"],
    "metadataURI":"ipfs://meta"
  }'
```

Returns a `mintIntent` with:
- contract address
- chain id
- granter / grantee
- `scopeHashes` (`bytes32[]`)
- `expiresAt`
- `proofHash`

### 3) Frontend wallet submits mint tx
The granter wallet submits contract mint directly. Contract semantics should set `granter = msg.sender`.

### 4) Get nonce for token exchange
```bash
curl -s http://localhost:3001/nonce \
  -H 'content-type: application/json' \
  -d '{"address":"0xGrantee","purpose":"token"}'
```

### 5) Exchange receipt for JWT
```bash
curl -s http://localhost:3001/token \
  -H 'content-type: application/json' \
  -d '{
    "receiptId": 1,
    "siweMessage":"<EIP-4361 with token nonce>",
    "siweSignature":"0x...",
    "requiredScopeHashes":["0x<hashScope(ai:train_data)>"]
  }'
```

Server validates:
- SIWE signature + nonce
- SIWE signer equals on-chain receipt grantee
- receipt valid for required scope hash (not revoked/expired)

JWT includes `sub`, `azp`, `receiptId`, `scopeHashes`, and `exp`.

### 6) Introspect
```bash
curl -s http://localhost:3001/introspect \
  -H 'content-type: application/json' \
  -d '{
    "token":"<access_token>",
    "requiredScopeHash":"0x<hashScope(ai:train_data)>"
  }'
```

### 7) Protected API example
```bash
curl -s http://localhost:3001/data \
  -H "authorization: Bearer <access_token>"
```
