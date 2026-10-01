# Mock leaf entity (dev only)

The Resolve endpoint fetches the subject's entity configuration over HTTPS from
`<sub>/.well-known/openid-federation`. Your TA database has `https://rp.example.com` registered as
a subordinate, but nothing actually serves that URL. This tiny script does — it signs and serves a
leaf Entity Configuration so the resolver has something real to walk.

It is **dev-only**, lives outside the module, and is never deployed.

## What it serves

A self-signed `entity-statement+jwt` with:
- `iss` = `sub` = the leaf entity ID
- `jwks` = the leaf's own public key
- `authority_hints` = `[ <TA> ]`
- `metadata.openid_relying_party` = a small sample RP metadata block
- `trust_marks` = `[ { trust_mark_type, trust_mark } ]` if you pass a mark to embed

## 1. Generate the leaf key and read its JWKS

```bash
cd dev-tools/mock-leaf
php serve.php print-jwks
```

This creates `leaf.key` (RSA-2048) on first run and prints the public JWKS, e.g.:

```json
{ "keys": [ { "kty": "RSA", "n": "…", "e": "AQAB", "use": "sig", "alg": "RS256", "kid": "…" } ] }
```

## 2. Register the leaf as a subordinate in the TA

In the TA admin UI (**OIDC Federation Subordinates → Register**):
- **Entity ID:** `https://rp.example.com` (must match `MOCK_LEAF_ENTITY_ID`)
- **Entity type:** `openid_relying_party`
- **JWKS:** paste the JSON from step 1

This makes `/federation/fetch?iss=<TA>&sub=https://rp.example.com` issue a subordinate statement
whose embedded JWKS matches the leaf's signing key — which is what lets the chain verify.

## 3. (Optional) Embed a Trust Mark

Issue a Trust Mark for `https://rp.example.com` (step 7 admin UI), copy its compact JWT, then:

```bash
export MOCK_LEAF_TRUST_MARK="eyJ…"      # the issued mark JWT
```

The leaf will include it under `trust_marks` so the resolver validates it (and calls the TA's
in-process `TrustMarkStatusService`).

## 4. Serve it

```bash
export MOCK_LEAF_ENTITY_ID="https://rp.example.com"
export MOCK_LEAF_TA="https://ta.local.stack-dev.cirrusidentity.com"
php -S 0.0.0.0:8080 serve.php
```

`serve.php` answers **every** path with the entity configuration, so
`http://localhost:8080/.well-known/openid-federation` returns the signed JWT.

## 5. Make it reachable at the subject's HTTPS URL

The resolver only fetches **HTTPS** URLs and uses the entity ID verbatim, so
`https://rp.example.com/.well-known/openid-federation` must resolve to this server. Pick one:

- **Reverse proxy (recommended for the Docker stack):** add an nginx/apache vhost (or a compose
  service) for `rp.example.com` that terminates TLS and proxies to `127.0.0.1:8080`. Map
  `rp.example.com` to the proxy via `/etc/hosts` (or the Docker network).
- **Self-signed TLS + skip verification (quickest):** serve over TLS with a self-signed cert and set
  `'http_verify_tls' => false` under `resolve` in `module_oidanchor.php` (or
  `OIDANCHOR_RESOLVE_VERIFY_TLS=false`). **Dev only.**
- **Point the demo at a reachable ID:** set `MOCK_LEAF_ENTITY_ID` to an HTTPS URL you can actually
  serve (and register that same ID as the subordinate), then resolve that `sub`.

> The TA's own entity configuration (`<TA>/.well-known/openid-federation`) and
> `federation_fetch_endpoint` must also be reachable from the resolver process — they are, since
> that's the running TA. In Docker, ensure the TA can reach both itself and the leaf URL.
