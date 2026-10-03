# capa_jwt

Pure-Capa JSON Web Tokens (JWS/JWT) with the **HS256** algorithm. Zero
capabilities: signing and verifying a token are data transforms over a
`String` and a `List<Int>` key. The library's functions declare no
capability, and the compiler refuses any capability call in them; it
reads no global state. The verifier takes **no `Clock`** either, expiry is
checked against a `now` the caller passes in, so the whole library
keeps its empty capability surface. `capa --manifest` records it (see
[Audit claim](#audit-claim)). Output is
byte-identical on the Python and Wasm backends.

The signature is `HMAC-SHA256(key, header_b64 + "." + payload_b64)`,
base64url-encoded without padding, **verified against the well-known
jwt.io HS256 vector and Python's stdlib oracle** (`hmac` / `hashlib` /
`base64` / `json`, cross-checked with PyJWT). This is a reference
implementation, **not audited by a cryptographer**. See
[Honest posture](#honest-posture) before relying on it for anything
security-critical.

## Status

v0.1 (seed library). Scope, fixed by design:

- **HS256 sign** (RFC 7519 / RFC 7515 / RFC 7518 section 3.2): build a
  compact JWS with the fixed header `{"alg":"HS256","typ":"JWT"}`.
- **HS256 verify**: three-segment check, an **algorithm gate** that
  requires `alg:"HS256"` before trusting any signature (the
  algorithm-confusion / `alg:"none"` defense), and a **constant-time**
  signature compare (never `==`).
- **Expiry check**: read the integer `exp` claim and compare it to a
  caller-supplied `now`. The library never reads the clock.

Out of scope, by design (each is a real decision, not an oversight):

- **RS256 / ES256 / EdDSA and any asymmetric algorithm.** These need
  RSA / elliptic-curve primitives, which are a separate, much larger
  design with separate guarantees. This library is HMAC-only, and it
  actively **rejects** an `RS256` header rather than pretending to
  handle it (the classic asymmetric-confusion vector).
- **HS384 / HS512.** SHA-384 / SHA-512 are out of scope in the
  underlying `capa_hash` (their 64-bit lanes do not fit with headroom
  in Capa's checked-`i64` `Int`), so this library ships HS256 only and
  rejects an `HS384` / `HS512` header.
- **`nbf` / `iat` / `aud` / `iss` validation.** Only `exp` has a helper.
  The verifier returns the payload JSON; validate the other registered
  claims in your own code with `parse_json`.
- **Encryption (JWE), key rotation, JWKS fetch.** Out of scope entirely.
  A JWT is signed, not encrypted; its payload is public. Fetching keys
  needs `Net`, which this library deliberately does not hold.

## Quick start

```capa
import capa_jwt.jwt

fun main(stdio: Stdio)
    let key = "your-256-bit-secret".bytes()

    // Sign a claim set. The header is always {"alg":"HS256","typ":"JWT"}.
    let token = sign_hs256("{\"sub\":\"alice\",\"exp\":2000000000}", key)
    stdio.println(token)

    // Verify under the same key; on success you get the payload back.
    match verify_hs256(token, key)
        Ok(claims) -> stdio.println("ok: ${claims}")
        Err(e)     -> stdio.println(jwt_error_message(e))

    // Check expiry against a caller-supplied `now` (you hold the Clock).
    match is_expired("{\"exp\":2000000000}", 1600000000)
        Ok(expired) -> stdio.println("expired: ${expired}")   // false
        Err(e)      -> stdio.println(jwt_error_message(e))
```

The full runnable example is [`example.capa`](./example.capa); it signs
a token, verifies it, reads a claim, and shows a tampered token failing.

```bash
capa install                     # vendor capa_base64 + capa_hash first
capa --run example.capa
capa --wasm --run example.capa   # byte-identical output
```

## Install via capa.toml

```toml
[dependencies.capa_jwt]
git = "https://github.com/nelsonduarte/capa_jwt"
tag = "v0.1.0"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

`capa install` runs `git verify-tag` against your GPG keyring; import
the publisher's key first (see [`SECURITY.md`](SECURITY.md) for the
fingerprint provenance and `gpg --import` instructions).

## API surface

From `capa_jwt.jwt`:

```capa
pub fun sign_hs256(payload_json: String, key: List<Int>) -> String
pub fun verify_hs256(token: String, key: List<Int>)      -> Result<String, JwtError>
pub fun is_expired(payload_json: String, now: Int)       -> Result<Bool, JwtError>

pub type JwtError =
    MalformedToken(String)       // segment count, base64, JSON, or encoding
    UnsupportedAlgorithm(String) // header `alg` is not exactly "HS256"
    InvalidSignature             // HS256 tag does not match the key
    InvalidClaim(String)         // a claim is absent or the wrong type

pub fun jwt_error_message(e: JwtError) -> String
```

The `key` is raw bytes (`List<Int>`, each in `0..255`); derive it from a
secret String with `String.bytes()`. `sign_hs256` passes `payload_json`
through verbatim, so you control the claim JSON exactly; `verify_hs256`
returns the payload JSON of a valid token.

- **`sign_hs256`** builds the header exactly as
  `{"alg":"HS256","typ":"JWT"}`, base64url-encodes the header bytes and
  the payload bytes, and appends `HMAC-SHA256(key, header_b64 + "." +
  payload_b64)` base64url-encoded. It reproduces the published jwt.io
  vector byte for byte.
- **`verify_hs256`** splits the token into exactly three segments (else
  `MalformedToken`), REQUIRES the header's `alg` to be exactly `"HS256"`
  (else `UnsupportedAlgorithm`, see below), recomputes the tag over the
  exact signing input, base64url-encodes it, and compares that string to
  the presented signature in **constant time**. On a match it decodes
  and returns the trusted payload; on a mismatch it returns
  `InvalidSignature`; on a base64 / JSON / encoding failure in the
  header, `MalformedToken`. Note the segment order: because the
  signature is checked BEFORE the payload is decoded (the payload is only
  decoded once it is trusted), a token with a malformed base64 PAYLOAD
  segment fails the signature check first and returns `InvalidSignature`,
  not `MalformedToken`. A `MalformedToken` from a decode failure
  therefore comes from the header segment (or the wrong segment count); a
  malformed payload surfaces only after a signature somehow matched.
- **`is_expired`** parses `payload_json`, reads the integer `exp` claim,
  and returns `Ok(exp <= now)`. A **missing `exp` is
  `Err(InvalidClaim(...))`**, not a silent `Ok(false)`: expiry is a
  security decision the caller must make deliberately, so a token with
  no `exp` is surfaced rather than treated as never-expiring. A
  non-object payload or a non-integer `exp` is also `InvalidClaim`; an
  unparseable payload is `MalformedToken`. `exp` is a JSON number, so it
  is read as a Float: an integer `exp` above 2^53 loses precision, and
  one **at or beyond the signed 64-bit integer range** (`+/-2^63`) is
  rejected as `InvalidClaim` rather than being converted (converting it
  would trap on the Wasm backend), deterministically on both backends.

### The algorithm-confusion defense

The #1 JWT vulnerability is algorithm confusion: an attacker rewrites
the header `alg` to `"none"` and strips the signature, or swaps a
symmetric `HS256` token to look like an asymmetric `RS256` one, to
bypass verification. `verify_hs256` decodes the header and **requires
`alg` to be exactly `"HS256"` before it trusts any signature**. An
`alg:"none"` header (even with an empty signature segment), an
`HS384` / `RS256` / other header, a missing `alg`, a non-string `alg`,
and a non-object header are **all** rejected with `UnsupportedAlgorithm`
at the gate, before the signature is ever examined. The gate also
rejects (per RFC 7515 section 4.1.11) any header carrying a `crit`
(critical header parameter), since this library understands no critical
extensions, so a validly-signed token that demands one is refused rather
than silently ignored. The security suite asserts each of these.

The signature compare re-encodes OUR recomputed signature and compares
that string to the token's third segment with `capa_hash.verify`'s
`@constant_time` `strings_equal`, so the attacker-supplied signature is
never decoded into an ambiguous form and `==` (a prefix-length timing
oracle, CWE-208) is never used.

> **ASCII JSON payloads.** Capa has no bytes-to-`String` primitive (a
> `String` is built from literals and `char_at` lookups, never from
> arbitrary bytes), so `verify_hs256` reconstructs the returned payload
> through a printable-ASCII table. Compact JSON, as emitted by the
> common encoders (Python's `json.dumps` and PyJWT default to
> `ensure_ascii`, escaping non-ASCII as `\uXXXX`), is entirely ASCII and
> round-trips exactly. A token whose decoded payload contains raw
> non-ASCII UTF-8 verifies its signature but is then reported as
> `MalformedToken` rather than returning mojibake. `sign_hs256` itself
> accepts any `String` payload; the ASCII limit is only on the text
> `verify_hs256` hands back. This is a language limit, documented here
> honestly.

## Dependencies

`capa_jwt` is the first Capa library built by composing other Capa
libraries: it is assembled from two capability-free seed libraries, declared as
real runtime dependencies in [`capa.toml`](./capa.toml) and pinned by
tag and publisher `verify_key`:

```toml
[dependencies.capa_base64]
git = "https://github.com/nelsonduarte/capa_base64"
tag = "v0.1.0"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"

[dependencies.capa_hash]
git = "https://github.com/nelsonduarte/capa_hash"
tag = "v0.1.2"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

- **[`capa_base64`](https://github.com/nelsonduarte/capa_base64)**
  provides `encode_url` / `decode_url_strict` (base64url, no padding, the
  JWT convention) and `encode_utf8`. The verifier uses the strict
  canonical decoder so a segment has exactly one accepted encoding (no
  signature-malleability footgun).
- **[`capa_hash`](https://github.com/nelsonduarte/capa_hash)** provides
  `hmac_sha256_bytes` for the signature and the `@constant_time`
  `strings_equal` for the tag compare.

`capa install` clones both into `./vendor/` and enforces the full
supply-chain check (lockfile SHA + GPG tag signature + SLSA L2
provenance) on each. Both are themselves zero-capability libraries,
so `capa_jwt`'s empty surface holds transitively.

## Verification

The token construction was written **oracle-first**: the expected tokens
in the suite come from Python's stdlib (`hmac`, `hashlib`,
`base64.urlsafe_b64encode(...).rstrip(b"=")`, `json`), cross-checked with
PyJWT where installed, and baked in. The scratch generator is **not**
part of the library; only `.capa` modules ship. The suite re-asserts the
vectors on both backends:

- **jwt.io HS256 vector:** header `{"alg":"HS256","typ":"JWT"}`, payload
  `{"sub":"1234567890","name":"John Doe","iat":1516239022}`, secret
  `your-256-bit-secret`. `sign_hs256` reproduces the published token
  byte for byte, and `verify_hs256` accepts it and returns the payload.
- **Round-trips:** `verify_hs256(sign_hs256(p, k), k) == p` for several
  payloads and keys, each sign also checked against the oracle string.
- **Security battery (all must hold):** a tampered payload, a tampered
  signature, and a token re-signed under a different key all fail with
  `InvalidSignature`; an `alg:"none"` token (with its empty signature),
  an `alg:"HS384"` / `"RS256"` token, a non-object header, a missing
  `alg`, and a validly-signed token carrying a `crit` header parameter
  are all rejected with `UnsupportedAlgorithm`; malformed inputs
  (two segments, four segments, bad base64, the empty string) are
  `MalformedToken`; a non-ASCII payload verifies then reports
  `MalformedToken` (the documented scope boundary); and `is_expired` is
  correct against a fixed `now` (past, future, equal, missing, wrong
  type, non-object, unparseable) and rejects an `exp` beyond the i64
  range as `InvalidClaim` on both backends (no Wasm trap), which is what
  keeps the "byte-identical on both backends" guarantee true.

```bash
capa test          # Python backend
capa test --both   # Python + Wasm, byte-identical stdout required
```

Current output of `capa test --both`:

```
capa test: 1 file(s) under .../capa_jwt/tests [backend: python+wasm]
test_jwt.capa ... ok
1 test(s): 1 passed, 0 failed
```

`capa_test` is declared under `[dev-dependencies]` with the same
git + tag + verify_key shape as the runtime dependencies, pinned to its
`v0.1.0` tag and verified against the publisher key, so `capa install`
runs the full three-layer check on it too. Dev-dependencies are resolved
only when this repository is the install root, so a consumer of
`capa_jwt` never fetches the test library.

## Audit claim

A token library is exactly the kind of dependency a supply-chain
attacker wants to own, so this one shows its empty capability surface.
`capa --manifest jwt.capa` over the library and its transitively reached
dependency code reports, for **every** function:

```
declared_capabilities:                []
transitively_reachable_capabilities:  []
has_unsafe:                           false
user_defined_capabilities:            []
```

0 functions with capabilities, 0 crossing `unsafe`. The four public
functions take **no capability parameters**: `verify_hs256` and
`is_expired` hold no `Clock`, no `Net`, nothing. Every capability
(`Clock`, `Db`, `Env`, `Fs`, `Net`, `Proc`, `Random`, `Stdio`,
`Unsafe`) is listed under each function's
`provably_excluded_capabilities`. The only capabilities anywhere in this
repository are in the example and are the example's own (`Stdio` to
print). **You can verify a JWT while holding no authority at all**, that
is the whole showcase: a token check whose functions declare no
capability.

## Honest posture

- **Verified, not audited.** The output is checked against the jwt.io
  vector and Python's `hmac` / `hashlib` / `base64` / `json` (and PyJWT)
  over many inputs, on both backends. It has **not** been reviewed by a
  cryptographer or fuzzed.
- **HS256 only, on purpose.** Asymmetric algorithms (`RS256`, `ES256`,
  ...) and the wider `HS384` / `HS512` are out of scope and actively
  rejected, not silently mishandled. That rejection IS the
  algorithm-confusion defense.
- **A JWT is signed, not encrypted.** The payload is base64url, not
  secret. Do not put confidential data in a JWT and expect it hidden.
- **Key strength is the caller's job.** HS256 security rests on a
  high-entropy key of at least 32 bytes (RFC 7518 section 3.2). This
  library does not generate keys (it holds no `Random`); pass a strong
  key you manage yourself.
- **What `@constant_time` does and does not promise.** The tag compare
  in `capa_hash.verify` carries the `@constant_time` marker, a
  source-level guarantee that no `@secret`-labelled value steers a
  branch or indexes memory inside it. It does **not** promise constant
  time against cache effects or microarchitectural side channels, nor
  about the backend's generated code. See `capa_hash`'s README for the
  precise scope.

## License

MIT. See [`LICENSE`](./LICENSE). Release tags are GPG-signed; see
[`SECURITY.md`](./SECURITY.md) for the fingerprint and verification
instructions.
