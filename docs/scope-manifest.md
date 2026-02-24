# Scope Manifest (v1)

The Scope Manifest defines how permission scopes are named, normalized, and hashed across PermChain OAuth components.

## 1) Scope string format

A scope string MUST use the following convention:

`<namespace>:<resource>[.<subresource>]:<action>[.<qualifier>]`

Examples:

- `timeline:post:read`
- `uls:wallet.session:issue`
- `ai:train_data:use`
- `ai:model.weights:read.public`

### Naming rules

- `namespace`: lower-case letters, digits, and `_`.
- `resource` / `subresource`: lower-case letters, digits, `_`, and `.` separators.
- `action` / `qualifier`: lower-case letters, digits, `_`, and `.` separators.
- `:` separates major parts; `.` is only for hierarchical refinement.

## 2) Canonicalization rules

Before hashing or storage, scope strings MUST be canonicalized:

1. Convert to string.
2. Trim leading/trailing ASCII whitespace.
3. Collapse internal ASCII whitespace to a single underscore (`_`) if present.
4. Convert the full scope to lower-case.

For this release, on-chain and server-side code assume already-canonical input and apply no automatic mutation beyond string conversion. Clients should submit canonical scope strings.

## 3) Reserved namespace prefixes

The following prefixes are reserved for protocol and ecosystem interoperability:

- `uls:` — Universal Login Session related scopes.
- `timeline:` — timeline/media/feed data permissions.
- `ai:` — model/data/training and inference permissions.

Projects MAY define additional namespaces, but SHOULD avoid collisions with reserved prefixes.

## 4) Domain-separated hashing rule

To prevent cross-domain collisions and enable future upgrades, Scope Manifest v1 uses domain separation.

- Domain tag: `PERMCHAIN_SCOPE_V1:`
- Hash algorithm: `keccak256`
- Input bytes: UTF-8 bytes of `domainTag + canonicalScope`

Formula:

```text
scopeHash(scope) = keccak256(utf8("PERMCHAIN_SCOPE_V1:" + scope))
```

Solidity equivalent:

```solidity
keccak256(abi.encodePacked("PERMCHAIN_SCOPE_V1:", scope))
```

Node (viem) equivalent:

```js
keccak256(toBytes(`PERMCHAIN_SCOPE_V1:${scope}`))
```

## 5) Examples

The exact hashes below are derived with the v1 formula above.

- `ai:train_data` -> `0x87454e3b94f8ba19860260d05601e5de87a7c68c3740a2ce2b0fc5f97cd94310`
- `timeline:post:read` -> `0xedb23c7c9f64d2d302fb765df9559b34f6b9faa9d35ac41906e0587f061a88f9`
- `uls:wallet.session:issue` -> `0x2fc693b5addfe50ec3bb2e869e6c1ea1f64e34aa69b8ded3277a8a2a1aee43e1`

## 6) Versioning policy

If canonicalization or hashing changes, a new domain tag MUST be introduced (`PERMCHAIN_SCOPE_V2:`) and both versions SHOULD be supported during migration.
