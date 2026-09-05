# YunoHost MCP integration boundary

`yunohost-nostr-auth` and `yunohost-mcp` may identify the same person or agent
with the same Nostr pubkey, but they answer different authorization questions.

Use lowercase x-only public-key hex internally. Convert `npub1...` at the
configuration or UI boundary. Reject `nsec` values anywhere a public key is
expected.

```text
Nostr pubkey
  ├── this service: pubkey → linked YunoHost account/session
  └── MCP: pubkey → role/scope/delegation/approval policy
```

A linked account does not automatically receive MCP administrative access.
The MCP must continue to require its own NIP-98 request authentication and
`identity.toml` authorization.

The proven `SO_PEERCRED` Unix-socket helper pattern is reusable by MCP for
privileged operations. `nostr_auth` should not depend on MCP internals or
mint MCP authorization; each service remains responsible for its own policy.

