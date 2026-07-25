# Bundled sing-box schema

`sing-box-1.14.0-beta.2.json` is copied verbatim from
[`docs/schema.json`](https://github.com/SagerNet/sing-box/blob/v1.14.0-beta.2/docs/schema.json)
in the official sing-box `v1.14.0-beta.2` source tree.

- Draft: JSON Schema 2020-12
- Canonical URI: `https://sing-box.sagernet.org/schema.json`
- SHA-256: `065e7a8ea2dc2e89f9f4d4ca3a18e791e5b877ca4ccd0f2637fcf09097cb3c1f`

The schema is bundled so configuration validation is deterministic and does
not require network access. When updating sing-box, replace the file with the
output of the matching `sing-box schema -o schema.json` command (using the
desired build tags), update the version/checksum here and in
`src/config/schema.rs`, then run the full test suite.
