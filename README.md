# simplesamlphp-module-oidanchor

OpenID Anchor module: an OpenID Federation 1.0 Trust Anchor for
SimpleSAMLphp.

See [docs/oidanchor.md](docs/oidanchor.md) for installation, configuration
and usage, and [docs/architecture.md](docs/architecture.md) for how the code
is organised.

## Federation endpoints

Paths are relative to the module URL, e.g.
`https://idp.example.org/simplesaml/module.php/oidanchor`.

| Endpoint                    | Path                              |
|-----------------------------|-----------------------------------|
| Entity Configuration        | `/.well-known/openid-federation`  |
| Subordinate listing         | `/federation/list`                |
| Subordinate statement fetch | `/federation/fetch` (or `/fetch`) |
| Resolve                     | `/resolve`                        |
| Trust Mark status           | `/trust_mark_status`              |

The admin UI lives under `/admin/` and the Federation Admin REST API under
`/api/v1/admin/`.

## Known limitations

- **Trust Mark endpoint (OpenID Federation 1.0, section 8.5) is not
  implemented.** The Trust Anchor issues Trust Marks and keeps them in its
  registry, but a subject cannot fetch a mark issued for it from a standard
  `federation_trust_mark_endpoint`. Marks have to be handed over out of band
  (for example from the admin UI or the admin API).
- **Trust Mark listing endpoint (section 8.6) is not implemented.** There is
  no `federation_trust_mark_list_endpoint` listing the entities that hold a
  mark of a given type; the admin API offers the same information to
  operators only.
- Neither endpoint is advertised in the `federation_entity` metadata of the
  Entity Configuration, so federation clients will not try to use them.
- **The `intermediate` filter of the subordinate listing (section 8.2.1) is not
  supported.** Requests that use it get HTTP 400 with `unsupported_parameter`,
  as the specification requires. The `entity_type`, `trust_marked` and
  `trust_mark_type` filters are supported.
