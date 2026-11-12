# oidanchor architecture

The module is split into thin controllers, services that hold the federation
logic, and repositories that own the database. Code depends downwards only:
controllers use services and repositories, services use repositories, and
repositories use nothing but PDO.

```text
src/
  Controller/       HTTP entry points (routes in routing/routes/routes.yml)
    Api/            the /api/v1/admin REST API
  Service/          federation logic: claim assembly, signing, resolution
  Repository/       one class per table; schema setup and migrations
  Entity/           value objects for rows and enums
  Database/         connection factory and portable SQL helpers
  Validation/       input validation for the admin UI
  Event/Listener/   SimpleSAMLphp event listeners (cron)
```

## Controllers

Controllers parse the request, check access, call services and render a
response. They hold no federation logic.

- `OpenIDFederation`, `Resolve` and `TrustMarkStatus` serve the public
  federation endpoints. They are read-only: they never fetch remote data,
  rotate keys or issue marks.
- The admin UI controllers extend `AdminController`, which provides admin
  authentication, the CSRF token, flash messages and the page chrome.
- The admin API controllers extend `Api\ApiController`, which provides
  authentication (HTTP Basic or session, with a same-origin check on writes),
  the JSON error envelope and body decoding. Behaviour shared by several API
  resources (metadata documents, policies, constraints, additional claims)
  lives in traits next to them.

## Services

- `EntityConfigurationService` and `SubordinateStatementService` assemble
  the claims of the Entity Configuration and of Subordinate Statements. They
  are the single source of truth for both the signed endpoints and the
  read-only admin API views.
- `FederationKeyService` signs every federation object; `KeyManagementService`
  is the key store behind it (import, rotation, algorithm switching).
- `FederationResolver` resolves trust chains through simplesamlphp/openid.
- `TrustMarkIssuanceService` is the only place a Trust Mark is built, signed
  and recorded; `TrustMarkStatusService` answers status queries.
  `EcTrustMarkService` manages the marks the Trust Anchor publishes about
  itself.
- `FederationMaintenanceService` holds the periodic work (rotation, Trust
  Mark refresh) that the cron listener runs.

JOSE work (signing, parsing, verification) goes through simplesamlphp/openid;
the module does not hand-roll JWTs.

## Repositories and the database

Each repository owns one table: it creates the table on first use, applies
column migrations, and maps rows to arrays or entities. JSON columns are
encoded and decoded only here.

`Database\PdoFactory` opens the connection, once per request, so every
repository and service in a request shares it and a transaction can span
them. `Database\Upsert` provides insert-or-update in standard SQL.
