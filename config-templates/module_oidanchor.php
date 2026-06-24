<?php

declare(strict_types=1);

/**
 * Configuration template for the oidanchor (Trust Anchor) module.
 *
 * Copy this file to your SimpleSAMLphp config directory as module_oidanchor.php
 * and adjust the values to your deployment.
 */
return [
    /*
     * The Entity Identifier of this Trust Anchor.
     * This becomes the iss and sub of the Entity Configuration JWT.
     * Must be the base URL of the service (no trailing slash).
     */
    'entity_id' => 'https://example.com',

    /*
     * Base URL used to construct federation endpoint URLs in the Entity Configuration.
     * Usually the same as entity_id.
     */
    'base_url' => 'https://example.com',

    /*
     * Path to the PEM-encoded RSA (or EC) private key used for signing federation objects.
     * Generated once and kept persistent — never rotated without republishing the JWKS.
     *
     * Generate an RSA-2048 key pair with:
     *   openssl genrsa -out oidanchor_module.key 2048
     *   openssl rsa -in oidanchor_module.key -pubout -out oidanchor_module.crt
     */
    'signing_key_file' => '/var/simplesamlphp/cert/oidanchor_module.key',

    /*
     * Passphrase for the private key, or null if the key is unencrypted.
     */
    'signing_key_passphrase' => null,

    /*
     * Signature algorithm for all federation JWTs.
     * Supported: RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, EdDSA
     */
    'signing_algorithm' => 'RS256',

    /*
     * Lifetime of the Entity Configuration JWT in seconds.
     * Defaults to 24 hours.
     */
    'entity_configuration_lifetime' => 86400,

    /*
     * List of Entity Identifiers of Immediate Superiors (for intermediate entities / leaf TAs).
     * Leave empty for a root Trust Anchor that has no superiors.
     * Example: ['https://federation.example.org']
     */
    'authority_hints' => [],

    /*
     * Override the federation_fetch_endpoint URL advertised in the Entity Configuration JWT.
     * null = auto-compute as base_url + '/federation/fetch'.
     *
     * Set this explicitly when clean-URL Apache rewrites are not in place, e.g.:
     *   'federation_fetch_endpoint' => 'https://localhost/simplesaml/module.php/oidanchor/federation/fetch',
     */
    'federation_fetch_endpoint' => null,

    /*
     * Override the federation_list_endpoint URL advertised in the Entity Configuration JWT.
     * null = auto-compute as base_url + '/federation/list'.
     *
     * Set this explicitly when clean-URL Apache rewrites are not in place, e.g.:
     *   'federation_list_endpoint' => 'https://localhost/simplesaml/module.php/oidanchor/federation/list',
     */
    'federation_list_endpoint' => null,

    /*
     * Lifetime in seconds of Subordinate Statements issued by this TA.
     */
    'subordinate_statement_lifetime' => 86400,

    /*
     * Lifetime in seconds of the signed Trust Mark Status Response JWT returned by
     * the /trust_mark_status endpoint. This bounds how long a relying party may cache
     * a status answer; keep it short. Does NOT affect the lifetime of issued Trust Marks
     * themselves (those use the per-type default_lifetime or a per-issuance exp).
     */
    'trust_mark_status_response_lifetime' => 600,

    /*
     * Resolve endpoint (/oidanchor/resolve) settings.
     */
    'resolve' => [
        // Maximum trust-chain depth the resolver will walk before failing (cycle/abuse guard).
        'max_chain_depth'      => 6,
        // cURL/Guzzle connect timeout, in seconds, for each entity-statement fetch.
        'http_connect_timeout' => 5,
        // Read timeout, in seconds, for each entity-statement fetch.
        'http_read_timeout'    => 5,
        // Lifetime in seconds applied to the exp claim of the signed Resolve Response JWT
        // (capped by the trust chain's own expiration).
        'response_lifetime'    => 600,
        // DEV ONLY: set false to skip TLS certificate verification when fetching entity
        // statements (e.g. a local mock leaf served with a self-signed certificate).
        // Leave true in production.
        'http_verify_tls'      => true,
    ],

    /*
     * Enable/disable the federation_fetch endpoint.
     */
    'federation_fetch_endpoint_enabled' => true,

    /*
     * Enable/disable the federation_list endpoint.
     */
    'federation_list_endpoint_enabled' => true,

    /*
     * PDO DSN for the subordinate registry database.
     * SQLite is fine for development; use PostgreSQL/MySQL in production.
     */
    'database_dsn' => 'sqlite:/var/simplesamlphp/data/oidanchor.sqlite',

    'database_username' => null,
    'database_password' => null,
];
