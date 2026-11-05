<?php

declare(strict_types=1);

return [
    'entity_id' => getenv('OIDANCHOR_ENTITY_ID') ?: 'https://ta.local.stack-dev.cirrusidentity.com',
    'base_url' => getenv('OIDANCHOR_BASE_URL') ?: 'https://ta.local.stack-dev.cirrusidentity.com',
    'signing_key_file' => '/var/simplesamlphp/cert/oidanchor_module.key',
    'signing_key_passphrase' => null,
    'signing_algorithm' => 'RS256',
    'authority_hints' => [],

    // Optional: override the federation endpoint URLs advertised in the Entity Configuration.
    // Set these when clean-URL Apache rewrites are NOT in place (e.g. localhost dev).
    // null = auto-compute as base_url + '/federation/fetch' / '/federation/list'.
    'federation_fetch_endpoint' => null,
    'federation_list_endpoint' => null,

    'subordinate_statement_lifetime' => 86400,

    // Lifetime (seconds) of the signed Trust Mark Status Response JWT from /trust_mark_status.
    'trust_mark_status_response_lifetime' => 600,

    // Resolve endpoint (/oidanchor/resolve) settings.
    'resolve' => [
        'max_chain_depth'      => 6,
        'http_connect_timeout' => 5,
        'http_read_timeout'    => 5,
        'response_lifetime'    => 600,
        // DEV ONLY — allow self-signed TLS on fetched entity statements (e.g. the mock leaf).
        'http_verify_tls'      => getenv('OIDANCHOR_RESOLVE_VERIFY_TLS') === 'false' ? false : true,
    ],

    'federation_fetch_endpoint_enabled' => true,
    'federation_list_endpoint_enabled' => true,
    'database_dsn' => getenv('OIDANCHOR_DATABASE_DSN') ?: 'sqlite:/var/simplesamlphp/data/oidanchor.sqlite',
    'database_username' => null,
    'database_password' => null,

    // Federation Admin API HTTP Basic credential (what the Federation Gateway BFF proxy injects).
    // Must match admin_auth username/password for this instance in the gateway's gateway.yaml.
    'api_admin_username' => getenv('OIDANCHOR_API_ADMIN_USERNAME') ?: null,
    'api_admin_password' => getenv('OIDANCHOR_API_ADMIN_PASSWORD') ?: null,
];
