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
    'federation_fetch_endpoint_enabled' => true,
    'federation_list_endpoint_enabled' => true,
    'database_dsn' => getenv('OIDANCHOR_DATABASE_DSN') ?: 'sqlite:/var/simplesamlphp/data/oidanchor.sqlite',
    'database_username' => null,
    'database_password' => null,
];
