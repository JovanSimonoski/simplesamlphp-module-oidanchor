<?php

declare(strict_types=1);

/**
 * Demo data for a local Trust Anchor (dev only).
 *
 * Fills the admin UI pages, the Federation Admin API and the signed federation endpoints with a
 * small example federation: subordinates in every status, general and per-subordinate metadata
 * policies and constraints, entity configuration metadata, keys, trust mark types with issuers
 * and an owner (with delegation), and issued (and one revoked) trust marks.
 *
 * Data is written through the Federation Admin API, so the usual validation and side effects
 * apply (audit events, trust mark issuance and revocation). Trust mark types are the exception:
 * they are created through the admin UI form, because the API has no display name or default
 * lifetime, which are what the Trust Mark Types page shows. Keys are real RSA key pairs generated
 * on the fly, so the signed endpoints keep working with the demo data.
 *
 * Run inside the TA container (see docs/reproduction.md):
 *
 *   docker exec ssp-oidanchor php /var/simplesamlphp/staging-modules/oidanchor/dev-tools/demo-data/seed.php
 *
 * Environment:
 *   OIDANCHOR_API_ADMIN_USERNAME / OIDANCHOR_API_ADMIN_PASSWORD  API Basic credential (required)
 *   SSP_ADMIN_PASSWORD       SimpleSAMLphp admin password, for the admin UI form (required)
 *   OIDANCHOR_SEED_BASE_URL  module base URL (default https://localhost/simplesaml/module.php/oidanchor)
 *
 * The script stops without changes when the demo subordinates are already registered.
 * To start over, recreate the container (its SQLite database is not persisted).
 */

const DEMO_SUBORDINATES = [
    [
        'entity_id'   => 'https://op.example.org',
        'type'        => 'openid_provider',
        'status'      => 'active',
        'description' => 'Example University OpenID Provider',
    ],
    [
        'entity_id'   => 'https://rp.example.com',
        'type'        => 'openid_relying_party',
        'status'      => 'active',
        'description' => 'Example Research Portal',
    ],
    [
        'entity_id'   => 'https://wiki.example.com',
        'type'        => 'openid_relying_party',
        'status'      => 'active',
        'description' => 'Example Collaboration Wiki',
    ],
    [
        'entity_id'   => 'https://intermediate.example.org',
        'type'        => 'federation_entity',
        'status'      => 'active',
        'description' => 'Example NREN (intermediate authority)',
    ],
    [
        'entity_id'   => 'https://rp2.example.net',
        'type'        => 'openid_relying_party',
        'status'      => 'pending',
        'description' => 'New Relying Party (awaiting approval)',
    ],
    [
        'entity_id'   => 'https://old-portal.example.net',
        'type'        => 'openid_relying_party',
        'status'      => 'inactive',
        'description' => 'Decommissioned Portal',
    ],
    [
        'entity_id'   => 'https://lab-op.example.edu',
        'type'        => 'openid_provider',
        'status'      => 'blocked',
        'description' => 'Example Lab OpenID Provider (suspended after a failed security review)',
    ],
];

$baseUrl       = rtrim(getenv('OIDANCHOR_SEED_BASE_URL') ?: 'https://localhost/simplesaml/module.php/oidanchor', '/');
$username      = getenv('OIDANCHOR_API_ADMIN_USERNAME') ?: '';
$password      = getenv('OIDANCHOR_API_ADMIN_PASSWORD') ?: '';
$adminPassword = getenv('SSP_ADMIN_PASSWORD') ?: '';

if ($username === '' || $password === '' || $adminPassword === '') {
    fwrite(STDERR, "OIDANCHOR_API_ADMIN_USERNAME, OIDANCHOR_API_ADMIN_PASSWORD and SSP_ADMIN_PASSWORD must be set.\n");
    exit(1);
}

try {
    seed($baseUrl, $username . ':' . $password, $adminPassword);
} catch (RuntimeException $e) {
    fwrite(STDERR, "\nFAILED: " . $e->getMessage() . "\n");
    exit(1);
}


function seed(string $baseUrl, string $credential, string $adminPassword): void
{
    $api = static fn(string $method, string $path, mixed $body = null, bool $text = false): mixed
        => api($baseUrl, $credential, $method, $path, $body, $text);

    $ta  = entityIdOf($baseUrl);
    $now = time();
    echo "Trust Anchor: {$ta}\n";

    $existing = array_column($api('GET', '/subordinates'), 'entity_id');
    if (array_intersect($existing, array_column(DEMO_SUBORDINATES, 'entity_id')) !== []) {
        echo "Demo data is already present, nothing to do.\n";

        return;
    }

    // ---- Keys ---------------------------------------------------------------
    // Rotate first, so everything signed below uses the new key. The old key stays published
    // for the overlap window, and the extra public key shows a pre-published next key.
    step('Keys: rotation options, one rotation, pre-published next key');
    $api('PUT', '/kms/rotation', ['enabled' => false, 'interval' => 90 * 86400, 'overlap' => 7 * 86400]);
    $api('POST', '/kms/rotate?reason=' . rawurlencode('demo rotation'));
    $api('POST', '/entity-configuration/keys', [
        'key' => rsaKey()['jwk'],
        'exp' => $now + 400 * 86400,
    ]);

    // ---- Entity configuration -------------------------------------------------
    // No authority hints: this demo TA is the root of its federation (OpenID Federation 1.0
    // §3.1.2 forbids authority_hints for a Trust Anchor with no superiors).
    step('Entity configuration: lifetime, metadata, additional claim');
    $api('PUT', '/entity-configuration/lifetime', '86400', true);
    $api('PUT', '/entity-configuration/metadata/federation_entity', [
        'organization_name' => 'Example Demo Federation',
        'homepage_uri'      => 'https://federation.example.org',
        'policy_uri'        => 'https://federation.example.org/policy',
        'logo_uri'          => 'https://federation.example.org/logo.svg',
        'contacts'          => ['federation-ops@example.org'],
    ]);
    $api('PUT', '/entity-configuration/additional-claims', [
        ['claim' => 'federation_name', 'value' => 'Example Demo Federation', 'crit' => false],
    ]);

    // ---- Federation-wide subordinate settings -----------------------------------
    // No metadata_policy_crit: it may only list non-standard operators (§3.1.3), and the demo
    // policies use standard ones only. allowed_entity_types never lists federation_entity,
    // which is always allowed (§6.2.3).
    step('General metadata policies, constraints, claims, lifetime');
    $api('PUT', '/subordinates/lifetime', '86400', true);
    $api('PUT', '/subordinates/metadata-policies', [
        'openid_relying_party' => [
            'grant_types'                  => ['subset_of' => ['authorization_code', 'refresh_token']],
            'token_endpoint_auth_method'   => ['one_of' => ['private_key_jwt', 'client_secret_basic'], 'default' => 'private_key_jwt'],
            'id_token_signed_response_alg' => ['one_of' => ['RS256', 'ES256'], 'default' => 'RS256'],
            'contacts'                     => ['add' => ['federation-support@example.org']],
        ],
        'openid_provider' => [
            'id_token_signing_alg_values_supported' => ['subset_of' => ['RS256', 'ES256', 'PS256']],
            'token_endpoint_auth_methods_supported' => ['subset_of' => ['private_key_jwt', 'client_secret_basic', 'client_secret_post']],
            'contacts'                              => ['add' => ['federation-support@example.org']],
        ],
    ]);
    $api('PUT', '/subordinates/constraints', [
        'max_path_length'      => 1,
        'naming_constraints'   => [
            'permitted' => ['.example.org', '.example.com', '.example.net', '.example.edu'],
            'excluded'  => ['.untrusted.example.net'],
        ],
        'allowed_entity_types' => ['openid_provider', 'openid_relying_party'],
    ]);
    $api('PUT', '/subordinates/additional-claims', [
        ['claim' => 'registration_policy_uri', 'value' => 'https://federation.example.org/registration', 'crit' => false],
    ]);

    // ---- Subordinates -----------------------------------------------------------
    step('Subordinates (' . count(DEMO_SUBORDINATES) . ')');
    $ids = [];
    foreach (DEMO_SUBORDINATES as $sub) {
        $body = [
            'entity_id'               => $sub['entity_id'],
            'status'                  => $sub['status'],
            'registered_entity_types' => [$sub['type']],
            'description'             => $sub['description'],
        ];
        // A pending registration has not supplied its keys yet.
        if ($sub['status'] !== 'pending') {
            $body['jwks'] = ['keys' => [rsaKey()['jwk']]];
        }

        $ids[$sub['entity_id']] = (int) $api('POST', '/subordinates', $body)['id'];
        echo "    {$sub['status']}\t{$sub['entity_id']}\n";
    }

    step('Per-subordinate keys, metadata, metadata policy, constraints, claims');
    $op = $ids['https://op.example.org'];
    $rp = $ids['https://rp.example.com'];

    // Key rollover: the OP has announced its next key.
    $api('POST', "/subordinates/{$op}/jwks", rsaKey()['jwk']);
    $api('PUT', "/subordinates/{$op}/metadata", [
        'openid_provider' => [
            'organization_name' => 'Example University',
            'contacts'          => ['idm-team@example.org'],
        ],
    ]);

    $api('PUT', "/subordinates/{$rp}/metadata", [
        'openid_relying_party' => [
            'client_name' => 'Example Research Portal',
            'contacts'    => ['portal-admin@example.com'],
        ],
    ]);
    $api('PUT', "/subordinates/{$rp}/metadata-policies", [
        'openid_relying_party' => [
            'scope'       => ['subset_of' => ['openid', 'profile', 'email']],
            'grant_types' => ['subset_of' => ['authorization_code']],
        ],
    ]);
    $api('PUT', "/subordinates/{$rp}/constraints", ['max_path_length' => 0]);
    $api('PUT', "/subordinates/{$rp}/additional-claims", [
        ['claim' => 'registration_reference', 'value' => 'REG-2026-0042', 'crit' => false],
    ]);

    // ---- Trust mark catalogue ---------------------------------------------------
    // Type identifiers live under the namespace of whoever defines the trust framework (§7.1):
    // this federation for its own marks, the owner for the delegated Sirtfi mark.
    step('Trust mark types (admin UI), issuers and owner');
    $types = [
        'certified-op' => $ta . '/marks/certified-op',
        'verified-rp'  => $ta . '/marks/verified-rp',
        'sirtfi'       => 'https://refeds.example.org/sirtfi',
    ];
    $owner    = 'https://refeds.example.org';
    $ownerKey = rsaKey();

    $cookies = adminLogin($baseUrl, $adminPassword);
    createTrustMarkType($baseUrl, $cookies, [
        'trust_mark_id'    => $types['certified-op'],
        'name'             => 'Certified OpenID Provider',
        'description'      => 'The OpenID Provider passed the federation certification.',
        'logo_uri'         => 'https://federation.example.org/logos/certified-op.svg',
        'ref_uri'          => 'https://federation.example.org/certification/op',
        'default_lifetime' => (string) (365 * 86400),
    ]);
    createTrustMarkType($baseUrl, $cookies, [
        'trust_mark_id'    => $types['verified-rp'],
        'name'             => 'Verified Relying Party',
        'description'      => 'The Relying Party organisation and contacts were verified by the federation.',
        'logo_uri'         => 'https://federation.example.org/logos/verified-rp.svg',
        'ref_uri'          => 'https://federation.example.org/certification/rp',
        'default_lifetime' => (string) (180 * 86400),
    ]);
    createTrustMarkType($baseUrl, $cookies, [
        'trust_mark_id'    => $types['sirtfi'],
        'name'             => 'Sirtfi',
        'description'      => 'Security incident response; issued by this Trust Anchor under delegation from the owner.',
        'ref_uri'          => 'https://refeds.example.org/sirtfi',
        'default_lifetime' => (string) (365 * 86400),
    ]);
    unlink($cookies);

    $typeIds = [];
    foreach ($api('GET', '/trust-marks/types') as $type) {
        $typeIds[$type['trust_mark_type']] = (int) $type['id'];
    }
    foreach ($types as $type) {
        $api('POST', "/trust-marks/types/{$typeIds[$type]}/issuers", ['issuer' => $ta, 'description' => 'This Trust Anchor']);
    }
    $api('POST', "/trust-marks/types/{$typeIds[$types['sirtfi']]}/owner", [
        'entity_id'   => $owner,
        'jwks'        => ['keys' => [$ownerKey['jwk']]],
        'description' => 'Owner of the Sirtfi trust framework',
    ]);

    // ---- Issuance specs and subjects ----------------------------------------------
    // Each type's issuance spec is created from the type (lifetime, logo, ref, description).
    // The owner authorises this TA to issue Sirtfi marks with a signed delegation.
    // Active subjects get their trust mark issued immediately.
    step('Issuance specs: delegation for the owned type');
    $specIds = [];
    foreach ($api('GET', '/trust-marks/issuance-spec') as $spec) {
        $specIds[$spec['trust_mark_type']] = (int) $spec['id'];
    }

    $api('PATCH', '/trust-marks/issuance-spec/' . $specIds[$types['sirtfi']], [
        'delegation_jwt' => signJwt(
            ['alg' => 'RS256', 'kid' => $ownerKey['jwk']['kid'], 'typ' => 'trust-mark-delegation+jwt'],
            [
                'iss'             => $owner,
                'sub'             => $ta,
                'iat'             => $now,
                'exp'             => $now + 365 * 86400,
                'trust_mark_type' => $types['sirtfi'],
            ],
            $ownerKey['private'],
        ),
    ]);

    step('Trust mark subjects and issued trust marks');
    $subject = static function (string $type, string $entityId, string $status, ?array $claims = null) use ($api, $specIds, $types): int {
        $body = ['entity_id' => $entityId, 'status' => $status];
        if ($claims !== null) {
            $body['additional_claims'] = $claims;
        }
        echo "    {$status}\t{$entityId}  ({$type})\n";

        return (int) $api('POST', '/trust-marks/issuance-spec/' . $specIds[$types[$type]] . '/subjects', $body)['id'];
    };

    $subject('certified-op', 'https://op.example.org', 'active', ['certification_level' => 'full']);
    $subject('certified-op', 'https://lab-op.example.edu', 'blocked');
    $subject('verified-rp', 'https://rp.example.com', 'active');
    $subject('verified-rp', 'https://wiki.example.com', 'active');
    $retired = $subject('verified-rp', 'https://old-portal.example.net', 'active');
    $subject('sirtfi', 'https://op.example.org', 'active');
    $subject('sirtfi', 'https://rp.example.com', 'active');

    // The portal was decommissioned after verification: deactivating the subject revokes its mark.
    $api('PUT', '/trust-marks/issuance-spec/' . $specIds[$types['verified-rp']] . "/subjects/{$retired}/status", 'inactive', true);
    echo "    inactive\thttps://old-portal.example.net  (verified-rp, mark revoked)\n";

    echo "\nDone. Open the admin UI: {$baseUrl}/admin/subordinates\n";
}


/**
 * Call the Federation Admin API. Returns the decoded JSON body; throws on any HTTP error.
 */
function api(string $baseUrl, string $credential, string $method, string $path, mixed $body, bool $text): mixed
{
    $ch = curl_init($baseUrl . '/api/v1/admin' . $path);
    $headers = ['Accept: application/json'];

    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_USERPWD        => $credential,
        CURLOPT_RETURNTRANSFER => true,
        // Dev only: the local container serves a self-signed certificate.
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);

    if ($body !== null) {
        $headers[] = $text ? 'Content-Type: text/plain' : 'Content-Type: application/json';
        curl_setopt($ch, CURLOPT_POSTFIELDS, $text ? (string) $body : json_encode($body, JSON_UNESCAPED_SLASHES));
    }
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $response = curl_exec($ch);
    $status   = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);

    if ($response === false) {
        throw new RuntimeException(sprintf('%s %s: %s', $method, $path, curl_error($ch)));
    }
    if ($status >= 400) {
        throw new RuntimeException(sprintf('%s %s -> HTTP %d: %s', $method, $path, $status, $response));
    }

    return $response === '' ? null : json_decode((string) $response, true);
}


/**
 * A request to the admin UI with a session cookie file and an optional form body.
 * Redirects are not followed.
 *
 * @param array<string,string>|null $form
 * @return array{status: int, body: string, redirect: string}
 */
function adminRequest(string $method, string $url, string $cookies, ?array $form = null): array
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_CUSTOMREQUEST  => $method,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_COOKIEFILE     => $cookies,
        CURLOPT_COOKIEJAR      => $cookies,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    if ($form !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form));
    }

    $body = curl_exec($ch);
    if ($body === false) {
        throw new RuntimeException(sprintf('%s %s: %s', $method, $url, curl_error($ch)));
    }

    $result = [
        'status'   => curl_getinfo($ch, CURLINFO_RESPONSE_CODE),
        'body'     => (string) $body,
        'redirect' => (string) curl_getinfo($ch, CURLINFO_REDIRECT_URL),
    ];
    unset($ch); // Frees the handle, which writes the cookie jar.

    return $result;
}


/**
 * Log in to the SimpleSAMLphp admin UI. Returns the cookie file holding the session.
 */
function adminLogin(string $baseUrl, string $password): string
{
    $cookies = (string) tempnam(sys_get_temp_dir(), 'oidanchor-seed');

    // Without a session, an admin page redirects to the login form, carrying the AuthState.
    $loginUrl = adminRequest('GET', $baseUrl . '/admin/trust-mark-types', $cookies)['redirect'];
    parse_str((string) parse_url($loginUrl, PHP_URL_QUERY), $query);

    $response = adminRequest('POST', $loginUrl, $cookies, [
        'AuthState' => (string) ($query['AuthState'] ?? ''),
        'username'  => 'admin',
        'password'  => $password,
    ]);
    if (!in_array($response['status'], [302, 303], true)) {
        throw new RuntimeException('Admin UI login failed; check SSP_ADMIN_PASSWORD.');
    }

    return $cookies;
}


/**
 * Create a trust mark type through the admin UI form.
 *
 * @param array<string,string> $fields
 */
function createTrustMarkType(string $baseUrl, string $cookies, array $fields): void
{
    $form = adminRequest('GET', $baseUrl . '/admin/trust-mark-types/create', $cookies);
    if (preg_match('/name="csrf_token" value="([^"]+)"/', $form['body'], $match) !== 1) {
        throw new RuntimeException('Could not read the CSRF token from the trust mark type form.');
    }

    $response = adminRequest('POST', $baseUrl . '/admin/trust-mark-types/create', $cookies, $fields + ['csrf_token' => $match[1]]);

    // Success redirects back to the list; a re-rendered form means validation failed.
    if (!in_array($response['status'], [302, 303], true)) {
        throw new RuntimeException(sprintf('Creating trust mark type %s failed (HTTP %d).', $fields['trust_mark_id'], $response['status']));
    }
    echo "    {$fields['trust_mark_id']}\n";
}


/**
 * The TA's entity ID, read from its public entity configuration.
 */
function entityIdOf(string $baseUrl): string
{
    $ch = curl_init($baseUrl . '/.well-known/openid-federation');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => 0,
    ]);
    $jwt = (string) curl_exec($ch);

    $payload = json_decode(base64UrlDecode(explode('.', $jwt)[1] ?? ''), true);
    if (!is_array($payload) || !isset($payload['iss'])) {
        throw new RuntimeException('Could not read the entity configuration at ' . $baseUrl . '/.well-known/openid-federation');
    }

    return (string) $payload['iss'];
}


/**
 * A fresh RSA-2048 key pair: the private key and its public JWK (kid = RFC 7638 thumbprint).
 *
 * @return array{private: OpenSSLAsymmetricKey, jwk: array<string,string>}
 */
function rsaKey(): array
{
    $private = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 2048]);
    $rsa     = openssl_pkey_get_details($private)['rsa'];

    $e = base64UrlEncode($rsa['e']);
    $n = base64UrlEncode($rsa['n']);
    $thumbprint = base64UrlEncode(hash('sha256', json_encode(['e' => $e, 'kty' => 'RSA', 'n' => $n]), true));

    return [
        'private' => $private,
        'jwk'     => ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => $thumbprint, 'n' => $n, 'e' => $e],
    ];
}


/**
 * @param array<string,mixed> $header
 * @param array<string,mixed> $payload
 */
function signJwt(array $header, array $payload, OpenSSLAsymmetricKey $key): string
{
    $input = base64UrlEncode(json_encode($header, JSON_UNESCAPED_SLASHES))
        . '.' . base64UrlEncode(json_encode($payload, JSON_UNESCAPED_SLASHES));
    openssl_sign($input, $signature, $key, OPENSSL_ALGO_SHA256);

    return $input . '.' . base64UrlEncode($signature);
}


function base64UrlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}


function base64UrlDecode(string $data): string
{
    return (string) base64_decode(str_pad(strtr($data, '-_', '+/'), (int) ceil(strlen($data) / 4) * 4, '='), true);
}


function step(string $label): void
{
    echo "- {$label}\n";
}
