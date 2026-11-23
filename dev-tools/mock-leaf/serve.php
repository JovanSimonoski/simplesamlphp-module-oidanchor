<?php

declare(strict_types=1);

/**
 * Dev-only mock leaf entity.
 *
 * Serves a signed Entity Configuration (application/entity-statement+jwt) at any path — most
 * importantly /.well-known/openid-federation — so the TA's Resolve endpoint has a real leaf to
 * fetch. NOT part of the oidanchor module; lives under dev-tools/ and is never deployed.
 *
 * Usage:
 *   # 1. Print the public JWKS to register this leaf as a subordinate in the TA admin UI:
 *   php serve.php print-jwks
 *
 *   # 2. Serve the entity configuration (built-in PHP server; serve.php routes every request):
 *   php -S 0.0.0.0:8080 serve.php
 *
 * Configuration via environment variables:
 *   MOCK_LEAF_ENTITY_ID    Leaf entity ID (default https://rp.example.com)
 *   MOCK_LEAF_TA           Trust Anchor entity ID to put in authority_hints
 *                          (default https://ta.local.stack-dev.cirrusidentity.com)
 *   MOCK_LEAF_KEY          Path to the leaf's PEM private key (default ./leaf.key; generated if absent)
 *   MOCK_LEAF_ALG          Signing algorithm (default RS256)
 *   MOCK_LEAF_TRUST_MARK   Optional compact Trust Mark JWT to embed under trust_marks
 *   MOCK_LEAF_TRUST_MARK_FILE  Optional path to a file containing the compact Trust Mark JWT
 */

require __DIR__ . '/../../vendor/autoload.php';

use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\SupportedAlgorithms;

$entityId = getenv('MOCK_LEAF_ENTITY_ID') ?: 'https://rp.example.com';
$trustAnchor = getenv('MOCK_LEAF_TA') ?: 'https://ta.local.stack-dev.cirrusidentity.com';
$keyFile = getenv('MOCK_LEAF_KEY') ?: __DIR__ . '/leaf.key';
$algStr = getenv('MOCK_LEAF_ALG') ?: 'RS256';

// Generate an RSA key pair on first use.
if (!file_exists($keyFile)) {
    $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($resource === false || !openssl_pkey_export($resource, $pem)) {
        fwrite(STDERR, "Failed to generate RSA key.\n");
        exit(1);
    }
    file_put_contents($keyFile, $pem);
    fwrite(STDERR, "Generated new leaf key at {$keyFile}\n");
}

$algorithm = SignatureAlgorithmEnum::from($algStr);
$signingKey = (new Jwk())->jwkDecoratorFactory()->fromPkcs1Or8KeyFile($keyFile, null, ['use' => 'sig']);
$publicJwk = $signingKey->jwk()->toPublic();
$kid = $publicJwk->thumbprint('sha256');
$publicJwkData = $publicJwk->jsonSerialize();
$publicJwkData['kid'] = $kid;

// CLI mode: print the public JWKS for subordinate registration in the TA.
if (PHP_SAPI === 'cli') {
    $command = $argv[1] ?? 'print-jwks';
    if ($command === 'print-jwks') {
        echo json_encode(['keys' => [$publicJwkData]], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        exit(0);
    }
    fwrite(STDERR, "Unknown command '{$command}'. Try: print-jwks, or run with `php -S` to serve.\n");
    exit(1);
}

// Optional Trust Mark to embed.
$trustMark = getenv('MOCK_LEAF_TRUST_MARK') ?: null;
$trustMarkFile = getenv('MOCK_LEAF_TRUST_MARK_FILE') ?: null;
if ($trustMark === null && $trustMarkFile !== null && file_exists($trustMarkFile)) {
    $trustMark = trim((string) file_get_contents($trustMarkFile));
}

$now = time();

$payload = [
    ClaimsEnum::Iss->value => $entityId,
    ClaimsEnum::Sub->value => $entityId,
    ClaimsEnum::Iat->value => $now,
    ClaimsEnum::Exp->value => $now + 3600,
    ClaimsEnum::Jwks->value => ['keys' => [$publicJwkData]],
    ClaimsEnum::AuthorityHints->value => [$trustAnchor],
    ClaimsEnum::Metadata->value => [
        EntityTypesEnum::OpenIdRelyingParty->value => [
            'client_name' => 'Mock Relying Party',
            'redirect_uris' => [rtrim($entityId, '/') . '/callback'],
            'grant_types' => ['authorization_code'],
            'id_token_signed_response_alg' => 'RS256',
            'token_endpoint_auth_method' => 'private_key_jwt',
        ],
    ],
];

if ($trustMark !== null && $trustMark !== '') {
    // Recover the trust_mark_type from the mark payload so the entry is spec-correct.
    $parts = explode('.', $trustMark);
    $markPayload = isset($parts[1])
        ? (json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true) ?: [])
        : [];
    $trustMarkType = is_array($markPayload) ? ($markPayload['trust_mark_type'] ?? 'unknown') : 'unknown';

    $payload[ClaimsEnum::TrustMarks->value] = [
        [
            ClaimsEnum::TrustMarkType->value => $trustMarkType,
            ClaimsEnum::TrustMark->value => $trustMark,
        ],
    ];
}

$federation = new Federation(new SupportedAlgorithms(new SignatureAlgorithmBag($algorithm)));

$token = $federation->entityStatementFactory()->fromData(
    $signingKey,
    $algorithm,
    $payload,
    [ClaimsEnum::Kid->value => $kid],
)->getToken();

header('Content-Type: application/entity-statement+jwt');
echo $token;
