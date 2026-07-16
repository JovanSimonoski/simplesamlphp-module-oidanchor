<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use GuzzleHttp\Client;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Exception\ResolveException;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use SimpleSAML\OpenID\Exceptions\TrustChainException;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\TrustChain;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Throwable;

/**
 * Resolves a trust chain from a subject entity up to this Trust Anchor and produces the
 * policy-applied metadata, the verified chain, and validated Trust Marks.
 *
 * The heavy lifting (discovery via authority_hints, HTTP fetching of entity configurations and
 * subordinate statements, signature verification, cycle/depth limits, metadata policy merge +
 * application) is delegated to simplesamlphp/openid's TrustChainResolver / TrustChain. This
 * service adds: the local-anchor shortcut, an anchor-key cross-check against the TA's own keys,
 * and persistence-aware Trust Mark validation via {@see TrustMarkStatusService} (step 8).
 */
class FederationResolver
{
    public function __construct(
        private readonly Configuration $moduleConfig,
        private readonly FederationKeyService $keys,
        private readonly TrustMarkStatusService $trustMarkStatus,
    ) {
    }


    /**
     * @throws ResolveException
     */
    public function resolve(string $sub, string $trustAnchor, ?string $entityType = null): ResolveResult
    {
        // 1. This endpoint only resolves chains to itself.
        if ($trustAnchor !== $this->keys->entityId()) {
            throw ResolveException::invalidTrustAnchor(sprintf(
                "This Trust Anchor only resolves chains to itself ('%s'), not to '%s'.",
                $this->keys->entityId(),
                $trustAnchor,
            ));
        }

        // Per-call cache so repeated fetches of the same entity configuration are deduped.
        $federation = $this->buildFederation(new InMemoryCache());

        // 2. Pre-fetch the subject's entity configuration so we can return a precise 'not_found'
        //    when it is unreachable (distinct from chain/signature failures below).
        try {
            $federation->entityStatementFetcher()->fromCacheOrWellKnownEndpoint($sub);
        } catch (Throwable $e) {
            throw ResolveException::notFound(sprintf(
                "Could not fetch the entity configuration for '%s': %s",
                $sub,
                $e->getMessage(),
            ));
        }

        // 3. Discover + verify the chain to this TA (signatures, depth and cycles handled by the library).
        try {
            $bag = $federation->trustChainResolver()->for($sub, [$trustAnchor]);
        } catch (TrustChainException $e) {
            throw ResolveException::invalidTrustChain(sprintf(
                "Could not build a valid trust chain from '%s' to '%s': %s",
                $sub,
                $trustAnchor,
                $e->getMessage(),
            ), $e);
        }

        try {
            $chain = $bag->getShortestByTrustAnchorPriority($trustAnchor);
        } catch (Throwable $e) {
            throw ResolveException::invalidTrustChain('Error selecting trust chain: ' . $e->getMessage(), $e);
        }

        if ($chain === null) {
            throw ResolveException::invalidTrustChain(sprintf(
                "No trust chain from '%s' reaches trust anchor '%s'.",
                $sub,
                $trustAnchor,
            ));
        }

        // 4. The resolved anchor must present this TA's own federation key (don't trust a spoofed anchor).
        $this->assertLocalAnchorKeys($chain);

        // 5. Metadata — already policy-merged + applied by the library.
        $metadata = $this->resolveMetadata($chain, $entityType);

        // 6. Trust Marks embedded in the leaf's entity configuration.
        $warnings   = [];
        $trustMarks = $this->validateTrustMarks($federation, $chain, $sub, $warnings);

        try {
            $expiration = $chain->getResolvedExpirationTime();
            $tokens     = $chain->jsonSerialize();
        } catch (Throwable $e) {
            throw ResolveException::invalidTrustChain('Trust chain is not usable: ' . $e->getMessage(), $e);
        }

        return new ResolveResult($sub, $chain, $tokens, $metadata, $trustMarks, $warnings, $expiration);
    }


    /**
     * Build the signed Resolve Response JWT (typ: resolve-response+jwt) from a resolution result.
     * Shared by the public endpoint and the admin tester so the output is identical.
     */
    public function buildSignedResponse(ResolveResult $result): string
    {
        $now = time();
        $exp = min($now + $this->config()['response_lifetime'], $result->expiration);

        $payload = [
            ClaimsEnum::Iss->value        => $this->keys->entityId(),
            ClaimsEnum::Sub->value        => $result->sub,
            ClaimsEnum::Iat->value        => $now,
            ClaimsEnum::Exp->value        => $exp,
            ClaimsEnum::Metadata->value   => $result->metadata,
            ClaimsEnum::TrustChain->value => $result->trustChainTokens,
        ];

        if ($result->trustMarks !== []) {
            $payload[ClaimsEnum::TrustMarks->value] = $result->trustMarks;
        }

        return $this->keys->signResolveResponse($payload);
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private function buildFederation(InMemoryCache $cache): Federation
    {
        $config = $this->config();

        $client = new Client([
            'connect_timeout' => $config['http_connect_timeout'],
            'timeout'         => $config['http_read_timeout'],
            'allow_redirects' => ['max' => 1, 'strict' => true, 'referer' => false, 'protocols' => ['https']],
            'verify'          => $config['http_verify_tls'],
            'http_errors'     => true,
            'headers'         => ['User-Agent' => 'oidanchor-resolve/1.0 (+' . $this->keys->entityId() . ')'],
        ]);

        return new Federation(
            supportedAlgorithms: new SupportedAlgorithms(new SignatureAlgorithmBag($this->keys->algorithm())),
            maxTrustChainDepth: $config['max_chain_depth'],
            cache: $cache,
            client: $client,
        );
    }


    /**
     * @throws ResolveException
     */
    private function assertLocalAnchorKeys(TrustChain $chain): void
    {
        try {
            $anchorJwks = $chain->getResolvedTrustAnchor()->getJwks()->getValue();
        } catch (Throwable $e) {
            throw ResolveException::invalidTrustChain('Could not read trust anchor keys: ' . $e->getMessage(), $e);
        }

        $kids = [];
        /** @var array<string,mixed> $key */
        foreach ((array) ($anchorJwks['keys'] ?? []) as $key) {
            if (is_array($key) && isset($key['kid']) && is_string($key['kid'])) {
                $kids[] = $key['kid'];
            }
        }

        if (!in_array($this->keys->kid(), $kids, true)) {
            throw ResolveException::invalidTrustChain(
                "The resolved trust anchor does not present this Trust Anchor's federation signing key.",
            );
        }
    }


    /**
     * @return array<string,array<string,mixed>>
     * @throws ResolveException
     */
    private function resolveMetadata(TrustChain $chain, ?string $entityType): array
    {
        if ($entityType !== null && $entityType !== '') {
            $typeEnum = EntityTypesEnum::tryFrom($entityType);
            if ($typeEnum === null) {
                throw ResolveException::invalidRequest(sprintf("Unknown entity type '%s'.", $entityType));
            }
            $types = [$typeEnum];
        } else {
            $types = EntityTypesEnum::cases();
        }

        $metadata = [];

        foreach ($types as $typeEnum) {
            try {
                $resolved = $chain->getResolvedMetadata($typeEnum);
            } catch (MetadataPolicyException $e) {
                throw ResolveException::invalidTrustChain(sprintf(
                    "Metadata policy could not be applied for '%s': %s",
                    $typeEnum->value,
                    $e->getMessage(),
                ), $e);
            } catch (Throwable $e) {
                throw ResolveException::invalidTrustChain(sprintf(
                    "Could not resolve metadata for '%s': %s",
                    $typeEnum->value,
                    $e->getMessage(),
                ), $e);
            }

            if (is_array($resolved)) {
                $metadata[$typeEnum->value] = $resolved;
            }
        }

        if (($entityType !== null && $entityType !== '') && $metadata === []) {
            throw ResolveException::unsupportedParameter(sprintf(
                "The resolved entity declares no '%s' metadata.",
                $entityType,
            ));
        }

        return $metadata;
    }


    /**
     * @param list<string> $warnings
     * @return list<array{trust_mark_type:string,trust_mark:string}>
     */
    private function validateTrustMarks(Federation $federation, TrustChain $chain, string $sub, array &$warnings): array
    {
        try {
            $bag = $chain->getResolvedLeaf()->getTrustMarks();
        } catch (Throwable $e) {
            $warnings[] = 'Could not read trust_marks from the leaf entity configuration: ' . $e->getMessage();
            return [];
        }

        if ($bag === null) {
            return [];
        }

        // Map issuer => JWKS for every entity configuration in the chain (self-signed: own keys).
        $chainKeysByIssuer = [];
        foreach ($chain->getEntities() as $entity) {
            try {
                if ($entity->isConfiguration()) {
                    $chainKeysByIssuer[$entity->getIssuer()] = $entity->getJwks()->getValue();
                }
            } catch (Throwable) {
                // Ignore entities we cannot introspect.
            }
        }

        $result = [];

        foreach ($bag->getAll() as $claim) {
            $type = $claim->getTrustMarkType();
            $jwt  = $claim->getTrustMark();

            try {
                $mark    = $federation->trustMarkFactory()->fromToken($jwt);
                $iss     = $mark->getIssuer();
                $markSub = $mark->getSubject();
            } catch (Throwable $e) {
                // Covers malformed marks and ones rejected on iat/exp (e.g. expired).
                $warnings[] = sprintf("Dropped Trust Mark '%s': could not parse/validate (%s).", $type, $e->getMessage());
                continue;
            }

            if ($markSub !== $sub) {
                $warnings[] = sprintf(
                    "Dropped Trust Mark '%s': subject '%s' does not match the resolved entity.",
                    $type,
                    $markSub,
                );
                continue;
            }

            // Verify the signature against the right keys.
            if ($iss === $this->keys->entityId()) {
                $verifyJwks = $this->keys->publicJwks();
            } elseif (isset($chainKeysByIssuer[$iss])) {
                $verifyJwks = $chainKeysByIssuer[$iss];
            } else {
                $warnings[] = sprintf(
                    "Skipped Trust Mark '%s': issuer '%s' is neither this TA nor present in the trust chain.",
                    $type,
                    $iss,
                );
                continue;
            }

            try {
                $mark->verifyWithKeySet($verifyJwks);
            } catch (Throwable $e) {
                $warnings[] = sprintf(
                    "Dropped Trust Mark '%s': signature verification failed (%s).",
                    $type,
                    $e->getMessage(),
                );
                continue;
            }

            // Revocation / status.
            if ($iss === $this->keys->entityId()) {
                // Marks issued by us: authoritative in-process status check (step 8).
                $status = $this->trustMarkStatus->getStatus($type, $markSub, $jwt);
                if ($status['active'] !== true) {
                    $warnings[] = sprintf("Dropped Trust Mark '%s': status is '%s'.", $type, $status['status']);
                    continue;
                }
            } else {
                // TODO(step 9+): HTTP-call the foreign issuer's trust_mark_status endpoint. Out of scope
                // for this step — accepted here on signature + (already validated) iat/exp only.
                $warnings[] = sprintf(
                    "Trust Mark '%s' issued by '%s' accepted on signature+expiry only (foreign status check not implemented).",
                    $type,
                    $iss,
                );
            }

            $result[] = ['trust_mark_type' => $type, 'trust_mark' => $jwt];
        }

        return $result;
    }


    /**
     * @return array{
     *     max_chain_depth:int, http_connect_timeout:int, http_read_timeout:int,
     *     response_lifetime:int, http_verify_tls:bool
     * }
     */
    private function config(): array
    {
        $r = $this->moduleConfig->getOptionalArray('resolve', []) ?? [];

        return [
            'max_chain_depth'      => (int) ($r['max_chain_depth'] ?? 6),
            'http_connect_timeout' => (int) ($r['http_connect_timeout'] ?? 5),
            'http_read_timeout'    => (int) ($r['http_read_timeout'] ?? 5),
            'response_lifetime'    => (int) ($r['response_lifetime'] ?? 600),
            'http_verify_tls'      => array_key_exists('http_verify_tls', $r) ? (bool) $r['http_verify_tls'] : true,
        ];
    }
}
