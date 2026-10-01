<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use PDO;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\AdditionalClaimsRepository;
use SimpleSAML\Module\oidanchor\Repository\AuthorityHintRepository;
use SimpleSAML\Module\oidanchor\Repository\EcMetadataRepository;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkIssuerRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkOwnerRepository;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Federation\Claims\TrustMarkIssuersClaimBag;
use SimpleSAML\OpenID\Federation\Claims\TrustMarkIssuersClaimValue;
use SimpleSAML\OpenID\Federation\Claims\TrustMarkOwnersClaimBag;
use SimpleSAML\OpenID\Federation\Claims\TrustMarkOwnersClaimValue;
use SimpleSAML\OpenID\ValueAbstracts\JwksClaim;
use Throwable;

/**
 * Assembles the Trust Anchor's Entity Configuration claim set.
 *
 * Single source of truth shared by the signed /.well-known/openid-federation endpoint and the
 * admin API (GET /api/v1/admin/entity-configuration), so the two never drift.
 *
 * The claim set is data-driven: authority hints, metadata, additional claims, held trust marks,
 * trust mark issuers/owners and the lifetime all come from the API-managed stores, falling back
 * to the module config where a store is empty. Every API mutation is therefore reflected in the
 * next request to the public endpoint, with no restarts or cache invalidation.
 */
class EntityConfigurationService
{
    public function __construct(
        private readonly FederationKeyService $keys,
    ) {
    }


    /**
     * Build the Entity Configuration payload (claims). Does not sign.
     *
     * @return array<string,mixed>
     */
    public function buildClaims(Configuration $moduleConfig, PDO $pdo): array
    {
        $entityId = $moduleConfig->getString('entity_id');
        $lifetime = $this->lifetime($moduleConfig, $pdo);

        $now = time();

        $payload = [
            ClaimsEnum::Iss->value      => $entityId,
            ClaimsEnum::Sub->value      => $entityId,
            ClaimsEnum::Iat->value      => $now,
            ClaimsEnum::Exp->value      => $now + $lifetime,
            ClaimsEnum::Jwks->value     => $this->keys->publicJwks(),
            ClaimsEnum::Metadata->value => $this->metadata($moduleConfig, $pdo),
        ];

        $authorityHints = $this->authorityHints($moduleConfig, $pdo);
        if ($authorityHints !== []) {
            $payload[ClaimsEnum::AuthorityHints->value] = $authorityHints;
        }

        // Never fail the entity configuration over an optional trust-mark lookup.
        try {
            $issuers = $this->trustMarkIssuers($pdo, $entityId);
            if ($issuers !== []) {
                $payload[ClaimsEnum::TrustMarkIssuers->value] = $issuers;
            }

            $owners = $this->trustMarkOwners($pdo);
            if ($owners !== []) {
                $payload[ClaimsEnum::TrustMarkOwners->value] = $owners;
            }

            $marks = (new EcTrustMarkService($this->keys, new EcTrustMarkRepository($pdo)))->claimValues();
            if ($marks !== []) {
                $payload[ClaimsEnum::TrustMarks->value] = $marks;
            }
        } catch (Throwable $e) {
            Logger::warning('oidanchor: could not load trust mark data for entity configuration: ' . $e->getMessage());
        }

        // Admin-managed additional claims last: they may add claims the builder does not model,
        // but never silently override the issuer-controlled claims above.
        foreach ((new AdditionalClaimsRepository($pdo))->findAll(AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION) as $claim) {
            if (!array_key_exists($claim['claim'], $payload)) {
                $payload[$claim['claim']] = $claim['value'];
            }
        }

        // The library's ClaimsEnum models `metadata_policy_crit` but not the JWT `crit` header
        // claim, so the spec name is used literally here.
        $crit = $this->criticalClaims($pdo);
        if ($crit !== []) {
            $payload['crit'] = $crit;
        }

        return $payload;
    }


    /**
     * The entity configuration lifetime: API-managed setting, else the config default.
     */
    public function lifetime(Configuration $moduleConfig, PDO $pdo): int
    {
        return (new SettingsRepository($pdo))->getInt(SettingsRepository::ENTITY_CONFIGURATION_LIFETIME)
            ?? $moduleConfig->getOptionalInteger('entity_configuration_lifetime', 86400)
            ?? 86400;
    }


    /**
     * The `metadata` claim: the auto-derived federation_entity endpoints, overlaid with the
     * API-managed metadata document (stored claims win, so an admin can override an endpoint).
     *
     * @return array<string,array<string,mixed>>
     */
    public function metadata(Configuration $moduleConfig, PDO $pdo): array
    {
        $metadata = [
            EntityTypesEnum::FederationEntity->value => $this->derivedFederationEntityMetadata($moduleConfig),
        ];

        foreach ((new EcMetadataRepository($pdo))->all() as $entityType => $claims) {
            $metadata[$entityType] = array_merge($metadata[$entityType] ?? [], $claims);
        }

        return $metadata;
    }


    /**
     * The federation_entity endpoints this module actually serves.
     *
     * @return array<string,mixed>
     */
    public function derivedFederationEntityMetadata(Configuration $moduleConfig): array
    {
        $baseUrl = $moduleConfig->getString('base_url');

        return [
            ClaimsEnum::FederationFetchEndpoint->value => $moduleConfig->getOptionalString('federation_fetch_endpoint', null)
                ?? $baseUrl . '/federation/fetch',
            ClaimsEnum::FederationListEndpoint->value  => $moduleConfig->getOptionalString('federation_list_endpoint', null)
                ?? $baseUrl . '/federation/list',
            // The library's ClaimsEnum has no federation_resolve_endpoint case (it models
            // fetch/list/trust-mark/trust-mark-status only), so the spec name is used literally.
            'federation_resolve_endpoint' => $moduleConfig->getOptionalString('federation_resolve_endpoint', null)
                ?? $baseUrl . '/resolve',
            ClaimsEnum::FederationTrustMarkStatusEndpoint->value => $moduleConfig->getOptionalString('federation_trust_mark_status_endpoint', null)
                ?? $baseUrl . '/trust_mark_status',
        ];
    }


    /**
     * Authority hints: the API-managed store, else the config list.
     *
     * @return list<string>
     */
    private function authorityHints(Configuration $moduleConfig, PDO $pdo): array
    {
        $stored = (new AuthorityHintRepository($pdo))->entityIds();
        if ($stored !== []) {
            return $stored;
        }

        /** @var list<string> $configured */
        $configured = $moduleConfig->getOptionalArray('authority_hints', []) ?? [];

        return $configured;
    }


    /**
     * The `trust_mark_issuers` claim, built with the library's claim bag: each trust mark type
     * maps to the entities authorised to issue it. Types with no registered issuers list this
     * TA (it issues them itself).
     *
     * @return array<string,mixed>
     */
    private function trustMarkIssuers(PDO $pdo, string $entityId): array
    {
        $bag = new TrustMarkIssuersClaimBag();

        foreach ((new TrustMarkIssuerRepository($pdo))->issuersByTrustMarkType() as $trustMarkType => $issuers) {
            $bag->add(new TrustMarkIssuersClaimValue($trustMarkType, $issuers === [] ? [$entityId] : $issuers));
        }

        return $bag->getAll() === [] ? [] : $bag->jsonSerialize();
    }


    /**
     * The `trust_mark_owners` claim, built with the library's claim bag.
     *
     * @return array<string,mixed>
     */
    private function trustMarkOwners(PDO $pdo): array
    {
        $bag = new TrustMarkOwnersClaimBag();

        foreach ((new TrustMarkOwnerRepository($pdo))->ownersByTrustMarkType() as $trustMarkType => $owner) {
            if (($owner['jwks']['keys'] ?? []) === []) {
                continue; // JwksClaim requires a non-empty key set.
            }

            $bag->add(new TrustMarkOwnersClaimValue(
                $trustMarkType,
                $owner['entity_id'],
                new JwksClaim($owner['jwks']),
            ));
        }

        return $bag->getAll() === [] ? [] : $bag->jsonSerialize();
    }


    /**
     * Claim names flagged critical among the API-managed additional claims.
     *
     * @return list<string>
     */
    private function criticalClaims(PDO $pdo): array
    {
        $crit = [];
        foreach ((new AdditionalClaimsRepository($pdo))->findAll(AdditionalClaimsRepository::SCOPE_ENTITY_CONFIGURATION) as $claim) {
            if ($claim['crit']) {
                $crit[] = $claim['claim'];
            }
        }

        return $crit;
    }
}
