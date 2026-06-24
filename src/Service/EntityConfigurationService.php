<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use PDO;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use Throwable;

/**
 * Assembles the Trust Anchor's Entity Configuration claim set.
 *
 * Single source of truth shared by the signed /.well-known/openid-federation endpoint and the
 * read-only admin API (GET /api/v1/admin/entity-configuration), so the two never drift.
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
        $baseUrl  = $moduleConfig->getString('base_url');
        $lifetime = $moduleConfig->getOptionalInteger('entity_configuration_lifetime', 86400) ?? 86400;
        /** @var string[] $authorityHints */
        $authorityHints = $moduleConfig->getOptionalArray('authority_hints', []) ?? [];

        $fetchEndpoint = $moduleConfig->getOptionalString('federation_fetch_endpoint', null)
            ?? $baseUrl . '/federation/fetch';
        $listEndpoint  = $moduleConfig->getOptionalString('federation_list_endpoint', null)
            ?? $baseUrl . '/federation/list';

        $now = time();

        $payload = [
            ClaimsEnum::Iss->value      => $entityId,
            ClaimsEnum::Sub->value      => $entityId,
            ClaimsEnum::Iat->value      => $now,
            ClaimsEnum::Exp->value      => $now + $lifetime,
            ClaimsEnum::Jwks->value     => $this->keys->publicJwks(),
            ClaimsEnum::Metadata->value => [
                EntityTypesEnum::FederationEntity->value => [
                    ClaimsEnum::FederationFetchEndpoint->value => $fetchEndpoint,
                    ClaimsEnum::FederationListEndpoint->value  => $listEndpoint,
                ],
            ],
        ];

        if ($authorityHints !== []) {
            $payload[ClaimsEnum::AuthorityHints->value] = $authorityHints;
        }

        // Advertise the Trust Mark Types this TA issues (defensive: never fail EC over a TM lookup).
        try {
            $types = (new TrustMarkTypeRepository($pdo))->findAll();

            if ($types !== []) {
                $issuers = [];
                foreach ($types as $type) {
                    $issuers[$type->trustMarkId] = [$entityId];
                }
                $payload[ClaimsEnum::TrustMarkIssuers->value] = $issuers;
            }
        } catch (Throwable $e) {
            Logger::warning('oidanchor: could not load trust mark types for entity configuration: ' . $e->getMessage());
        }

        return $payload;
    }
}
