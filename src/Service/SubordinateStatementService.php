<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use PDO;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Federation\Claims\TrustMarksClaimValue;

/**
 * Assembles the Subordinate Statement claim set for a subordinate.
 *
 * Single source of truth shared by the signed /federation/fetch endpoint and the read-only admin
 * API (GET /api/v1/admin/subordinates/{id}/statement) so the issued statement and the admin view
 * never drift. Callers are responsible for validating the subordinate is active and has a JWKS.
 */
class SubordinateStatementService
{
    /**
     * Build the subordinate statement payload (claims). Does not sign.
     *
     * @return array<string,mixed>
     * @throws \SimpleSAML\OpenID\Exceptions\MetadataPolicyException When the merged policy is incompatible.
     */
    public function buildClaims(Subordinate $subordinate, Configuration $moduleConfig, PDO $pdo): array
    {
        $entityId = $moduleConfig->getString('entity_id');
        $lifetime = $moduleConfig->getOptionalInteger('subordinate_statement_lifetime', 86400) ?? 86400;

        // Merge federation-wide policy (per entity type) with the per-subordinate policy.
        $policyRepo      = new FederationPolicyRepository($pdo);
        $federationEntry = $subordinate->entityType !== null
            ? $policyRepo->findByEntityType($subordinate->entityType)
            : null;

        $federationWidePolicy = $federationEntry !== null
            ? [$federationEntry->entityType => $federationEntry->policy]
            : null;

        $mergedPolicy = (new MetadataPolicyMerger())->merge(
            $federationWidePolicy,
            $subordinate->metadataPolicy,
        );

        $now = time();

        $payload = [
            ClaimsEnum::Iss->value  => $entityId,
            ClaimsEnum::Sub->value  => $subordinate->entityId,
            ClaimsEnum::Iat->value  => $now,
            ClaimsEnum::Exp->value  => $now + $lifetime,
            ClaimsEnum::Jwks->value => $subordinate->jwks,
        ];

        if ($mergedPolicy !== null) {
            $payload[ClaimsEnum::MetadataPolicy->value] = $mergedPolicy;
        }

        if ($subordinate->extraClaims !== null) {
            foreach ($subordinate->extraClaims as $claim => $value) {
                $payload[$claim] = $value;
            }
        }

        if ($subordinate->includeTrustMarks) {
            $activeMarks = (new IssuedTrustMarkRepository($pdo))->findActiveBySub($subordinate->entityId);

            if ($activeMarks !== []) {
                $payload[ClaimsEnum::TrustMarks->value] = array_map(
                    static fn($mark): array =>
                        (new TrustMarksClaimValue($mark->trustMarkId, $mark->jwt))->jsonSerialize(),
                    $activeMarks,
                );
            }
        }

        return $payload;
    }
}
