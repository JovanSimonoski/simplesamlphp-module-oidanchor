<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use PDO;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\AdditionalClaimsRepository;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;

/**
 * Assembles the Subordinate Statement claim set for a subordinate.
 *
 * Single source of truth shared by the signed /federation/fetch endpoint and the admin API
 * (GET /api/v1/admin/subordinates/{id}/statement) so the issued statement and the admin view
 * never drift. Callers are responsible for validating the subordinate is active and has a JWKS.
 *
 * Claims assembled here: jwks, metadata (per-subordinate overrides), metadata_policy (federation
 * -wide merged with per-subordinate), metadata_policy_crit, constraints (general merged with
 * per-subordinate), trust_marks, and additional claims (general defaults overlaid with
 * per-subordinate ones).
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
        $lifetime = $this->lifetime($moduleConfig, $pdo);

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

        if ($subordinate->metadata !== null && $subordinate->metadata !== []) {
            $payload[ClaimsEnum::Metadata->value] = $subordinate->metadata;
        }

        if ($mergedPolicy !== null) {
            $payload[ClaimsEnum::MetadataPolicy->value] = $mergedPolicy;

            $crit = (new MetadataPolicyCritService($pdo))->all();
            if ($crit !== []) {
                $payload[ClaimsEnum::MetadataPolicyCrit->value] = $crit;
            }
        }

        $constraints = (new ConstraintsService($pdo))->effective($subordinate);
        if ($constraints !== null) {
            // simplesamlphp/openid models no constraints claim (checked Codebooks\ClaimsEnum and
            // Federation\*), so the OpenID Federation 1.0 §3.1 claim name is used literally.
            $payload[ConstraintsService::CLAIM] = $constraints;
        }

        foreach ($this->additionalClaims($subordinate, $pdo) as $claim => $value) {
            if (!array_key_exists($claim, $payload)) {
                $payload[$claim] = $value;
            }
        }

        // NOTE: a `trust_marks` claim is deliberately NOT emitted here. Per OpenID Federation 1.0,
        // an entity's Trust Marks live in that entity's own Entity Configuration (iss == sub), not
        // in the superior's Subordinate Statement about it (iss = TA, sub = subordinate). The
        // simplesamlphp/openid library enforces exactly this: EntityStatement::validate() throws
        // "Trust Marks claim encountered in configuration statement" when a non-configuration
        // statement carries `trust_marks`, so signing such a statement would fail. The
        // `include_trust_marks` column is retained (inert) to avoid a migration; the TA advertises
        // the marks it issues via `trust_mark_issuers` in its own Entity Configuration instead.

        return $payload;
    }


    /**
     * The subordinate statement lifetime: API-managed setting, else the config default.
     */
    public function lifetime(Configuration $moduleConfig, PDO $pdo): int
    {
        return (new SettingsRepository($pdo))->getInt(SettingsRepository::SUBORDINATE_STATEMENT_LIFETIME)
            ?? $moduleConfig->getOptionalInteger('subordinate_statement_lifetime', 86400)
            ?? 86400;
    }


    /**
     * General subordinate additional claims overlaid with the per-subordinate ones.
     * The legacy `extra_claims` column is applied first so pre-migration data keeps working.
     *
     * @return array<string,mixed>
     */
    private function additionalClaims(Subordinate $subordinate, PDO $pdo): array
    {
        $repo = new AdditionalClaimsRepository($pdo);

        $claims = $subordinate->extraClaims ?? [];
        $claims = array_merge($claims, $repo->asMap(AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL));

        if ($subordinate->id !== null) {
            $claims = array_merge(
                $claims,
                $repo->asMap(AdditionalClaimsRepository::SCOPE_SUBORDINATE, $subordinate->id),
            );
        }

        return $claims;
    }
}
