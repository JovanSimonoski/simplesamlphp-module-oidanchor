<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use SimpleSAML\OpenID\Federation\MetadataPolicyResolver;
use SimpleSAML\OpenID\Helpers;

/**
 * Merges federation-wide and per-subordinate metadata policies using the
 * OpenID Federation spec's merging algorithm via simplesamlphp/openid.
 *
 * Both policy arguments use the full format: { entity_type: { param: { op: val } } }.
 * The federation-wide policy comes from oidanchor_metadata_policies (one row per entity type,
 * wrapped by the caller). The per-subordinate policy comes from oidanchor_subordinates.metadata_policy.
 */
class MetadataPolicyMerger
{
    private MetadataPolicyResolver $resolver;


    public function __construct()
    {
        $this->resolver = new MetadataPolicyResolver(new Helpers());
    }


    /**
     * Merge two full-format policy documents and return the merged claim, or null if the result is empty.
     *
     * The federation-wide policy is applied first; the per-subordinate policy is applied on top per the spec.
     *
     * @param array<string,mixed>|null $federationPolicy Federation-wide policy (full format, may be null).
     * @param array<string,mixed>|null $subordinatePolicy Per-subordinate policy (full format, may be null).
     * @return array<string,mixed>|null Merged metadata_policy claim, or null if nothing to embed.
     * @throws MetadataPolicyException If the two policies are incompatible (e.g. empty one_of intersection).
     */
    public function merge(?array $federationPolicy, ?array $subordinatePolicy): ?array
    {
        $policies = array_values(array_filter(
            [$federationPolicy, $subordinatePolicy],
            fn(?array $p): bool => $p !== null && $p !== [],
        ));

        if ($policies === []) {
            return null;
        }

        if (count($policies) === 1) {
            return $policies[0];
        }

        $result = [];

        foreach (EntityTypesEnum::cases() as $entityTypeEnum) {
            $merged = $this->resolver->for($entityTypeEnum, $policies);

            if ($merged !== []) {
                $result[$entityTypeEnum->value] = $merged;
            }
        }

        return $result !== [] ? $result : null;
    }
}
