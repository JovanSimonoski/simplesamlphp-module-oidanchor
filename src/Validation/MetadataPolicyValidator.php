<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Validation;

use SimpleSAML\OpenID\Codebooks\MetadataPolicyOperatorsEnum;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use SimpleSAML\OpenID\Federation\MetadataPolicyResolver;
use SimpleSAML\OpenID\Helpers;

/**
 * Validates metadata policy documents using the simplesamlphp/openid library.
 *
 * Two formats are handled:
 *  - Full: { entity_type: { param: { operator: value } } }  — used for subordinate policies
 *  - Entity-type: { param: { operator: value } }            — used for federation-wide policies
 */
class MetadataPolicyValidator
{
    private MetadataPolicyResolver $resolver;


    public function __construct()
    {
        $this->resolver = new MetadataPolicyResolver(new Helpers());
    }


    /**
     * Validate a full metadata policy document (entity_type → param → operators).
     *
     * Returns null on success, an error string on failure.
     */
    public function validateFull(string $json): ?string
    {
        $decoded = json_decode($json, true);

        if (!is_array($decoded)) {
            return 'Metadata policy must be valid JSON.';
        }

        try {
            $this->resolver->ensureFormat($decoded);
        } catch (MetadataPolicyException $e) {
            return 'Invalid metadata policy structure: ' . $e->getMessage();
        }

        return $this->validateParamOperators($decoded);
    }


    /**
     * Validate a per-entity-type policy document (param → operators), given a known entity type.
     *
     * Returns null on success, an error string on failure.
     */
    public function validateEntityTypePolicy(string $json, string $entityType): ?string
    {
        $decoded = json_decode($json, true);

        if (!is_array($decoded)) {
            return 'Policy must be valid JSON.';
        }

        // Wrap it so ensureFormat can validate the structure.
        $wrapped = [$entityType => $decoded];

        try {
            $this->resolver->ensureFormat($wrapped);
        } catch (MetadataPolicyException $e) {
            return 'Invalid policy structure: ' . $e->getMessage();
        }

        return $this->validateParamOperators($wrapped);
    }


    /**
     * Run operator-level validation (combinations and value types) on every parameter in $policy.
     *
     * @param array<string,array<string,array<string,mixed>>> $policy Full-format policy.
     */
    private function validateParamOperators(array $policy): ?string
    {
        foreach ($policy as $entityType => $params) {
            foreach ($params as $param => $ops) {
                if (!is_array($ops)) {
                    continue;
                }

                try {
                    MetadataPolicyOperatorsEnum::validateGeneralParameterOperationRules($ops);
                    MetadataPolicyOperatorsEnum::validateSpecificParameterOperationRules($ops);
                } catch (MetadataPolicyException $e) {
                    return sprintf(
                        'Invalid policy for "%s"."%s": %s',
                        $entityType,
                        $param,
                        $e->getMessage(),
                    );
                }
            }
        }

        return null;
    }
}
