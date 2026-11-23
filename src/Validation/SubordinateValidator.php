<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Validation;

use SimpleSAML\Module\oidanchor\Entity\SubordinateStatus;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use Throwable;

class SubordinateValidator
{
    /**
     * Validate subordinate data. Returns field => error-message pairs; empty means valid.
     *
     * @param array<string,mixed> $data
     * @param bool $isUpdate Skip entity_id and required-JWKS checks on updates.
     * @return array<string,string>
     */
    public function validate(array $data, bool $isUpdate = false): array
    {
        $errors = [];

        if (!$isUpdate) {
            if (empty($data['entity_id'])) {
                $errors['entity_id'] = 'Entity ID is required.';
            } elseif (!Url::isHttps((string) $data['entity_id'])) {
                $errors['entity_id'] = 'Entity ID must be a valid HTTPS URL (must start with https://).';
            }
        }

        $entityTypes = is_array($data['entity_types'] ?? null)
            ? $data['entity_types']
            : (empty($data['entity_type']) ? [] : [$data['entity_type']]);
        $validTypes = array_column(EntityTypesEnum::cases(), 'value');
        foreach ($entityTypes as $entityType) {
            if (!in_array($entityType, $validTypes, true)) {
                $errors['entity_types'] = sprintf(
                    'Unknown entity type. Valid types: %s.',
                    implode(', ', $validTypes),
                );
                break;
            }
        }

        if (!empty($data['jwks'])) {
            $jwksError = $this->validateJwks((string) $data['jwks']);
            if ($jwksError !== null) {
                $errors['jwks'] = $jwksError;
            }
        }

        if (!empty($data['metadata_policy'])) {
            $policyError = $this->validateMetadataPolicy((string) $data['metadata_policy']);
            if ($policyError !== null) {
                $errors['metadata_policy'] = $policyError;
            }
        }

        if (!empty($data['extra_claims'])) {
            $claimsDecoded = json_decode((string) $data['extra_claims'], true);
            if (!is_array($claimsDecoded)) {
                $errors['extra_claims'] = 'Extra claims must be valid JSON.';
            }
        }

        if (isset($data['status']) && SubordinateStatus::tryFrom((string) $data['status']) === null) {
            $errors['status'] = 'Status must be one of: ' . implode(', ', SubordinateStatus::values()) . '.';
        }

        return $errors;
    }


    private function validateJwks(string $jwksJson): ?string
    {
        $decoded = json_decode($jwksJson, true);

        if (!is_array($decoded)) {
            return 'JWKS must be valid JSON.';
        }

        if (!isset($decoded['keys']) || !is_array($decoded['keys'])) {
            return 'JWKS must be a JSON object with a "keys" array.';
        }

        if (empty($decoded['keys'])) {
            return 'JWKS must contain at least one key.';
        }

        try {
            (new JwksDecoratorFactory())->fromKeySetData($decoded);
        } catch (Throwable $e) {
            return 'Invalid JWKS: ' . $e->getMessage();
        }

        return null;
    }


    private function validateMetadataPolicy(string $json): ?string
    {
        return (new MetadataPolicyValidator())->validateFull($json);
    }
}
