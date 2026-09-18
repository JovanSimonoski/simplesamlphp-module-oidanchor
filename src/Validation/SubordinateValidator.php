<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Validation;

use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Jwks\Factories\JwksDecoratorFactory;
use Throwable;

class SubordinateValidator
{
    private const VALID_STATUSES = ['active', 'suspended'];


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
            } elseif (!$this->isHttpsUrl((string) $data['entity_id'])) {
                $errors['entity_id'] = 'Entity ID must be a valid HTTPS URL (must start with https://).';
            }
        }

        if (!empty($data['entity_type'])) {
            $validTypes = array_column(EntityTypesEnum::cases(), 'value');
            if (!in_array($data['entity_type'], $validTypes, true)) {
                $errors['entity_type'] = sprintf(
                    'Unknown entity type. Valid types: %s.',
                    implode(', ', $validTypes),
                );
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

        if (isset($data['status']) && !in_array($data['status'], self::VALID_STATUSES, true)) {
            $errors['status'] = 'Status must be one of: ' . implode(', ', self::VALID_STATUSES) . '.';
        }

        return $errors;
    }


    private function isHttpsUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
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
