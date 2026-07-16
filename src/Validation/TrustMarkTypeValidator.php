<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Validation;

/**
 * Validates Trust Mark Type admin input. Returns field => error-message pairs; empty means valid.
 */
class TrustMarkTypeValidator
{
    /**
     * Claim names the issuer controls — they must not be overridden via a type's extra_claims.
     */
    public const RESERVED_CLAIMS = ['iss', 'sub', 'iat', 'exp', 'id', 'trust_mark_id', 'trust_mark_type'];


    /**
     * @param array<string,mixed> $data
     * @param bool $isUpdate Skip the trust_mark_id checks on updates (it is immutable).
     * @return array<string,string>
     */
    public function validate(array $data, bool $isUpdate = false): array
    {
        $errors = [];

        if (!$isUpdate) {
            if (empty($data['trust_mark_id'])) {
                $errors['trust_mark_id'] = 'Trust Mark ID is required.';
            } elseif (!$this->isHttpsUrl((string) $data['trust_mark_id'])) {
                $errors['trust_mark_id'] = 'Trust Mark ID must be a valid HTTPS URL.';
            }
        }

        if (empty($data['name'])) {
            $errors['name'] = 'Name is required.';
        }

        if (!empty($data['logo_uri']) && !$this->isHttpsUrl((string) $data['logo_uri'])) {
            $errors['logo_uri'] = 'Logo URI must be a valid HTTPS URL.';
        }

        if (!empty($data['ref_uri']) && !$this->isHttpsUrl((string) $data['ref_uri'])) {
            $errors['ref_uri'] = 'Reference URI must be a valid HTTPS URL.';
        }

        if (isset($data['default_lifetime']) && $data['default_lifetime'] !== '') {
            if (!preg_match('/^\d+$/', (string) $data['default_lifetime']) || (int) $data['default_lifetime'] <= 0) {
                $errors['default_lifetime'] = 'Default lifetime must be a positive integer (seconds).';
            }
        }

        if (!empty($data['extra_claims'])) {
            $error = $this->validateExtraClaims((string) $data['extra_claims']);
            if ($error !== null) {
                $errors['extra_claims'] = $error;
            }
        }

        return $errors;
    }


    /**
     * Ensure extra_claims is a JSON object that does not set any reserved (issuer-controlled) claim.
     */
    private function validateExtraClaims(string $json): ?string
    {
        $decoded = json_decode($json, true);

        if (!is_array($decoded)) {
            return 'Extra claims must be valid JSON.';
        }

        if ($decoded !== [] && array_is_list($decoded)) {
            return 'Extra claims must be a JSON object, not an array.';
        }

        $reserved = array_intersect(self::RESERVED_CLAIMS, array_keys($decoded));
        if ($reserved !== []) {
            return sprintf(
                'Extra claims must not set issuer-controlled claims: %s.',
                implode(', ', $reserved),
            );
        }

        return null;
    }


    private function isHttpsUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
    }
}
