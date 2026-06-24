<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Validation;

/**
 * Validates Trust Mark issuance admin input. Returns field => error-message pairs; empty means valid.
 *
 * Whether the referenced trust_mark_id exists in the catalog is checked by the controller
 * (it owns the repository); this class validates the shape of the submitted values.
 */
class IssuedTrustMarkValidator
{
    /**
     * @param array<string,mixed> $data
     * @return array<string,string>
     */
    public function validate(array $data): array
    {
        $errors = [];

        if (empty($data['trust_mark_id'])) {
            $errors['trust_mark_id'] = 'Trust Mark type is required.';
        }

        if (empty($data['sub'])) {
            $errors['sub'] = 'Subject (sub) is required.';
        } elseif (!$this->isHttpsUrl((string) $data['sub'])) {
            $errors['sub'] = 'Subject must be a valid HTTPS URL.';
        }

        if (isset($data['exp']) && $data['exp'] !== '') {
            if (!preg_match('/^\d+$/', (string) $data['exp']) || (int) $data['exp'] <= 0) {
                $errors['exp'] = 'Expiry override must be a positive integer (seconds from now).';
            }
        }

        if (!empty($data['extra_claims'])) {
            $decoded = json_decode((string) $data['extra_claims'], true);

            if (!is_array($decoded)) {
                $errors['extra_claims'] = 'Extra claims must be valid JSON.';
            } elseif ($decoded !== [] && array_is_list($decoded)) {
                $errors['extra_claims'] = 'Extra claims must be a JSON object, not an array.';
            } else {
                $reserved = array_intersect(TrustMarkTypeValidator::RESERVED_CLAIMS, array_keys($decoded));
                if ($reserved !== []) {
                    $errors['extra_claims'] = sprintf(
                        'Extra claims must not set issuer-controlled claims: %s.',
                        implode(', ', $reserved),
                    );
                }
            }
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
}
