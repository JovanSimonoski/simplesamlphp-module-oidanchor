<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Entity;

/**
 * A single Trust Mark the TA has issued.
 *
 * Rows are append-mostly: re-issuing a mark for the same (trust_mark_id, sub) creates a
 * new row, and revocation flips the status of an existing row rather than deleting it,
 * so the status endpoint can give honest historical answers.
 */
class IssuedTrustMark
{
    public function __construct(
        public readonly ?int $id,
        public readonly string $trustMarkId,
        public readonly string $sub,
        public readonly string $jwt,
        public readonly int $iat,
        public readonly ?int $exp,
        public readonly string $status,
        public readonly ?int $revokedAt,
        public readonly ?string $revocationReason,
    ) {
    }


    /**
     * @param array<string,mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            id:               isset($row['id']) ? (int) $row['id'] : null,
            trustMarkId:      (string) $row['trust_mark_id'],
            sub:              (string) $row['sub'],
            jwt:              (string) $row['jwt'],
            iat:              (int) $row['iat'],
            exp:              isset($row['exp']) ? (int) $row['exp'] : null,
            status:           isset($row['status']) ? (string) $row['status'] : 'active',
            revokedAt:        isset($row['revoked_at']) ? (int) $row['revoked_at'] : null,
            revocationReason: isset($row['revocation_reason']) ? (string) $row['revocation_reason'] : null,
        );
    }


    public function isActive(): bool
    {
        if ($this->status !== 'active') {
            return false;
        }

        return $this->exp === null || $this->exp > time();
    }
}
