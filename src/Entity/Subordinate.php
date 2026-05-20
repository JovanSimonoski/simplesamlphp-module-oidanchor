<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Entity;

class Subordinate
{
    public function __construct(
        public readonly string $entityId,
        public readonly ?string $entityType,
        public readonly ?array $jwks,
        public readonly ?array $metadataPolicy,
        public readonly ?array $extraClaims,
        public readonly string $status,
        public readonly int $registeredAt,
        public readonly ?int $updatedAt,
    ) {
    }


    /**
     * @param array<string,mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            entityId:       (string) $row['entity_id'],
            entityType:     isset($row['entity_type']) ? (string) $row['entity_type'] : null,
            jwks:           isset($row['jwks']) ? json_decode((string) $row['jwks'], true) : null,
            metadataPolicy: isset($row['metadata_policy'])
                                ? json_decode((string) $row['metadata_policy'], true)
                                : null,
            extraClaims:    isset($row['extra_claims'])
                                ? json_decode((string) $row['extra_claims'], true)
                                : null,
            status:         isset($row['status']) ? (string) $row['status'] : 'active',
            registeredAt:   (int) $row['registered_at'],
            updatedAt:      isset($row['updated_at']) ? (int) $row['updated_at'] : null,
        );
    }
}
