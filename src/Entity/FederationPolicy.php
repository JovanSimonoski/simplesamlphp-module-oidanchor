<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Entity;

class FederationPolicy
{
    public function __construct(
        public readonly string $entityType,
        public readonly array $policy,
        public readonly int $createdAt,
        public readonly int $updatedAt,
    ) {
    }


    /**
     * @param array<string,mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            entityType: (string) $row['entity_type'],
            policy:     json_decode((string) $row['policy'], true) ?? [],
            createdAt:  (int) $row['created_at'],
            updatedAt:  (int) $row['updated_at'],
        );
    }
}
