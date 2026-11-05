<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Entity;

class Subordinate
{
    /**
     * Every registered entity type. $entityType is the primary (first) one, kept for callers
     * that need a single type.
     *
     * @var list<string>
     */
    public readonly array $entityTypes;


    /**
     * @param array<string,mixed>|null $jwks
     * @param array<string,mixed>|null $metadataPolicy
     * @param array<string,mixed>|null $extraClaims
     * @param array<string,mixed>|null $metadata
     * @param array<string,mixed>|null $constraints
     * @param list<string> $entityTypes All registered types; defaults to [$entityType].
     */
    public function __construct(
        public readonly string $entityId,
        public readonly ?string $entityType,
        public readonly ?array $jwks,
        public readonly ?array $metadataPolicy,
        public readonly ?array $extraClaims,
        public readonly string $status,
        public readonly int $registeredAt,
        public readonly ?int $updatedAt,
        public readonly bool $includeTrustMarks = false,
        public readonly ?string $description = null,
        public readonly ?int $id = null,
        public readonly ?array $metadata = null,
        public readonly ?array $constraints = null,
        array $entityTypes = [],
    ) {
        $this->entityTypes = $entityTypes !== [] ? $entityTypes : ($entityType !== null ? [$entityType] : []);
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
            includeTrustMarks: isset($row['include_trust_marks']) ? (bool) $row['include_trust_marks'] : false,
            description:    isset($row['description']) ? (string) $row['description'] : null,
            id:             isset($row['id']) ? (int) $row['id'] : null,
            metadata:       isset($row['metadata']) ? json_decode((string) $row['metadata'], true) : null,
            constraints:    isset($row['constraints']) ? json_decode((string) $row['constraints'], true) : null,
            entityTypes:    self::decodeEntityTypes($row['entity_types'] ?? null),
        );
    }


    /**
     * @return list<string>
     */
    private static function decodeEntityTypes(mixed $json): array
    {
        $decoded = is_string($json) ? json_decode($json, true) : null;

        return is_array($decoded) ? array_values(array_filter($decoded, 'is_string')) : [];
    }
}
