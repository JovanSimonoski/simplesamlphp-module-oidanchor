<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Entity;

/**
 * A Trust Mark Type the TA is willing to issue.
 *
 * The trust_mark_id is the type identifier URL (it becomes the trust_mark_type claim
 * of every issued Trust Mark JWT). `id` is the surrogate key exposed as the API's
 * InternalID. extra_claims is an optional JSON object merged into every issued mark
 * of this type (superseded by the richer issuance-spec model, retained for the UI).
 */
class TrustMarkType
{
    /**
     * @param array<string,mixed>|null $extraClaims
     */
    public function __construct(
        public readonly string $trustMarkId,
        public readonly string $name,
        public readonly ?string $description,
        public readonly ?string $logoUri,
        public readonly ?string $refUri,
        public readonly ?int $defaultLifetime,
        public readonly ?array $extraClaims,
        public readonly int $createdAt,
        public readonly ?int $updatedAt,
        public readonly ?int $id = null,
    ) {
    }


    /**
     * @param array<string,mixed> $row
     */
    public static function fromRow(array $row): self
    {
        return new self(
            trustMarkId:     (string) $row['trust_mark_id'],
            name:            (string) $row['name'],
            description:     isset($row['description']) ? (string) $row['description'] : null,
            logoUri:         isset($row['logo_uri']) ? (string) $row['logo_uri'] : null,
            refUri:          isset($row['ref_uri']) ? (string) $row['ref_uri'] : null,
            defaultLifetime: isset($row['default_lifetime']) ? (int) $row['default_lifetime'] : null,
            extraClaims:     isset($row['extra_claims']) && $row['extra_claims'] !== null
                                ? json_decode((string) $row['extra_claims'], true)
                                : null,
            createdAt:       (int) $row['created_at'],
            updatedAt:       isset($row['updated_at']) ? (int) $row['updated_at'] : null,
            id:              isset($row['id']) ? (int) $row['id'] : null,
        );
    }


    /**
     * The spec's TrustMarkType shape.
     *
     * @return array<string,mixed>
     */
    public function toApi(): array
    {
        $data = [
            'id'              => $this->id,
            'trust_mark_type' => $this->trustMarkId,
        ];

        if ($this->description !== null) {
            $data['description'] = $this->description;
        }

        return $data;
    }
}
