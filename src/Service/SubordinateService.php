<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use InvalidArgumentException;
use LogicException;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Entity\SubordinateStatus;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateEventRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;

/**
 * Subordinate registry operations shared by the admin UI and the Federation Admin API.
 *
 * Every mutation records an audit event when an event repository is supplied, which is what
 * backs GET /api/v1/admin/subordinates/{id}/history.
 */
class SubordinateService
{
    public function __construct(
        private readonly SubordinateRepository $repository,
        private readonly ?SubordinateEventRepository $events = null,
    ) {
    }


    /**
     * Entity IDs of the active subordinates, for the federation list endpoint, optionally
     * filtered as OpenID Federation 1.0 §8.2.1 defines: by registered entity type, by having
     * any active trust mark issued by this TA, or an active one of a given type.
     *
     * @return string[]
     * @throws \LogicException When filtering by trust marks without $issuedMarks.
     */
    public function listSubordinates(
        ?string $entityType = null,
        bool $trustMarked = false,
        ?string $trustMarkType = null,
        ?IssuedTrustMarkRepository $issuedMarks = null,
    ): array {
        if ($entityType === null && !$trustMarked && $trustMarkType === null) {
            return $this->repository->getAllActiveEntityIds();
        }

        if (($trustMarked || $trustMarkType !== null) && $issuedMarks === null) {
            throw new LogicException('Filtering by trust marks needs the issued trust mark repository.');
        }

        $ids = [];
        foreach ($this->repository->findAll() as $sub) {
            if ($sub->status !== SubordinateStatus::Active->value) {
                continue;
            }
            if ($entityType !== null && !in_array($entityType, $sub->entityTypes, true)) {
                continue;
            }
            if ($issuedMarks !== null) {
                if ($trustMarkType !== null && $issuedMarks->findActive($trustMarkType, $sub->entityId) === null) {
                    continue;
                }
                if ($trustMarked && $issuedMarks->findActiveBySub($sub->entityId) === []) {
                    continue;
                }
            }
            $ids[] = $sub->entityId;
        }

        return $ids;
    }


    /**
     * Return all subordinates (any status) for admin display.
     *
     * @return \SimpleSAML\Module\oidanchor\Entity\Subordinate[]
     */
    public function findAll(): array
    {
        return $this->repository->findAll();
    }


    /**
     * Find a single subordinate by entity ID (any status).
     */
    public function findSubordinate(string $entityId): ?Subordinate
    {
        return $this->repository->findByEntityId($entityId);
    }


    /**
     * Find a single subordinate by its surrogate id (the API's InternalID).
     */
    public function findByInternalId(int $id): ?Subordinate
    {
        return $this->repository->findByInternalId($id);
    }


    /**
     * JSON-valued subordinate columns. create() and update() take them as decoded arrays (or
     * null); encoding happens only at the repository boundary. An empty array means "none".
     */
    private const array JSON_FIELDS = ['jwks', 'metadata', 'metadata_policy', 'constraints', 'extra_claims'];


    /**
     * Create a new subordinate from the given data array.
     *
     * @param array<string,mixed> $data JSON fields ({@see JSON_FIELDS}) as decoded arrays.
     * @throws \InvalidArgumentException When a JSON field is not an array or null.
     */
    public function create(array $data): Subordinate
    {
        $entityTypes = self::entityTypesFrom($data) ?? [];

        $sub = new Subordinate(
            entityId:       (string) $data['entity_id'],
            entityType:     $entityTypes[0] ?? null,
            entityTypes:    $entityTypes,
            jwks:           self::jsonField($data, 'jwks'),
            metadataPolicy: self::jsonField($data, 'metadata_policy'),
            extraClaims:    self::jsonField($data, 'extra_claims'),
            metadata:       self::jsonField($data, 'metadata'),
            constraints:    self::jsonField($data, 'constraints'),
            status:         !empty($data['status']) ? (string) $data['status'] : 'active',
            registeredAt:   time(),
            updatedAt:      null,
            description:    !empty($data['description']) ? (string) $data['description'] : null,
        );

        $id = $this->repository->create($sub);

        $this->events?->record(
            $id,
            $sub->entityId,
            'created',
            $sub->status,
            sprintf('subordinate created: %s', $sub->entityId),
        );

        return $this->repository->findByInternalId($id) ?? $sub;
    }


    /**
     * Update a subordinate. $data may contain any subset of the updatable fields.
     *
     * @param array<string,mixed> $data JSON fields ({@see JSON_FIELDS}) as decoded arrays.
     * @throws \InvalidArgumentException When a JSON field is not an array or null.
     */
    public function update(string $entityId, array $data, string $eventType = 'updated', ?string $message = null): void
    {
        $fields = ['updated_at' => time()];

        $entityTypes = self::entityTypesFrom($data);
        if ($entityTypes !== null) {
            $fields['entity_type']  = $entityTypes[0] ?? null;
            $fields['entity_types'] = $entityTypes !== [] ? $entityTypes : null;
        }

        foreach (self::JSON_FIELDS as $jsonField) {
            if (array_key_exists($jsonField, $data)) {
                $fields[$jsonField] = self::jsonField($data, $jsonField);
            }
        }

        if (array_key_exists('description', $data)) {
            $raw = trim((string) ($data['description'] ?? ''));
            $fields['description'] = $raw !== '' ? $raw : null;
        }

        $this->repository->update($entityId, $fields);

        $this->recordFor($entityId, $eventType, $message);
    }


    /**
     * Delete a subordinate.
     */
    public function delete(string $entityId): void
    {
        $sub = $this->repository->findByEntityId($entityId);

        $this->repository->delete($entityId);

        $this->events?->record(
            $sub?->id,
            $entityId,
            'deleted',
            $sub?->status,
            sprintf('subordinate deleted: %s', $entityId),
        );
    }


    /**
     * Block a subordinate: it stops being served by the federation endpoints.
     */
    public function block(string $entityId): void
    {
        $this->setStatus($entityId, SubordinateStatus::Blocked->value);
    }


    /**
     * Activate a subordinate (status = active).
     */
    public function activate(string $entityId): void
    {
        $this->setStatus($entityId, SubordinateStatus::Active->value);
    }


    /**
     * Set the status; must be one of {@see SubordinateStatus}.
     *
     * @throws \InvalidArgumentException For a value outside the shared vocabulary.
     */
    public function setStatus(string $entityId, string $status): void
    {
        if (SubordinateStatus::tryFrom($status) === null) {
            throw new InvalidArgumentException(sprintf(
                'Invalid subordinate status "%s"; expected one of: %s.',
                $status,
                implode(', ', SubordinateStatus::values()),
            ));
        }

        $this->repository->setStatus($entityId, $status);

        $sub = $this->repository->findByEntityId($entityId);
        $this->events?->record(
            $sub?->id,
            $entityId,
            'status_updated',
            $status,
            sprintf('status changed to %s', $status),
        );
    }


    /**
     * Check whether an entity ID is already registered.
     */
    public function exists(string $entityId): bool
    {
        return $this->repository->exists($entityId);
    }


    /**
     * @param array<string,mixed> $data
     * @return array<mixed>|null
     * @throws \InvalidArgumentException
     */
    private static function jsonField(array $data, string $field): ?array
    {
        $value = $data[$field] ?? null;

        if ($value !== null && !is_array($value)) {
            throw new InvalidArgumentException(sprintf(
                'Subordinate field "%s" must be a decoded array or null, got %s.',
                $field,
                get_debug_type($value),
            ));
        }

        return $value === [] ? null : $value;
    }


    /**
     * The registered entity types in $data: `entity_types` (a list) or the single `entity_type`.
     * Null when neither is present, so an update leaves the types alone.
     *
     * @param array<string,mixed> $data
     * @return list<string>|null
     */
    private static function entityTypesFrom(array $data): ?array
    {
        if (array_key_exists('entity_types', $data)) {
            $types = is_array($data['entity_types']) ? $data['entity_types'] : [];
        } elseif (array_key_exists('entity_type', $data)) {
            $types = [$data['entity_type']];
        } else {
            return null;
        }

        return array_values(array_unique(array_filter(
            array_map(static fn(mixed $t): string => is_string($t) ? trim($t) : '', $types),
            static fn(string $t): bool => $t !== '',
        )));
    }


    /**
     * Record an audit event for a subordinate addressed by entity_id.
     */
    public function recordFor(string $entityId, string $eventType, ?string $message = null): void
    {
        if ($this->events === null) {
            return;
        }

        $sub = $this->repository->findByEntityId($entityId);
        $this->events->record($sub?->id, $entityId, $eventType, $sub?->status, $message);
    }
}
