<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Module\oidanchor\Entity\Subordinate;
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
     * Return entity IDs of all active subordinates (for the federation list endpoint).
     *
     * @return string[]
     */
    public function listSubordinates(): array
    {
        return $this->repository->getAllActiveEntityIds();
    }


    /**
     * Return all subordinates (any status) for admin display.
     *
     * @return Subordinate[]
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
     * Create a new subordinate from the given data array.
     *
     * @param array<string,mixed> $data
     */
    public function create(array $data): Subordinate
    {
        $sub = new Subordinate(
            entityId:       (string) $data['entity_id'],
            entityType:     !empty($data['entity_type']) ? (string) $data['entity_type'] : null,
            jwks:           !empty($data['jwks'])
                                ? json_decode((string) $data['jwks'], true)
                                : null,
            metadataPolicy: !empty($data['metadata_policy'])
                                ? json_decode((string) $data['metadata_policy'], true)
                                : null,
            extraClaims:    !empty($data['extra_claims'])
                                ? json_decode((string) $data['extra_claims'], true)
                                : null,
            status:         !empty($data['status']) ? (string) $data['status'] : 'active',
            registeredAt:   time(),
            updatedAt:      null,
            includeTrustMarks: !empty($data['include_trust_marks']),
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
     * Update a subordinate. $data may contain any subset of updatable fields as raw input.
     *
     * @param array<string,mixed> $data
     */
    public function update(string $entityId, array $data, string $eventType = 'updated', ?string $message = null): void
    {
        $fields = ['updated_at' => time()];

        if (array_key_exists('entity_type', $data)) {
            $fields['entity_type'] = !empty($data['entity_type']) ? (string) $data['entity_type'] : null;
        }

        foreach (['jwks', 'metadata', 'metadata_policy', 'constraints', 'extra_claims'] as $jsonColumn) {
            if (array_key_exists($jsonColumn, $data)) {
                $raw = trim((string) ($data[$jsonColumn] ?? ''));
                $fields[$jsonColumn] = $raw !== '' ? $raw : null;
            }
        }

        if (array_key_exists('include_trust_marks', $data)) {
            $fields['include_trust_marks'] = !empty($data['include_trust_marks']) ? 1 : 0;
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
     * Suspend a subordinate (status = suspended).
     */
    public function suspend(string $entityId): void
    {
        $this->setStatus($entityId, 'suspended');
    }


    /**
     * Activate a subordinate (status = active).
     */
    public function activate(string $entityId): void
    {
        $this->setStatus($entityId, 'active');
    }


    /**
     * Set an arbitrary status value (e.g. active, blocked, pending, inactive).
     */
    public function setStatus(string $entityId, string $status): void
    {
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
