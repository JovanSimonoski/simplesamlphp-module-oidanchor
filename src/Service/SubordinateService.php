<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;

class SubordinateService
{
    public function __construct(
        private readonly SubordinateRepository $repository,
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

        $this->repository->create($sub);

        return $sub;
    }


    /**
     * Update a subordinate. $data may contain any subset of updatable fields as raw input.
     *
     * @param array<string,mixed> $data
     */
    public function update(string $entityId, array $data): void
    {
        $fields = ['updated_at' => time()];

        if (array_key_exists('entity_type', $data)) {
            $fields['entity_type'] = !empty($data['entity_type']) ? (string) $data['entity_type'] : null;
        }

        if (array_key_exists('jwks', $data)) {
            $raw = trim((string) ($data['jwks'] ?? ''));
            $fields['jwks'] = $raw !== '' ? $raw : null;
        }

        if (array_key_exists('metadata_policy', $data)) {
            $raw = trim((string) ($data['metadata_policy'] ?? ''));
            $fields['metadata_policy'] = $raw !== '' ? $raw : null;
        }

        if (array_key_exists('extra_claims', $data)) {
            $raw = trim((string) ($data['extra_claims'] ?? ''));
            $fields['extra_claims'] = $raw !== '' ? $raw : null;
        }

        if (array_key_exists('include_trust_marks', $data)) {
            $fields['include_trust_marks'] = !empty($data['include_trust_marks']) ? 1 : 0;
        }

        if (array_key_exists('description', $data)) {
            $raw = trim((string) ($data['description'] ?? ''));
            $fields['description'] = $raw !== '' ? $raw : null;
        }

        $this->repository->update($entityId, $fields);
    }


    /**
     * Delete a subordinate.
     */
    public function delete(string $entityId): void
    {
        $this->repository->delete($entityId);
    }


    /**
     * Suspend a subordinate (status = suspended).
     */
    public function suspend(string $entityId): void
    {
        $this->repository->setStatus($entityId, 'suspended');
    }


    /**
     * Activate a subordinate (status = active).
     */
    public function activate(string $entityId): void
    {
        $this->repository->setStatus($entityId, 'active');
    }


    /**
     * Set an arbitrary status value (e.g. active, blocked, pending, inactive).
     */
    public function setStatus(string $entityId, string $status): void
    {
        $this->repository->setStatus($entityId, $status);
    }


    /**
     * Check whether an entity ID is already registered.
     */
    public function exists(string $entityId): bool
    {
        return $this->repository->exists($entityId);
    }
}
