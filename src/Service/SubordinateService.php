<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;

class SubordinateService
{
    public function __construct(
        private readonly SubordinateRepository $repository,
    ) {
    }


    /**
     * Return the entity IDs of all registered subordinates.
     *
     * @return string[]
     */
    public function listSubordinates(): array
    {
        return $this->repository->getAllEntityIds();
    }


    /**
     * Look up a subordinate by entity ID.
     * Returns null when the entity is not registered with this TA.
     *
     * @return array{entity_id: string, entity_type: string|null, jwks: string|null, registered_at: int}|null
     */
    public function findSubordinate(string $entityId): ?array
    {
        return $this->repository->findByEntityId($entityId);
    }
}
