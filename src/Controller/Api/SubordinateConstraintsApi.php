<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\SubordinateEventRepository;
use SimpleSAML\Module\oidanchor\Service\ConstraintsService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for per-subordinate constraints. These override the general constraints per member
 * when the subordinate statement is issued (see ConstraintsService::effective).
 */
class SubordinateConstraintsApi extends ApiController
{
    use ConstraintsTrait;

    private ?Subordinate $subordinate = null;


    public function get(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->constraintsIndex();
    }


    public function update(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->constraintsReplace($request);
    }


    /**
     * POST — copy the general constraints onto this subordinate.
     */
    public function copyFromGeneral(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        $general = (new ConstraintsService($this->buildPdo()))->general();
        $this->writeConstraints($general);

        return $this->json($general === [] ? new \stdClass() : $general, JsonResponse::HTTP_CREATED);
    }


    public function delete(Request $request, string $subordinateID): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->constraintsDelete();
    }


    public function getMaxPathLength(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->maxPathLengthGet();
    }


    public function setMaxPathLength(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->maxPathLengthSet($request);
    }


    public function deleteMaxPathLength(Request $request, string $subordinateID): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->maxPathLengthDelete();
    }


    public function getNamingConstraints(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->namingConstraintsGet();
    }


    public function setNamingConstraints(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->namingConstraintsSet($request);
    }


    public function deleteNamingConstraints(Request $request, string $subordinateID): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->namingConstraintsDelete();
    }


    public function getAllowedEntityTypes(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->allowedEntityTypesGet();
    }


    public function setAllowedEntityTypes(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->allowedEntityTypesSet($request);
    }


    public function addAllowedEntityType(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->allowedEntityTypesAdd($request);
    }


    public function deleteAllowedEntityType(Request $request, string $subordinateID, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->allowedEntityTypeDelete($entityType);
    }


    // -------------------------------------------------------------------------

    private function bind(string $subordinateID): bool
    {
        $this->subordinate = $this->resolveSubordinate($subordinateID);

        return $this->subordinate !== null;
    }


    /**
     * @return array<string,mixed>
     */
    protected function readConstraints(): array
    {
        return $this->subordinate?->constraints ?? [];
    }


    /**
     * @param array<string,mixed> $constraints
     */
    protected function writeConstraints(array $constraints): void
    {
        $subordinate = $this->subordinate;
        if ($subordinate === null) {
            return;
        }

        $pdo = $this->buildPdo();
        (new ConstraintsService($pdo))->setForSubordinate($subordinate->entityId, $constraints);

        (new SubordinateEventRepository($pdo))->record(
            $subordinate->id,
            $subordinate->entityId,
            $constraints === [] ? 'constraints_deleted' : 'constraints_updated',
            $subordinate->status,
            'subordinate constraints updated',
        );

        Logger::info(sprintf('oidanchor: API subordinate constraints updated: %s', $subordinate->entityId));

        $this->subordinate = $this->subordinateService()->findSubordinate($subordinate->entityId);
    }
}
