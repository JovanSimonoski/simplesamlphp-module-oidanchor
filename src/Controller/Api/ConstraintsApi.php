<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Service\ConstraintsService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for the federation-wide (general) constraints applied to every subordinate
 * statement, unless a per-subordinate constraint overrides the member.
 */
class ConstraintsApi extends ApiController
{
    use ConstraintsTrait;

    public function get(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->constraintsIndex();
    }


    public function update(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->constraintsReplace($request);
    }


    public function getMaxPathLength(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->maxPathLengthGet();
    }


    public function setMaxPathLength(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->maxPathLengthSet($request);
    }


    public function deleteMaxPathLength(Request $request): Response
    {
        $this->requireAdmin();

        return $this->maxPathLengthDelete();
    }


    public function getNamingConstraints(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->namingConstraintsGet();
    }


    public function setNamingConstraints(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->namingConstraintsSet($request);
    }


    public function deleteNamingConstraints(Request $request): Response
    {
        $this->requireAdmin();

        return $this->namingConstraintsDelete();
    }


    public function getAllowedEntityTypes(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->allowedEntityTypesGet();
    }


    public function setAllowedEntityTypes(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->allowedEntityTypesSet($request);
    }


    public function addAllowedEntityType(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->allowedEntityTypesAdd($request);
    }


    public function deleteAllowedEntityType(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        return $this->allowedEntityTypeDelete($entityType);
    }


    // -------------------------------------------------------------------------

    /**
     * @return array<string,mixed>
     */
    protected function readConstraints(): array
    {
        return (new ConstraintsService($this->buildPdo()))->general();
    }


    /**
     * @param array<string,mixed> $constraints
     */
    protected function writeConstraints(array $constraints): void
    {
        (new ConstraintsService($this->buildPdo()))->setGeneral($constraints);
        Logger::info('oidanchor: API general constraints updated');
    }
}
