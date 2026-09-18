<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for general (federation-wide) metadata policies, backed by FederationPolicyRepository.
 *
 * The stored per-entity-type document ({ claim: { operator: value } }) is exactly the spec's
 * EntityTypedMetadataPolicy, and the collection keyed by entity type is the spec's MetadataPolicy.
 * All four granularities come from MetadataPolicyDocumentTrait.
 */
class MetadataPoliciesApi extends ApiController
{
    use MetadataPolicyDocumentTrait;

    // ---- whole collection -------------------------------------------------

    public function getAll(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyIndex();
    }


    public function replaceAll(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyReplace($request);
    }


    // ---- per entity type --------------------------------------------------

    public function getForType(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyForType($entityType);
    }


    public function putForType(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyPutType($request, $entityType);
    }


    public function addForType(Request $request, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyAddClaims($request, $entityType);
    }


    public function deleteForType(Request $request, string $entityType): Response
    {
        $this->requireAdmin();

        return $this->policyDeleteType($entityType);
    }


    // ---- per claim --------------------------------------------------------

    public function getClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyGetClaim($entityType, $claim);
    }


    public function putClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyPutClaim($request, $entityType, $claim);
    }


    public function addOperators(Request $request, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyAddOperators($request, $entityType, $claim);
    }


    public function deleteClaim(Request $request, string $entityType, string $claim): Response
    {
        $this->requireAdmin();

        return $this->policyDeleteClaim($entityType, $claim);
    }


    // ---- per operator -----------------------------------------------------

    public function getOperator(Request $request, string $entityType, string $claim, string $operator): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyGetOperator($entityType, $claim, $operator);
    }


    public function putOperator(Request $request, string $entityType, string $claim, string $operator): JsonResponse
    {
        $this->requireAdmin();

        return $this->policyPutOperator($request, $entityType, $claim, $operator);
    }


    public function deleteOperator(Request $request, string $entityType, string $claim, string $operator): Response
    {
        $this->requireAdmin();

        return $this->policyDeleteOperator($entityType, $claim, $operator);
    }


    // -------------------------------------------------------------------------

    /**
     * @return array<string,array<string,mixed>>
     */
    protected function readPolicyDocument(): array
    {
        $document = [];
        foreach ((new FederationPolicyRepository($this->buildPdo()))->findAll() as $entry) {
            $document[$entry->entityType] = $entry->policy;
        }

        return $document;
    }


    /**
     * @param array<string,array<string,mixed>> $document
     */
    protected function writePolicyDocument(array $document): void
    {
        $repo = new FederationPolicyRepository($this->buildPdo());

        // Replace semantics: drop entity types no longer present, upsert the rest.
        foreach ($repo->findAll() as $entry) {
            if (!array_key_exists($entry->entityType, $document)) {
                $repo->delete($entry->entityType);
            }
        }

        foreach ($document as $entityType => $policy) {
            $repo->upsert((string) $entityType, $policy);
        }

        Logger::info('oidanchor: API general metadata policies updated');
    }
}
