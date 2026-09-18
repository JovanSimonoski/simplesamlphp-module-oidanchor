<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for per-subordinate metadata policies at the spec's four granularities, plus the
 * copy-from-general and delete-all operations.
 *
 * The document is persisted on the subordinate row and merged with the federation-wide policy
 * (library MetadataPolicyResolver) when the subordinate statement is issued.
 */
class SubordinateMetadataPoliciesApi extends ApiController
{
    use MetadataPolicyDocumentTrait;

    private ?Subordinate $subordinate = null;


    // ---- whole policy -----------------------------------------------------

    public function getAll(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyIndex();
    }


    public function replaceAll(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyReplace($request);
    }


    /**
     * POST — copy the federation-wide policies onto this subordinate.
     */
    public function copyFromGeneral(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        $general = [];
        foreach ((new FederationPolicyRepository($this->buildPdo()))->findAll() as $entry) {
            $general[$entry->entityType] = $entry->policy;
        }

        $this->writePolicyDocument($general);

        return $this->json($general === [] ? new \stdClass() : $general, JsonResponse::HTTP_CREATED);
    }


    public function deleteAll(Request $request, string $subordinateID): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        $this->writePolicyDocument([]);

        return $this->noContent();
    }


    // ---- per entity type --------------------------------------------------

    public function getForType(Request $request, string $subordinateID, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyForType($entityType);
    }


    public function putForType(Request $request, string $subordinateID, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyPutType($request, $entityType);
    }


    public function addForType(Request $request, string $subordinateID, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyAddClaims($request, $entityType);
    }


    public function deleteForType(Request $request, string $subordinateID, string $entityType): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyDeleteType($entityType);
    }


    // ---- per claim --------------------------------------------------------

    public function getClaim(Request $request, string $subordinateID, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyGetClaim($entityType, $claim);
    }


    public function putClaim(Request $request, string $subordinateID, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyPutClaim($request, $entityType, $claim);
    }


    public function addOperators(Request $request, string $subordinateID, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyAddOperators($request, $entityType, $claim);
    }


    public function deleteClaim(Request $request, string $subordinateID, string $entityType, string $claim): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyDeleteClaim($entityType, $claim);
    }


    // ---- per operator -----------------------------------------------------

    public function getOperator(Request $request, string $subordinateID, string $entityType, string $claim, string $operator): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyGetOperator($entityType, $claim, $operator);
    }


    public function putOperator(Request $request, string $subordinateID, string $entityType, string $claim, string $operator): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyPutOperator($request, $entityType, $claim, $operator);
    }


    public function deleteOperator(Request $request, string $subordinateID, string $entityType, string $claim, string $operator): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->policyDeleteOperator($entityType, $claim, $operator);
    }


    // -------------------------------------------------------------------------

    private function bind(string $subordinateID): bool
    {
        $this->subordinate = $this->resolveSubordinate($subordinateID);

        return $this->subordinate !== null;
    }


    /**
     * @return array<string,array<string,mixed>>
     */
    protected function readPolicyDocument(): array
    {
        return $this->subordinate?->metadataPolicy ?? [];
    }


    /**
     * @param array<string,array<string,mixed>> $document
     */
    protected function writePolicyDocument(array $document): void
    {
        $subordinate = $this->subordinate;
        if ($subordinate === null) {
            return;
        }

        $this->subordinateService()->update(
            $subordinate->entityId,
            ['metadata_policy' => $document === [] ? null : json_encode($document, JSON_UNESCAPED_SLASHES)],
            $document === [] ? 'policy_deleted' : 'policy_updated',
            'subordinate metadata policy updated',
        );

        $this->subordinate = $this->subordinateService()->findSubordinate($subordinate->entityId);
    }
}
