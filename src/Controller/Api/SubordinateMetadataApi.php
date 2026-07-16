<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for per-subordinate metadata at the spec's three granularities. The document is
 * persisted on the subordinate row and emitted as the `metadata` claim of the subordinate
 * statement (see SubordinateStatementService).
 */
class SubordinateMetadataApi extends ApiController
{
    use MetadataDocumentTrait;

    private ?Subordinate $subordinate = null;


    public function getMetadata(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataIndex();
    }


    public function updateMetadata(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataReplace($request);
    }


    public function getEntityTypedMetadata(Request $request, string $subordinateID, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataForType($entityType);
    }


    public function changeEntityTypedMetadata(Request $request, string $subordinateID, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataPutType($request, $entityType);
    }


    public function addMetadataClaims(Request $request, string $subordinateID, string $entityType): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataAddClaims($request, $entityType);
    }


    public function deleteEntityTypedMetadata(Request $request, string $subordinateID, string $entityType): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataDeleteType($entityType);
    }


    public function getMetadataClaim(Request $request, string $subordinateID, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataGetClaim($entityType, $claim);
    }


    public function changeMetadataClaim(Request $request, string $subordinateID, string $entityType, string $claim): JsonResponse
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataPutClaim($request, $entityType, $claim);
    }


    public function deleteMetadataClaim(Request $request, string $subordinateID, string $entityType, string $claim): Response
    {
        $this->requireAdmin();

        if (!$this->bind($subordinateID)) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->metadataDeleteClaim($entityType, $claim);
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
    protected function readMetadataDocument(): array
    {
        return $this->subordinate?->metadata ?? [];
    }


    /**
     * @param array<string,array<string,mixed>> $document
     */
    protected function writeMetadataDocument(array $document): void
    {
        $subordinate = $this->subordinate;
        if ($subordinate === null) {
            return;
        }

        $this->subordinateService()->update(
            $subordinate->entityId,
            ['metadata' => $document === [] ? null : json_encode($document, JSON_UNESCAPED_SLASHES)],
            $document === [] ? 'metadata_deleted' : 'metadata_updated',
            'subordinate metadata updated',
        );

        // Re-read so subsequent granularity reads in the same request see the write.
        $this->subordinate = $this->subordinateService()->findSubordinate($subordinate->entityId);
    }
}
