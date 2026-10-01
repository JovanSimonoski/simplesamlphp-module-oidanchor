<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The three metadata granularities the spec defines — whole document, one entity type, one
 * claim within an entity type — expressed against an abstract { entityType: { claim: value } }
 * document. Used by both the entity-configuration metadata endpoints and the per-subordinate
 * metadata endpoints, which differ only in where the document is persisted.
 *
 * Implementors provide readMetadataDocument() / writeMetadataDocument().
 */
trait MetadataDocumentTrait
{
    /**
     * @return array<string,array<string,mixed>>
     */
    abstract protected function readMetadataDocument(): array;


    /**
     * @param array<string,array<string,mixed>> $document
     */
    abstract protected function writeMetadataDocument(array $document): void;


    // ---- whole document ---------------------------------------------------

    protected function metadataIndex(): JsonResponse
    {
        $document = $this->readMetadataDocument();

        return $this->json($document === [] ? new \stdClass() : $document);
    }


    protected function metadataReplace(Request $request): JsonResponse
    {
        $body = $this->decodeJson($request);
        if (!is_array($body) || array_is_list($body)) {
            return $this->badRequest('Body must be a JSON object keyed by entity type.');
        }

        foreach ($body as $entityType => $claims) {
            if (!is_array($claims) || array_is_list($claims)) {
                return $this->badRequest(sprintf('Metadata for "%s" must be a JSON object.', $entityType));
            }
        }

        $this->writeMetadataDocument($body);

        return $this->metadataIndex();
    }


    // ---- one entity type --------------------------------------------------

    protected function metadataForType(string $entityType): JsonResponse
    {
        $document = $this->readMetadataDocument();
        if (!array_key_exists($entityType, $document)) {
            return $this->notFound(sprintf('No metadata for entity type "%s".', $entityType));
        }

        return $this->json($document[$entityType] === [] ? new \stdClass() : $document[$entityType]);
    }


    protected function metadataPutType(Request $request, string $entityType): JsonResponse
    {
        $claims = $this->decodeJson($request);
        if (!is_array($claims) || array_is_list($claims)) {
            return $this->badRequest('Body must be a JSON object of claim → value.');
        }

        $document = $this->readMetadataDocument();
        $document[$entityType] = $claims;
        $this->writeMetadataDocument($document);

        return $this->json($claims === [] ? new \stdClass() : $claims);
    }


    /**
     * POST — merge the supplied claims into the entity type's metadata.
     */
    protected function metadataAddClaims(Request $request, string $entityType): JsonResponse
    {
        $claims = $this->decodeJson($request);
        if (!is_array($claims) || array_is_list($claims)) {
            return $this->badRequest('Body must be a JSON object of claim → value.');
        }

        $document = $this->readMetadataDocument();
        $document[$entityType] = array_merge($document[$entityType] ?? [], $claims);
        $this->writeMetadataDocument($document);

        return $this->json($document[$entityType]);
    }


    protected function metadataDeleteType(string $entityType): Response
    {
        $document = $this->readMetadataDocument();
        if (array_key_exists($entityType, $document)) {
            unset($document[$entityType]);
            $this->writeMetadataDocument($document);
        }

        return $this->noContent();
    }


    // ---- one claim --------------------------------------------------------

    protected function metadataGetClaim(string $entityType, string $claim): JsonResponse
    {
        $document = $this->readMetadataDocument();
        if (!isset($document[$entityType]) || !array_key_exists($claim, $document[$entityType])) {
            return $this->notFound(sprintf('No metadata claim "%s" for entity type "%s".', $claim, $entityType));
        }

        return $this->json($document[$entityType][$claim]);
    }


    /**
     * PUT — 201 when the claim is newly created, 200 when it replaces an existing value.
     */
    protected function metadataPutClaim(Request $request, string $entityType, string $claim): JsonResponse
    {
        if (trim($request->getContent()) === '') {
            return $this->badRequest('Body must contain the claim value as JSON.');
        }

        $value = $this->decodeJson($request);
        if ($value === null && json_last_error() !== JSON_ERROR_NONE) {
            return $this->badRequest('Body must contain the claim value as valid JSON.');
        }

        $document = $this->readMetadataDocument();
        $existed  = isset($document[$entityType]) && array_key_exists($claim, $document[$entityType]);

        $document[$entityType][$claim] = $value;
        $this->writeMetadataDocument($document);

        return $this->json($value, $existed ? JsonResponse::HTTP_OK : JsonResponse::HTTP_CREATED);
    }


    protected function metadataDeleteClaim(string $entityType, string $claim): Response
    {
        $document = $this->readMetadataDocument();
        if (isset($document[$entityType]) && array_key_exists($claim, $document[$entityType])) {
            unset($document[$entityType][$claim]);
            $this->writeMetadataDocument($document);
        }

        return $this->noContent();
    }
}
