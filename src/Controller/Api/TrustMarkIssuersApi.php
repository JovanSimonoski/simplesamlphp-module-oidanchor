<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkIssuerRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for global trust mark issuers and their type associations.
 * Issuers drive the `trust_mark_issuers` claim of the TA's entity configuration.
 */
class TrustMarkIssuersApi extends ApiController
{
    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->repo()->findAll());
    }


    public function create(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $issuer = trim((string) ($body['issuer'] ?? ''));
        if ($issuer === '') {
            return $this->badRequest('issuer is required.');
        }

        try {
            $id = $this->repo()->create($issuer, isset($body['description']) ? (string) $body['description'] : null);
        } catch (InvalidArgumentException $e) {
            return $this->conflict($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API trust mark issuer created: %s', $issuer));

        return $this->json($this->repo()->findById($id), JsonResponse::HTTP_CREATED);
    }


    public function get(Request $request, string $issuerID): JsonResponse
    {
        $this->requireAdmin();

        $issuer = $this->find($issuerID);
        if ($issuer === null) {
            return $this->issuerNotFound($issuerID);
        }

        return $this->json($issuer);
    }


    public function update(Request $request, string $issuerID): JsonResponse
    {
        $this->requireAdmin();

        $issuer = $this->find($issuerID);
        if ($issuer === null) {
            return $this->issuerNotFound($issuerID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $issuerId = trim((string) ($body['issuer'] ?? ''));
        if ($issuerId === '') {
            return $this->badRequest('issuer is required.');
        }

        $conflicting = $this->repo()->findByIssuer($issuerId);
        if ($conflicting !== null && (int) $conflicting['id'] !== (int) $issuer['id']) {
            return $this->conflict(sprintf('Trust mark issuer "%s" already exists.', $issuerId));
        }

        $this->repo()->update(
            (int) $issuer['id'],
            $issuerId,
            isset($body['description']) ? (string) $body['description'] : null,
        );
        Logger::info(sprintf('oidanchor: API trust mark issuer updated: %s', $issuerId));

        return $this->json($this->repo()->findById((int) $issuer['id']));
    }


    public function delete(Request $request, string $issuerID): Response
    {
        $this->requireAdmin();

        $issuer = $this->find($issuerID);
        if ($issuer === null) {
            return $this->issuerNotFound($issuerID);
        }

        $this->repo()->delete((int) $issuer['id']);
        Logger::info(sprintf('oidanchor: API trust mark issuer deleted: %s', (string) $issuer['issuer']));

        return $this->noContent();
    }


    // ---- issuer → types ------------------------------------------------------

    public function listTypes(Request $request, string $issuerID): JsonResponse
    {
        $this->requireAdmin();

        $issuer = $this->find($issuerID);
        if ($issuer === null) {
            return $this->issuerNotFound($issuerID);
        }

        return $this->json($this->typesOf((int) $issuer['id']));
    }


    /**
     * PUT — replace the issuer's type associations with the supplied InternalID list.
     */
    public function setTypes(Request $request, string $issuerID): JsonResponse
    {
        $this->requireAdmin();

        $issuer = $this->find($issuerID);
        if ($issuer === null) {
            return $this->issuerNotFound($issuerID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body) || !array_is_list($body)) {
            return $this->badRequest('Body must be a JSON array of trust mark type IDs.');
        }

        $issuerId = (int) $issuer['id'];
        $this->repo()->unlinkAllOfIssuer($issuerId);

        foreach ($body as $rawId) {
            $typeId = $this->resolveTypeId($rawId);
            if ($typeId === null) {
                return $this->badRequest(sprintf('Unknown trust mark type ID "%s".', (string) $rawId));
            }
            $this->repo()->link($typeId, $issuerId);
        }

        Logger::info(sprintf('oidanchor: API trust mark issuer types set: %s', (string) $issuer['issuer']));

        return $this->json($this->typesOf($issuerId));
    }


    /**
     * POST — associate one more type with the issuer (text/plain or JSON InternalID).
     */
    public function addType(Request $request, string $issuerID): JsonResponse
    {
        $this->requireAdmin();

        $issuer = $this->find($issuerID);
        if ($issuer === null) {
            return $this->issuerNotFound($issuerID);
        }

        $raw = trim($this->bodyString($request), " \t\n\r\0\x0B\"");
        if ($raw === '') {
            return $this->badRequest('Body must contain the trust mark type ID.');
        }

        $typeId = $this->resolveTypeId($raw);
        if ($typeId === null) {
            return $this->badRequest(sprintf('Unknown trust mark type ID "%s".', $raw));
        }

        $this->repo()->link($typeId, (int) $issuer['id']);
        Logger::info(sprintf('oidanchor: API trust mark issuer type added: %s', (string) $issuer['issuer']));

        return $this->json($this->typesOf((int) $issuer['id']), JsonResponse::HTTP_CREATED);
    }


    public function unlinkType(Request $request, string $issuerID, string $trustMarkTypeID): Response
    {
        $this->requireAdmin();

        $issuer = $this->find($issuerID);
        $typeId = $this->internalId($trustMarkTypeID);

        if ($issuer !== null && $typeId !== null) {
            $this->repo()->unlink($typeId, (int) $issuer['id']);
            Logger::info(sprintf('oidanchor: API trust mark issuer type unlinked: %s', (string) $issuer['issuer']));
        }

        // The spec declares only 204 for this operation.
        return $this->noContent();
    }


    // -------------------------------------------------------------------------

    private function resolveTypeId(mixed $rawId): ?int
    {
        $typeId = is_int($rawId) ? $rawId : $this->internalId((string) $rawId);

        return $typeId !== null && $this->typeRepo()->findByInternalId($typeId) !== null ? $typeId : null;
    }


    /**
     * @return list<array<string,mixed>>
     */
    private function typesOf(int $issuerId): array
    {
        $repo  = $this->typeRepo();
        $types = [];

        foreach ($this->repo()->typeIdsOfIssuer($issuerId) as $typeId) {
            $type = $repo->findByInternalId($typeId);
            if ($type instanceof TrustMarkType) {
                $types[] = $type->toApi();
            }
        }

        return $types;
    }


    /**
     * @return array<string,mixed>|null
     */
    private function find(string $issuerID): ?array
    {
        $id = $this->internalId($issuerID);

        return $id !== null ? $this->repo()->findById($id) : null;
    }


    private function issuerNotFound(string $issuerID): JsonResponse
    {
        return $this->notFound(sprintf('Trust mark issuer "%s" not found.', $issuerID));
    }


    private function repo(): TrustMarkIssuerRepository
    {
        return new TrustMarkIssuerRepository($this->buildPdo());
    }


    private function typeRepo(): TrustMarkTypeRepository
    {
        return new TrustMarkTypeRepository($this->buildPdo());
    }
}
