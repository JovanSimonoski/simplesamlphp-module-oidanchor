<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkOwnerRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\Module\oidanchor\Service\TrustMarkDelegationService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * REST API for global trust mark owners and their type associations.
 * Owners drive the `trust_mark_owners` claim of the TA's entity configuration.
 */
class TrustMarkOwnersApi extends ApiController
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

        $entityId = trim((string) ($body['entity_id'] ?? ''));
        if ($entityId === '' || !$this->jwksHasKeys($body['jwks'] ?? null)) {
            return $this->badRequest('entity_id and a jwks with at least one key are required.');
        }

        try {
            $id = $this->repo()->create(
                $entityId,
                $body['jwks'],
                isset($body['description']) ? (string) $body['description'] : null,
            );
        } catch (InvalidArgumentException $e) {
            return $this->conflict($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API trust mark owner created: %s', $entityId));

        return $this->json($this->repo()->findById($id), JsonResponse::HTTP_CREATED);
    }


    public function get(Request $request, string $ownerID): JsonResponse
    {
        $this->requireAdmin();

        $owner = $this->find($ownerID);
        if ($owner === null) {
            return $this->ownerNotFound($ownerID);
        }

        return $this->json($owner);
    }


    public function update(Request $request, string $ownerID): JsonResponse
    {
        $this->requireAdmin();

        $owner = $this->find($ownerID);
        if ($owner === null) {
            return $this->ownerNotFound($ownerID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $entityId = trim((string) ($body['entity_id'] ?? ''));
        if ($entityId === '' || !$this->jwksHasKeys($body['jwks'] ?? null)) {
            return $this->badRequest('entity_id and a jwks with at least one key are required.');
        }

        $conflicting = $this->repo()->findByEntityId($entityId);
        if ($conflicting !== null && (int) $conflicting['id'] !== (int) $owner['id']) {
            return $this->conflict(sprintf('Trust mark owner "%s" already exists.', $entityId));
        }

        $this->repo()->update(
            (int) $owner['id'],
            $entityId,
            $body['jwks'],
            isset($body['description']) ? (string) $body['description'] : null,
        );
        Logger::info(sprintf('oidanchor: API trust mark owner updated: %s', $entityId));

        return $this->json($this->repo()->findById((int) $owner['id']));
    }


    public function delete(Request $request, string $ownerID): Response
    {
        $this->requireAdmin();

        $owner = $this->find($ownerID);
        if ($owner === null) {
            return $this->ownerNotFound($ownerID);
        }

        $this->repo()->delete((int) $owner['id']);
        Logger::info(sprintf('oidanchor: API trust mark owner deleted: %s', (string) $owner['entity_id']));

        return $this->noContent();
    }


    // ---- owner → types -------------------------------------------------------

    public function listTypes(Request $request, string $ownerID): JsonResponse
    {
        $this->requireAdmin();

        $owner = $this->find($ownerID);
        if ($owner === null) {
            return $this->ownerNotFound($ownerID);
        }

        return $this->json($this->typesOf((int) $owner['id']));
    }


    /**
     * PUT — replace the owner's type associations with the supplied InternalID list.
     */
    public function setTypes(Request $request, string $ownerID): JsonResponse
    {
        $this->requireAdmin();

        $owner = $this->find($ownerID);
        if ($owner === null) {
            return $this->ownerNotFound($ownerID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body) || !array_is_list($body)) {
            return $this->badRequest('Body must be a JSON array of trust mark type IDs.');
        }

        $ownerId = (int) $owner['id'];

        foreach ($this->repo()->typeIdsOfOwner($ownerId) as $typeId) {
            $this->repo()->unlinkOwnerType($ownerId, $typeId);
        }

        foreach ($body as $rawId) {
            $error = $this->linkType($ownerId, $rawId, (string) $owner['entity_id']);
            if ($error !== null) {
                return $this->badRequest($error);
            }
        }

        Logger::info(sprintf('oidanchor: API trust mark owner types set: %s', (string) $owner['entity_id']));

        return $this->json($this->typesOf($ownerId));
    }


    /**
     * POST — associate one more type with the owner (text/plain or JSON InternalID).
     */
    public function addType(Request $request, string $ownerID): JsonResponse
    {
        $this->requireAdmin();

        $owner = $this->find($ownerID);
        if ($owner === null) {
            return $this->ownerNotFound($ownerID);
        }

        $raw = trim($this->bodyString($request), " \t\n\r\0\x0B\"");
        if ($raw === '') {
            return $this->badRequest('Body must contain the trust mark type ID.');
        }

        $error = $this->linkType((int) $owner['id'], $raw, (string) $owner['entity_id']);
        if ($error !== null) {
            return $this->badRequest($error);
        }

        Logger::info(sprintf('oidanchor: API trust mark owner type added: %s', (string) $owner['entity_id']));

        return $this->json($this->typesOf((int) $owner['id']), JsonResponse::HTTP_CREATED);
    }


    public function unlinkType(Request $request, string $ownerID, string $trustMarkTypeID): Response
    {
        $this->requireAdmin();

        $owner  = $this->find($ownerID);
        $typeId = $this->internalId($trustMarkTypeID);

        if ($owner !== null && $typeId !== null) {
            $this->repo()->unlinkOwnerType((int) $owner['id'], $typeId);
            Logger::info(sprintf('oidanchor: API trust mark owner type unlinked: %s', (string) $owner['entity_id']));
        }

        // The spec declares only 204 for this operation.
        return $this->noContent();
    }


    // -------------------------------------------------------------------------

    /**
     * Link a type to an owner, minting a delegation JWT when this TA is the owner.
     * Returns an error message, or null on success.
     */
    private function linkType(int $ownerId, mixed $rawTypeId, string $ownerEntityId): ?string
    {
        $typeId = is_int($rawTypeId) ? $rawTypeId : $this->internalId((string) $rawTypeId);
        $type   = $typeId !== null ? $this->typeRepo()->findByInternalId($typeId) : null;

        if ($type === null || $typeId === null) {
            return sprintf('Unknown trust mark type ID "%s".', (string) $rawTypeId);
        }

        $delegation = null;
        try {
            $delegation = (new TrustMarkDelegationService($this->moduleConfig(), $this->buildPdo()))
                ->mintIfOwnedByThisAnchor($type->trustMarkId, $ownerEntityId);
        } catch (Throwable $e) {
            Logger::warning('oidanchor: could not mint trust mark delegation: ' . $e->getMessage());
        }

        $this->repo()->setOwnerOfType($typeId, $ownerId, $delegation);

        return null;
    }


    /**
     * @return list<array<string,mixed>>
     */
    private function typesOf(int $ownerId): array
    {
        $repo  = $this->typeRepo();
        $types = [];

        foreach ($this->repo()->typeIdsOfOwner($ownerId) as $typeId) {
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
    private function find(string $ownerID): ?array
    {
        $id = $this->internalId($ownerID);

        return $id !== null ? $this->repo()->findById($id) : null;
    }


    private function ownerNotFound(string $ownerID): JsonResponse
    {
        return $this->notFound(sprintf('Trust mark owner "%s" not found.', $ownerID));
    }


    private function repo(): TrustMarkOwnerRepository
    {
        return new TrustMarkOwnerRepository($this->buildPdo());
    }


    private function typeRepo(): TrustMarkTypeRepository
    {
        return new TrustMarkTypeRepository($this->buildPdo());
    }
}
