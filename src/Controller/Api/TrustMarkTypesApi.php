<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkIssuerRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkOwnerRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\Module\oidanchor\Service\TrustMarkDelegationService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * REST API for federation trust mark types and their issuer / owner associations.
 *
 * {trustMarkTypeID} is the spec's InternalID — the surrogate id on oidanchor_trust_mark_types.
 * The type ↔ issuer links and the type's owner (with its delegation JWT) drive the
 * `trust_mark_issuers` and `trust_mark_owners` claims of the TA's entity configuration.
 */
class TrustMarkTypesApi extends ApiController
{
    // ---- types -------------------------------------------------------------

    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json(array_map(
            static fn(TrustMarkType $type): array => $type->toApi(),
            $this->typeRepo()->findAll(),
        ));
    }


    public function create(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $trustMarkType = trim((string) ($body['trust_mark_type'] ?? ''));
        if ($trustMarkType === '' || !$this->isHttpsUrl($trustMarkType)) {
            return $this->badRequest('trust_mark_type is required and must be an HTTPS URL.');
        }

        $typeRepo = $this->typeRepo();
        if ($typeRepo->exists($trustMarkType)) {
            return $this->conflict(sprintf('Trust mark type "%s" already exists.', $trustMarkType));
        }

        $id = $typeRepo->create(new TrustMarkType(
            trustMarkId:     $trustMarkType,
            name:            $trustMarkType,
            description:     isset($body['description']) ? (string) $body['description'] : null,
            logoUri:         null,
            refUri:          null,
            defaultLifetime: null,
            extraClaims:     null,
            createdAt:       time(),
            updatedAt:       null,
        ));

        // Optional inline associations (spec AddTrustMarkType).
        foreach ((array) ($body['trust_mark_issuers'] ?? []) as $issuer) {
            if (is_array($issuer)) {
                try {
                    $this->resolveOrCreateIssuer($issuer, $id);
                } catch (InvalidArgumentException $e) {
                    return $this->badRequest($e->getMessage());
                }
            }
        }

        if (isset($body['trust_mark_owner']) && is_array($body['trust_mark_owner'])) {
            try {
                $this->resolveOrCreateOwner($body['trust_mark_owner'], $id);
            } catch (InvalidArgumentException $e) {
                return $this->badRequest($e->getMessage());
            }
        }

        Logger::info(sprintf('oidanchor: API trust mark type created: %s', $trustMarkType));

        return $this->json($typeRepo->findByInternalId($id)?->toApi(), JsonResponse::HTTP_CREATED);
    }


    public function get(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        return $this->json($type->toApi());
    }


    public function update(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $description = array_key_exists('description', $body)
            ? (string) $body['description']
            : $type->description;

        $updated = new TrustMarkType(
            trustMarkId:     $type->trustMarkId,
            name:            $type->name,
            description:     $description,
            logoUri:         $type->logoUri,
            refUri:          $type->refUri,
            defaultLifetime: $type->defaultLifetime,
            extraClaims:     $type->extraClaims,
            createdAt:       $type->createdAt,
            updatedAt:       time(),
            id:              $type->id,
        );
        $this->typeRepo()->update($type->trustMarkId, $updated);

        Logger::info(sprintf('oidanchor: API trust mark type updated: %s', $type->trustMarkId));

        return $this->json($updated->toApi());
    }


    public function delete(Request $request, string $trustMarkTypeID): Response
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        $this->issuerRepo()->unlinkAllOfType($type->id);
        $this->ownerRepo()->unsetOwnerOfType($type->id);
        $this->typeRepo()->delete($type->trustMarkId);

        Logger::info(sprintf('oidanchor: API trust mark type deleted: %s', $type->trustMarkId));

        return $this->noContent();
    }


    // ---- type → issuers -----------------------------------------------------

    public function listIssuers(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        return $this->json($this->issuerRepo()->issuersOfType($type->id));
    }


    /**
     * PUT — replace the type's issuer list.
     */
    public function setIssuers(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body) || !array_is_list($body)) {
            return $this->badRequest('Body must be a JSON array of issuers.');
        }

        $this->issuerRepo()->unlinkAllOfType($type->id);

        foreach ($body as $issuer) {
            if (!is_array($issuer)) {
                return $this->badRequest('Each issuer entry must be a JSON object.');
            }
            try {
                $this->resolveOrCreateIssuer($issuer, $type->id);
            } catch (InvalidArgumentException $e) {
                return $this->badRequest($e->getMessage());
            }
        }

        Logger::info(sprintf('oidanchor: API trust mark type issuers set: %s', $type->trustMarkId));

        return $this->json($this->issuerRepo()->issuersOfType($type->id));
    }


    /**
     * POST — add one issuer (linking an existing one or creating a new one).
     */
    public function addIssuer(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        try {
            $this->resolveOrCreateIssuer($body, $type->id);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API trust mark type issuer added: %s', $type->trustMarkId));

        return $this->json($this->issuerRepo()->issuersOfType($type->id), JsonResponse::HTTP_CREATED);
    }


    public function deleteIssuer(Request $request, string $trustMarkTypeID, string $issuerID): JsonResponse
    {
        $this->requireAdmin();

        $type     = $this->findType($trustMarkTypeID);
        $issuerId = $this->internalId($issuerID);

        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }
        if ($issuerId === null || $this->issuerRepo()->findById($issuerId) === null) {
            return $this->notFound(sprintf('Trust mark issuer "%s" not found.', $issuerID));
        }

        $this->issuerRepo()->unlink($type->id, $issuerId);
        Logger::info(sprintf('oidanchor: API trust mark type issuer removed: %s', $type->trustMarkId));

        return $this->json($this->issuerRepo()->issuersOfType($type->id));
    }


    // ---- type → owner -------------------------------------------------------

    public function getOwner(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        $owner = $this->ownerRepo()->findOwnerOfType($type->id);
        if ($owner === null) {
            return $this->notFound(sprintf('Trust mark type "%s" has no owner.', $trustMarkTypeID));
        }

        return $this->json($owner);
    }


    /**
     * POST — create or link the type's owner (spec AddTrustMarkOwner: owner_id, or entity_id + jwks).
     */
    public function createOwner(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        try {
            $this->resolveOrCreateOwner($body, $type->id);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API trust mark owner set for type: %s', $type->trustMarkId));

        return $this->json($this->ownerRepo()->findOwnerOfType($type->id), JsonResponse::HTTP_CREATED);
    }


    /**
     * PUT — replace the type's owner (spec AddTrustMarkOwnerCreate: entity_id + jwks).
     */
    public function updateOwner(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        $body = $this->decodeJson($request);
        if (!is_array($body) || !isset($body['entity_id'], $body['jwks'])) {
            return $this->badRequest('Body must contain entity_id and jwks.');
        }

        try {
            $this->resolveOrCreateOwner(
                ['entity_id' => $body['entity_id'], 'jwks' => $body['jwks'], 'description' => $body['description'] ?? null],
                $type->id,
            );
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API trust mark owner updated for type: %s', $type->trustMarkId));

        return $this->json($this->ownerRepo()->findOwnerOfType($type->id));
    }


    public function deleteOwner(Request $request, string $trustMarkTypeID): Response
    {
        $this->requireAdmin();

        $type = $this->findType($trustMarkTypeID);
        if ($type === null || $type->id === null) {
            return $this->typeNotFound($trustMarkTypeID);
        }

        if ($this->ownerRepo()->findOwnerOfType($type->id) === null) {
            return $this->notFound(sprintf('Trust mark type "%s" has no owner.', $trustMarkTypeID));
        }

        $this->ownerRepo()->unsetOwnerOfType($type->id);
        Logger::info(sprintf('oidanchor: API trust mark owner removed from type: %s', $type->trustMarkId));

        return $this->noContent();
    }


    // -------------------------------------------------------------------------

    /**
     * Link an existing issuer (issuer_id) or create one (issuer [+ description]).
     *
     * @param array<string,mixed> $data
     * @throws InvalidArgumentException
     */
    private function resolveOrCreateIssuer(array $data, int $typeId): void
    {
        $repo = $this->issuerRepo();

        if (isset($data['issuer_id'])) {
            $issuerId = is_int($data['issuer_id']) ? $data['issuer_id'] : $this->internalId((string) $data['issuer_id']);
            if ($issuerId === null || $repo->findById($issuerId) === null) {
                throw new InvalidArgumentException(sprintf('Unknown issuer_id "%s".', (string) $data['issuer_id']));
            }
            $repo->link($typeId, $issuerId);

            return;
        }

        $issuer = trim((string) ($data['issuer'] ?? ''));
        if ($issuer === '') {
            throw new InvalidArgumentException('Provide either issuer_id or issuer.');
        }

        $existing = $repo->findByIssuer($issuer);
        $issuerId = $existing !== null
            ? (int) $existing['id']
            : $repo->create($issuer, isset($data['description']) ? (string) $data['description'] : null);

        $repo->link($typeId, $issuerId);
    }


    /**
     * Link an existing owner (owner_id) or create one (entity_id + jwks). When the TA itself is
     * the owner, a delegation JWT is minted so it can be presented on issuance.
     *
     * @param array<string,mixed> $data
     * @throws InvalidArgumentException
     */
    private function resolveOrCreateOwner(array $data, int $typeId): void
    {
        $repo = $this->ownerRepo();

        if (isset($data['owner_id'])) {
            $ownerId = is_int($data['owner_id']) ? $data['owner_id'] : $this->internalId((string) $data['owner_id']);
            if ($ownerId === null || $repo->findById($ownerId) === null) {
                throw new InvalidArgumentException(sprintf('Unknown owner_id "%s".', (string) $data['owner_id']));
            }
        } else {
            $entityId = trim((string) ($data['entity_id'] ?? ''));
            $jwks     = $data['jwks'] ?? null;

            if ($entityId === '' || !$this->jwksHasKeys($jwks)) {
                throw new InvalidArgumentException('Provide either owner_id, or entity_id and a jwks with at least one key.');
            }

            $existing = $repo->findByEntityId($entityId);
            if ($existing !== null) {
                $ownerId = (int) $existing['id'];
                $repo->update($ownerId, $entityId, $jwks, isset($data['description']) ? (string) $data['description'] : null);
            } else {
                $ownerId = $repo->create($entityId, $jwks, isset($data['description']) ? (string) $data['description'] : null);
            }
        }

        $owner = $repo->findById($ownerId);
        $type  = $this->typeRepo()->findByInternalId($typeId);

        $delegation = null;
        if ($owner !== null && $type !== null) {
            try {
                $delegation = $this->delegationService()->mintIfOwnedByThisAnchor(
                    $type->trustMarkId,
                    (string) $owner['entity_id'],
                );
            } catch (Throwable $e) {
                // A delegation is optional: only the owner can sign one, and it may be supplied later.
                Logger::warning('oidanchor: could not mint trust mark delegation: ' . $e->getMessage());
            }
        }

        $repo->setOwnerOfType($typeId, $ownerId, $delegation);
    }


    private function findType(string $trustMarkTypeID): ?TrustMarkType
    {
        $id = $this->internalId($trustMarkTypeID);

        return $id !== null ? $this->typeRepo()->findByInternalId($id) : null;
    }


    private function typeNotFound(string $trustMarkTypeID): JsonResponse
    {
        return $this->notFound(sprintf('Trust mark type "%s" not found.', $trustMarkTypeID));
    }


    private function typeRepo(): TrustMarkTypeRepository
    {
        return new TrustMarkTypeRepository($this->buildPdo());
    }


    private function issuerRepo(): TrustMarkIssuerRepository
    {
        return new TrustMarkIssuerRepository($this->buildPdo());
    }


    private function ownerRepo(): TrustMarkOwnerRepository
    {
        return new TrustMarkOwnerRepository($this->buildPdo());
    }


    private function delegationService(): TrustMarkDelegationService
    {
        return new TrustMarkDelegationService($this->moduleConfig(), $this->buildPdo());
    }


    private function isHttpsUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
    }
}
