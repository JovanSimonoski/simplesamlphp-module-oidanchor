<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for federation trust mark types, backed by TrustMarkTypeRepository.
 *
 * {trustMarkTypeID} is the URL-encoded trust_mark_id (our catalog is keyed by the type URL).
 * The spec's issuer/owner sub-resources are out of scope (no backing service yet), so the
 * AddTrustMarkType.trust_mark_issuers / trust_mark_owner fields are accepted but ignored.
 */
class TrustMarkTypesApi extends ApiController
{
    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $out = array_map(fn(TrustMarkType $t): array => $this->toApi($t), $this->repo()->findAll());

        return $this->json($out);
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

        $repo = $this->repo();
        if ($repo->exists($trustMarkType)) {
            return $this->badRequest(sprintf('Trust mark type "%s" already exists.', $trustMarkType));
        }

        $type = new TrustMarkType(
            trustMarkId:     $trustMarkType,
            name:            $trustMarkType,
            description:     isset($body['description']) ? (string) $body['description'] : null,
            logoUri:         null,
            refUri:          null,
            defaultLifetime: null,
            extraClaims:     null,
            createdAt:       time(),
            updatedAt:       null,
        );
        $repo->create($type);

        Logger::info(sprintf('oidanchor: API trust mark type created: %s', $trustMarkType));

        return $this->json($this->toApi($type), JsonResponse::HTTP_CREATED);
    }


    public function get(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $type = $this->repo()->findById($trustMarkTypeID);
        if ($type === null) {
            return $this->notFound(sprintf('Trust mark type "%s" not found.', $trustMarkTypeID));
        }

        return $this->json($this->toApi($type));
    }


    public function update(Request $request, string $trustMarkTypeID): JsonResponse
    {
        $this->requireAdmin();

        $repo = $this->repo();
        $type = $repo->findById($trustMarkTypeID);
        if ($type === null) {
            return $this->notFound(sprintf('Trust mark type "%s" not found.', $trustMarkTypeID));
        }

        $body = $this->decodeJson($request);
        $description = is_array($body) && isset($body['description'])
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
        );
        $repo->update($type->trustMarkId, $updated);

        Logger::info(sprintf('oidanchor: API trust mark type updated: %s', $type->trustMarkId));

        return $this->json($this->toApi($updated));
    }


    public function delete(Request $request, string $trustMarkTypeID): Response
    {
        $this->requireAdmin();

        $repo = $this->repo();
        if ($repo->findById($trustMarkTypeID) === null) {
            return $this->notFound(sprintf('Trust mark type "%s" not found.', $trustMarkTypeID));
        }

        $repo->delete($trustMarkTypeID);
        Logger::info(sprintf('oidanchor: API trust mark type deleted: %s', $trustMarkTypeID));

        return new Response('', Response::HTTP_NO_CONTENT);
    }


    // -------------------------------------------------------------------------

    private function repo(): TrustMarkTypeRepository
    {
        return new TrustMarkTypeRepository($this->buildPdo());
    }


    /**
     * @return array<string,mixed>
     */
    private function toApi(TrustMarkType $type): array
    {
        $data = [
            'id'              => $type->trustMarkId,
            'trust_mark_type' => $type->trustMarkId,
        ];

        if ($type->description !== null) {
            $data['description'] = $type->description;
        }

        return $data;
    }


    private function isHttpsUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
    }
}
