<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\Module\oidanchor\Service\SubordinateStatementService;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * REST API for subordinates, backed by the existing SubordinateService / SubordinateRepository.
 *
 * The spec's InternalID {subordinateID} is this module's entity_id (our subordinates are keyed by
 * entity_id), so {subordinateID} is the URL-encoded entity_id. registered_entity_types maps to the
 * single stored entity_type ([entity_type]).
 */
class SubordinatesApi extends ApiController
{
    private const STATUSES = ['active', 'blocked', 'pending', 'inactive'];


    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $entityType = trim((string) $request->query->get('entity_type', '')) ?: null;
        $status     = trim((string) $request->query->get('status', '')) ?: null;

        $subordinates = $this->service()->findAll();

        $result = [];
        foreach ($subordinates as $sub) {
            if ($entityType !== null && $sub->entityType !== $entityType) {
                continue;
            }
            if ($status !== null && $sub->status !== $status) {
                continue;
            }
            $result[] = $this->summary($sub);
        }

        return $this->json($result);
    }


    public function create(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Request body must be a JSON object.');
        }

        $entityId = trim((string) ($body['entity_id'] ?? ''));
        if ($entityId === '' || !$this->isHttpsUrl($entityId)) {
            return $this->badRequest('entity_id is required and must be an HTTPS URL.');
        }

        $status = (string) ($body['status'] ?? 'active');
        if (!in_array($status, self::STATUSES, true)) {
            return $this->badRequest('status must be one of: ' . implode(', ', self::STATUSES) . '.');
        }

        $jwks = $body['jwks'] ?? null;
        if ($status === 'active' && !$this->jwksHasKeys($jwks)) {
            return $this->badRequest('status "active" requires a jwks with at least one key.');
        }

        $service = $this->service();
        if ($service->exists($entityId)) {
            return $this->conflict(sprintf('A subordinate with entity_id "%s" already exists.', $entityId));
        }

        $registeredTypes = $this->normalizeEntityTypes($body['registered_entity_types'] ?? null);

        $sub = $service->create([
            'entity_id'   => $entityId,
            'entity_type' => $registeredTypes[0] ?? null,
            'status'      => $status,
            'description' => $body['description'] ?? null,
            'jwks'        => $jwks !== null ? json_encode($jwks, JSON_UNESCAPED_SLASHES) : null,
        ]);

        Logger::info(sprintf('oidanchor: API subordinate created: %s', $entityId));

        return $this->json($this->summary($sub), JsonResponse::HTTP_CREATED);
    }


    public function get(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->service()->findSubordinate($subordinateID);
        if ($sub === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        return $this->json($this->details($sub));
    }


    public function update(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $service = $this->service();
        $sub     = $service->findSubordinate($subordinateID);
        if ($sub === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Request body must be a JSON object.');
        }

        $fields = [];
        if (array_key_exists('description', $body)) {
            $fields['description'] = $body['description'];
        }
        if (array_key_exists('registered_entity_types', $body)) {
            $types = $this->normalizeEntityTypes($body['registered_entity_types']);
            $fields['entity_type'] = $types[0] ?? null;
        }

        $service->update($subordinateID, $fields);

        Logger::info(sprintf('oidanchor: API subordinate updated: %s', $subordinateID));

        return $this->json($this->details($service->findSubordinate($subordinateID)));
    }


    public function delete(Request $request, string $subordinateID): Response
    {
        $this->requireAdmin();

        $service = $this->service();
        if ($service->findSubordinate($subordinateID) === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        $service->delete($subordinateID);
        Logger::info(sprintf('oidanchor: API subordinate deleted: %s', $subordinateID));

        return new Response('', Response::HTTP_NO_CONTENT);
    }


    public function changeStatus(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $service = $this->service();
        $sub     = $service->findSubordinate($subordinateID);
        if ($sub === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        $status = $this->bodyString($request);
        if (!in_array($status, self::STATUSES, true)) {
            return $this->badRequest('status must be one of: ' . implode(', ', self::STATUSES) . '.');
        }

        if ($status === 'active' && !$this->jwksHasKeys($sub->jwks)) {
            return $this->badRequest('Cannot set status "active": the subordinate has no keys in its JWKS.');
        }

        $service->setStatus($subordinateID, $status);
        Logger::info(sprintf('oidanchor: API subordinate status changed: %s -> %s', $subordinateID, $status));

        return $this->json($this->summary($service->findSubordinate($subordinateID)));
    }


    public function getJwks(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->service()->findSubordinate($subordinateID);
        if ($sub === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        return $this->json($sub->jwks ?? ['keys' => []]);
    }


    public function setJwks(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $service = $this->service();
        if ($service->findSubordinate($subordinateID) === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        $body = $this->decodeJson($request);
        if (!$this->jwksHasKeys($body)) {
            return $this->badRequest('Body must be a JWKS object with a non-empty "keys" array.');
        }

        $service->update($subordinateID, ['jwks' => json_encode($body, JSON_UNESCAPED_SLASHES)]);
        Logger::info(sprintf('oidanchor: API subordinate jwks replaced: %s', $subordinateID));

        return $this->json($body);
    }


    public function addJwk(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $service = $this->service();
        $sub     = $service->findSubordinate($subordinateID);
        if ($sub === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        $jwk = $this->decodeJson($request);
        if (!is_array($jwk) || !isset($jwk['kty'])) {
            return $this->badRequest('Body must be a single JWK object (with at least a "kty").');
        }

        $jwks = is_array($sub->jwks) && isset($sub->jwks['keys']) && is_array($sub->jwks['keys'])
            ? $sub->jwks
            : ['keys' => []];
        $jwks['keys'][] = $jwk;

        $service->update($subordinateID, ['jwks' => json_encode($jwks, JSON_UNESCAPED_SLASHES)]);
        Logger::info(sprintf('oidanchor: API subordinate jwk added: %s', $subordinateID));

        return $this->json($jwks, JsonResponse::HTTP_CREATED);
    }


    public function statement(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->service()->findSubordinate($subordinateID);
        if ($sub === null) {
            return $this->notFound(sprintf('Subordinate "%s" not found.', $subordinateID));
        }

        if (!$this->jwksHasKeys($sub->jwks)) {
            return $this->notFound(sprintf('Subordinate "%s" has no JWKS; no statement can be built.', $subordinateID));
        }

        try {
            $claims = (new SubordinateStatementService())->buildClaims($sub, $this->moduleConfig(), $this->buildPdo());
        } catch (MetadataPolicyException $e) {
            return $this->error(
                'server_error',
                'Incompatible metadata policies for this subordinate: ' . $e->getMessage(),
                JsonResponse::HTTP_INTERNAL_SERVER_ERROR,
            );
        } catch (Throwable $e) {
            return $this->error('server_error', 'Could not build statement: ' . $e->getMessage(), 500);
        }

        return $this->json($claims);
    }


    // -------------------------------------------------------------------------

    private function service(): SubordinateService
    {
        return new SubordinateService(new SubordinateRepository($this->buildPdo()));
    }


    /**
     * @return array<string,mixed>
     */
    private function summary(Subordinate $sub): array
    {
        $data = [
            'id'                      => $sub->entityId,
            'entity_id'               => $sub->entityId,
            'status'                  => $sub->status,
            'registered_entity_types' => $sub->entityType !== null ? [$sub->entityType] : [],
        ];

        if ($sub->description !== null) {
            $data['description'] = $sub->description;
        }

        return $data;
    }


    /**
     * @return array<string,mixed>
     */
    private function details(Subordinate $sub): array
    {
        $data = $this->summary($sub);
        $data['jwks'] = $sub->jwks ?? ['keys' => []];

        if ($sub->metadataPolicy !== null) {
            $data['metadata_policy'] = $sub->metadataPolicy;
        }
        if ($sub->extraClaims !== null) {
            $data['additional_claims'] = $sub->extraClaims;
        }

        return $data;
    }


    /**
     * @return list<string>
     */
    private function normalizeEntityTypes(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }

        return array_values(array_filter(
            array_map(static fn($v): string => is_string($v) ? trim($v) : '', $value),
            static fn(string $v): bool => $v !== '',
        ));
    }


    private function jwksHasKeys(mixed $jwks): bool
    {
        return is_array($jwks)
            && isset($jwks['keys'])
            && is_array($jwks['keys'])
            && $jwks['keys'] !== [];
    }


    private function isHttpsUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
    }
}
