<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\AdditionalClaimsRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateEventRepository;
use SimpleSAML\Module\oidanchor\Service\ConstraintsService;
use SimpleSAML\Module\oidanchor\Service\SubordinateStatementService;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * REST API for subordinates: CRUD, status, event history, the signed statement's claims,
 * the JWKS sub-resource, and additional claims (both the general defaults and per-subordinate).
 *
 * {subordinateID} is the spec's InternalID — the surrogate id on oidanchor_subordinates.
 */
class SubordinatesApi extends ApiController
{
    use AdditionalClaimsTrait;

    private const STATUSES = ['active', 'blocked', 'pending', 'inactive'];

    private const HISTORY_DEFAULT_LIMIT = 50;
    private const HISTORY_MAX_LIMIT = 100;


    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $entityType = trim((string) $request->query->get('entity_type', '')) ?: null;
        $status     = trim((string) $request->query->get('status', '')) ?: null;

        $result = [];
        foreach ($this->subordinateService()->findAll() as $sub) {
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

        $service = $this->subordinateService();
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

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->json($this->details($sub));
    }


    public function update(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
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

        $service = $this->subordinateService();
        $service->update($sub->entityId, $fields, 'updated', 'subordinate details updated');

        Logger::info(sprintf('oidanchor: API subordinate updated: %s', $sub->entityId));

        return $this->json($this->details($service->findSubordinate($sub->entityId)));
    }


    public function delete(Request $request, string $subordinateID): Response
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        if ($sub->id !== null) {
            (new AdditionalClaimsRepository($this->buildPdo()))->deleteForSubordinate($sub->id);
        }

        $this->subordinateService()->delete($sub->entityId);
        Logger::info(sprintf('oidanchor: API subordinate deleted: %s', $sub->entityId));

        return $this->noContent();
    }


    public function changeStatus(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $status = trim($this->bodyString($request), " \t\n\r\0\x0B\"");
        if (!in_array($status, self::STATUSES, true)) {
            return $this->badRequest('status must be one of: ' . implode(', ', self::STATUSES) . '.');
        }

        if ($status === 'active' && !$this->jwksHasKeys($sub->jwks)) {
            return $this->badRequest('Cannot set status "active": the subordinate has no keys in its JWKS.');
        }

        $service = $this->subordinateService();
        $service->setStatus($sub->entityId, $status);
        Logger::info(sprintf('oidanchor: API subordinate status changed: %s -> %s', $sub->entityId, $status));

        return $this->json($this->summary($service->findSubordinate($sub->entityId)));
    }


    /**
     * GET /subordinates/{id}/history — the audit trail, newest first, paginated.
     */
    public function history(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null || $sub->id === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $limit = $this->intQuery($request, 'limit', self::HISTORY_DEFAULT_LIMIT);
        if ($limit < 1 || $limit > self::HISTORY_MAX_LIMIT) {
            return $this->badRequest(sprintf('limit must be between 1 and %d.', self::HISTORY_MAX_LIMIT));
        }

        $offset = $this->intQuery($request, 'offset', 0);
        if ($offset < 0) {
            return $this->badRequest('offset must be non-negative.');
        }

        $type = trim((string) $request->query->get('type', '')) ?: null;
        if ($type !== null && !in_array($type, SubordinateEventRepository::TYPES, true)) {
            return $this->badRequest('type must be one of: ' . implode(', ', SubordinateEventRepository::TYPES) . '.');
        }

        $from = $request->query->has('from') ? $this->intQuery($request, 'from', 0) : null;
        $to   = $request->query->has('to') ? $this->intQuery($request, 'to', 0) : null;

        $result = (new SubordinateEventRepository($this->buildPdo()))
            ->query($sub->id, $limit, $offset, $type, $from, $to);

        return $this->json([
            'events'     => $result['events'],
            'pagination' => ['total' => $result['total'], 'limit' => $limit, 'offset' => $offset],
        ]);
    }


    /**
     * GET /subordinates/{id}/statement — the claims of the statement /federation/fetch would sign.
     */
    public function statement(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        if (!$this->jwksHasKeys($sub->jwks)) {
            return $this->notFound(sprintf('Subordinate "%s" has no JWKS; no statement can be built.', $sub->entityId));
        }

        try {
            $claims = (new SubordinateStatementService())->buildClaims($sub, $this->moduleConfig(), $this->buildPdo());
        } catch (MetadataPolicyException $e) {
            return $this->serverError('Incompatible metadata policies for this subordinate: ' . $e->getMessage());
        } catch (Throwable $e) {
            return $this->serverError('Could not build statement: ' . $e->getMessage());
        }

        return $this->json($claims);
    }


    // ---- JWKS sub-resource --------------------------------------------------

    public function getJwks(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->json($sub->jwks ?? ['keys' => []]);
    }


    public function setJwks(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $body = $this->decodeJson($request);
        if (!$this->jwksHasKeys($body)) {
            return $this->badRequest('Body must be a JWKS object with a non-empty "keys" array.');
        }

        $this->subordinateService()->update(
            $sub->entityId,
            ['jwks' => json_encode($body, JSON_UNESCAPED_SLASHES)],
            'jwks_replaced',
            'JWKS replaced',
        );
        Logger::info(sprintf('oidanchor: API subordinate jwks replaced: %s', $sub->entityId));

        return $this->json($body);
    }


    public function addJwk(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $jwk = $this->decodeJson($request);
        if (!is_array($jwk) || !isset($jwk['kty'])) {
            return $this->badRequest('Body must be a single JWK object (with at least a "kty").');
        }

        /** @var array{keys: list<array<string,mixed>>} $jwks */
        $jwks = $this->jwksHasKeys($sub->jwks) ? $sub->jwks : ['keys' => []];
        $jwks['keys'][] = $jwk;

        $this->subordinateService()->update(
            $sub->entityId,
            ['jwks' => json_encode($jwks, JSON_UNESCAPED_SLASHES)],
            'jwk_added',
            sprintf('key added: %s', isset($jwk['kid']) ? (string) $jwk['kid'] : 'no kid'),
        );
        Logger::info(sprintf('oidanchor: API subordinate jwk added: %s', $sub->entityId));

        return $this->json($jwks, JsonResponse::HTTP_CREATED);
    }


    /**
     * DELETE /subordinates/{id}/jwks/{kid} — returns the remaining JWKS.
     */
    public function deleteJwk(Request $request, string $subordinateID, string $kid): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        /** @var array{keys: list<array<string,mixed>>} $jwks */
        $jwks = $this->jwksHasKeys($sub->jwks) ? $sub->jwks : ['keys' => []];

        $remaining = array_values(array_filter(
            $jwks['keys'],
            static fn(array $key): bool => ($key['kid'] ?? null) !== $kid,
        ));

        if (count($remaining) !== count($jwks['keys'])) {
            $jwks['keys'] = $remaining;
            $this->subordinateService()->update(
                $sub->entityId,
                ['jwks' => json_encode($jwks, JSON_UNESCAPED_SLASHES)],
                'jwk_removed',
                sprintf('key removed: %s', $kid),
            );
            Logger::info(sprintf('oidanchor: API subordinate jwk removed: %s (%s)', $sub->entityId, $kid));
        }

        return $this->json($jwks);
    }


    // ---- additional claims: general defaults ---------------------------------

    public function getGeneralAdditionalClaims(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimsIndex(AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL);
    }


    public function updateGeneralAdditionalClaims(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimsReplace($request, AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL);
    }


    public function addGeneralAdditionalClaim(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimsAdd($request, AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL);
    }


    public function getGeneralAdditionalClaim(Request $request, string $additionalClaimsID): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimGet(AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL, $additionalClaimsID);
    }


    public function updateGeneralAdditionalClaim(Request $request, string $additionalClaimsID): JsonResponse
    {
        $this->requireAdmin();

        return $this->additionalClaimUpdate(
            $request,
            AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL,
            $additionalClaimsID,
        );
    }


    public function deleteGeneralAdditionalClaim(Request $request, string $additionalClaimsID): Response
    {
        $this->requireAdmin();

        return $this->additionalClaimDelete(
            AdditionalClaimsRepository::SCOPE_SUBORDINATE_GENERAL,
            $additionalClaimsID,
        );
    }


    // ---- additional claims: per subordinate ----------------------------------

    public function getSubordinateAdditionalClaims(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null || $sub->id === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->additionalClaimsIndex(AdditionalClaimsRepository::SCOPE_SUBORDINATE, $sub->id);
    }


    public function updateSubordinateAdditionalClaims(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null || $sub->id === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $response = $this->additionalClaimsReplace($request, AdditionalClaimsRepository::SCOPE_SUBORDINATE, $sub->id);
        $this->recordClaimsEvent($response, $sub, 'claims_updated', 'additional claims replaced');

        return $response;
    }


    public function addSubordinateAdditionalClaims(Request $request, string $subordinateID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null || $sub->id === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $response = $this->additionalClaimsAdd($request, AdditionalClaimsRepository::SCOPE_SUBORDINATE, $sub->id);
        $this->recordClaimsEvent($response, $sub, 'claims_updated', 'additional claim added');

        return $response;
    }


    public function getSubordinateAdditionalClaim(Request $request, string $subordinateID, string $additionalClaimsID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null || $sub->id === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        return $this->additionalClaimGet(AdditionalClaimsRepository::SCOPE_SUBORDINATE, $additionalClaimsID, $sub->id);
    }


    public function updateSubordinateAdditionalClaim(Request $request, string $subordinateID, string $additionalClaimsID): JsonResponse
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null || $sub->id === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $response = $this->additionalClaimUpdate(
            $request,
            AdditionalClaimsRepository::SCOPE_SUBORDINATE,
            $additionalClaimsID,
            $sub->id,
        );
        $this->recordClaimsEvent($response, $sub, 'claims_updated', 'additional claim updated');

        return $response;
    }


    public function deleteSubordinateAdditionalClaim(Request $request, string $subordinateID, string $additionalClaimsID): Response
    {
        $this->requireAdmin();

        $sub = $this->resolveSubordinate($subordinateID);
        if ($sub === null || $sub->id === null) {
            return $this->subordinateNotFound($subordinateID);
        }

        $response = $this->additionalClaimDelete(
            AdditionalClaimsRepository::SCOPE_SUBORDINATE,
            $additionalClaimsID,
            $sub->id,
        );
        $this->recordClaimsEvent($response, $sub, 'claim_deleted', 'additional claim deleted');

        return $response;
    }


    // -------------------------------------------------------------------------

    /**
     * Spec Subordinate shape.
     *
     * @return array<string,mixed>
     */
    private function summary(Subordinate $sub): array
    {
        $data = [
            'id'                      => $sub->id,
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
     * Spec SubordinateDetails shape.
     *
     * @return array<string,mixed>
     */
    private function details(Subordinate $sub): array
    {
        $data = $this->summary($sub);
        $data['jwks'] = $sub->jwks ?? ['keys' => []];

        if ($sub->metadata !== null) {
            $data['metadata'] = $sub->metadata;
        }
        if ($sub->metadataPolicy !== null) {
            $data['metadata_policy'] = $sub->metadataPolicy;
        }

        $constraints = (new ConstraintsService($this->buildPdo()))->forSubordinate($sub);
        if ($constraints !== []) {
            $data['constraints'] = $constraints;
        }

        if ($sub->id !== null) {
            $claims = (new AdditionalClaimsRepository($this->buildPdo()))
                ->asMap(AdditionalClaimsRepository::SCOPE_SUBORDINATE, $sub->id);
            if ($claims !== []) {
                $data['additional_claims'] = $claims;
            }
        }

        return $data;
    }


    /**
     * Record an audit event only when the claim mutation actually succeeded.
     */
    private function recordClaimsEvent(Response $response, Subordinate $sub, string $type, string $message): void
    {
        if ($response->getStatusCode() >= 400) {
            return;
        }

        (new SubordinateEventRepository($this->buildPdo()))
            ->record($sub->id, $sub->entityId, $type, $sub->status, $message);
    }


    private function intQuery(Request $request, string $name, int $default): int
    {
        $raw = $request->query->get($name);

        return is_string($raw) && $raw !== '' && preg_match('/^-?\d+$/', $raw) === 1 ? (int) $raw : $default;
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


    private function isHttpsUrl(string $url): bool
    {
        $parsed = parse_url($url);

        return isset($parsed['scheme'], $parsed['host'])
            && $parsed['scheme'] === 'https'
            && $parsed['host'] !== '';
    }
}
