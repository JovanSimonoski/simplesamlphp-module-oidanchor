<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\AdditionalClaimsRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The AdditionalClaims sub-resource, identical in shape across the three scopes the spec
 * defines (entity configuration, general subordinate defaults, per subordinate). Controllers
 * bind a scope (and optionally a subordinate id) and inherit all six operations.
 *
 * @see AdditionalClaimsRepository
 */
trait AdditionalClaimsTrait
{
    /**
     * GET — the scope's claims as the spec's `AdditionalClaims`: a JSON array of `AdditionalClaim`
     * rows ({ id, claim, value, crit }). findAll() already returns exactly that shape, in
     * insertion order. (An empty scope serialises to `[]`.)
     */
    protected function additionalClaimsIndex(string $scope, ?int $subordinateId = null): JsonResponse
    {
        return $this->json($this->claimsRepo()->findAll($scope, $subordinateId));
    }


    /**
     * PUT — replace every claim row in the scope with the supplied AddAdditionalClaim array.
     */
    protected function additionalClaimsReplace(Request $request, string $scope, ?int $subordinateId = null): JsonResponse
    {
        $body = $this->decodeJson($request);
        if (!is_array($body) || !array_is_list($body)) {
            return $this->badRequest('Body must be a JSON array of additional claims.');
        }

        $claims = [];
        foreach ($body as $entry) {
            if (!is_array($entry) || !isset($entry['claim']) || !is_string($entry['claim']) || trim($entry['claim']) === '') {
                return $this->badRequest('Each entry must be an object with a non-empty "claim".');
            }
            if (!array_key_exists('value', $entry)) {
                return $this->badRequest(sprintf('Entry "%s" is missing "value".', $entry['claim']));
            }
            $claims[] = [
                'claim' => trim($entry['claim']),
                'value' => $entry['value'],
                'crit'  => (bool) ($entry['crit'] ?? false),
            ];
        }

        $names = array_column($claims, 'claim');
        if (count($names) !== count(array_unique($names))) {
            return $this->conflict('Duplicate claim names in the request body.');
        }

        $this->claimsRepo()->replaceAll($scope, $claims, $subordinateId);
        Logger::info(sprintf('oidanchor: API additional claims replaced (scope=%s)', $scope));

        return $this->additionalClaimsIndex($scope, $subordinateId);
    }


    /**
     * POST — add a single claim row (409 when the claim name is taken).
     */
    protected function additionalClaimsAdd(Request $request, string $scope, ?int $subordinateId = null): JsonResponse
    {
        $body = $this->decodeJson($request);
        if (!is_array($body) || !isset($body['claim']) || !is_string($body['claim']) || trim($body['claim']) === '') {
            return $this->badRequest('Body must be an object with a non-empty "claim".');
        }
        if (!array_key_exists('value', $body)) {
            return $this->badRequest('Body is missing "value".');
        }

        $claim = trim($body['claim']);
        $crit  = (bool) ($body['crit'] ?? false);

        try {
            $id = $this->claimsRepo()->create($scope, $claim, $body['value'], $crit, $subordinateId);
        } catch (InvalidArgumentException $e) {
            return $this->conflict($e->getMessage());
        }

        Logger::info(sprintf('oidanchor: API additional claim added: %s (scope=%s)', $claim, $scope));

        return $this->json(
            ['id' => $id, 'claim' => $claim, 'value' => $body['value'], 'crit' => $crit],
            JsonResponse::HTTP_CREATED,
        );
    }


    /**
     * GET {additionalClaimsID} — a single claim row.
     */
    protected function additionalClaimGet(string $scope, string $claimId, ?int $subordinateId = null): JsonResponse
    {
        $id  = $this->internalId($claimId);
        $row = $id !== null ? $this->claimsRepo()->findById($scope, $id, $subordinateId) : null;

        if ($row === null) {
            return $this->notFound(sprintf('Additional claim "%s" not found.', $claimId));
        }

        return $this->json($row);
    }


    /**
     * PUT {additionalClaimsID} — update a single claim row.
     */
    protected function additionalClaimUpdate(
        Request $request,
        string $scope,
        string $claimId,
        ?int $subordinateId = null,
    ): JsonResponse {
        $id  = $this->internalId($claimId);
        $row = $id !== null ? $this->claimsRepo()->findById($scope, $id, $subordinateId) : null;

        if ($row === null || $id === null) {
            return $this->notFound(sprintf('Additional claim "%s" not found.', $claimId));
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $claim = isset($body['claim']) && is_string($body['claim']) && trim($body['claim']) !== ''
            ? trim($body['claim'])
            : $row['claim'];
        $value = array_key_exists('value', $body) ? $body['value'] : $row['value'];
        $crit  = array_key_exists('crit', $body) ? (bool) $body['crit'] : $row['crit'];

        if ($claim !== $row['claim'] && $this->claimsRepo()->claimExists($scope, $claim, $subordinateId)) {
            return $this->conflict(sprintf('Claim "%s" already exists.', $claim));
        }

        $this->claimsRepo()->update($id, $claim, $value, $crit);
        Logger::info(sprintf('oidanchor: API additional claim updated: %s (scope=%s)', $claim, $scope));

        return $this->json(['id' => $id, 'claim' => $claim, 'value' => $value, 'crit' => $crit]);
    }


    /**
     * DELETE {additionalClaimsID} — remove a single claim row.
     */
    protected function additionalClaimDelete(string $scope, string $claimId, ?int $subordinateId = null): Response
    {
        $id  = $this->internalId($claimId);
        $row = $id !== null ? $this->claimsRepo()->findById($scope, $id, $subordinateId) : null;

        if ($row === null || $id === null) {
            return $this->notFound(sprintf('Additional claim "%s" not found.', $claimId));
        }

        $this->claimsRepo()->delete($id);
        Logger::info(sprintf('oidanchor: API additional claim deleted: %s (scope=%s)', $row['claim'], $scope));

        return $this->noContent();
    }


    private function claimsRepo(): AdditionalClaimsRepository
    {
        return new AdditionalClaimsRepository($this->buildPdo());
    }
}
