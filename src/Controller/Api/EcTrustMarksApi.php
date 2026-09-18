<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * REST API for the trust marks the TA holds and publishes in its own entity configuration.
 *
 * A trust mark is configured in one of three ways (spec AddTrustMark):
 *  1. trust_mark_type + trust_mark_issuer — fetched from the issuer (optionally refreshed),
 *  2. trust_mark — a JWT supplied directly,
 *  3. self_issuance_spec — the TA issues the mark to itself (always refreshed).
 *
 * @see \SimpleSAML\Module\oidanchor\Service\EcTrustMarkService for materialisation into the claim.
 */
class EcTrustMarksApi extends ApiController
{
    public function list(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json(array_map(
            static fn(array $row): array => self::toApi($row),
            $this->repo()->findAll(),
        ));
    }


    public function create(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        if (($err = $this->validate($body)) !== null) {
            return $this->badRequest($err);
        }

        $type = isset($body['trust_mark_type']) ? (string) $body['trust_mark_type'] : null;
        if ($type !== null && $this->repo()->typeExists($type)) {
            return $this->conflict(sprintf('A trust mark of type "%s" is already configured.', $type));
        }

        $id = $this->repo()->create($this->normalize($body));
        Logger::info(sprintf('oidanchor: API entity configuration trust mark created: %s', $type ?? 'jwt'));

        return $this->json(self::toApi($this->repo()->findById($id)), JsonResponse::HTTP_CREATED);
    }


    public function get(Request $request, string $trustMarkID): JsonResponse
    {
        $this->requireAdmin();

        $row = $this->find($trustMarkID);
        if ($row === null) {
            return $this->notFound(sprintf('Trust mark "%s" not found.', $trustMarkID));
        }

        return $this->json(self::toApi($row));
    }


    /**
     * PUT — replace the whole entry.
     */
    public function replace(Request $request, string $trustMarkID): JsonResponse
    {
        $this->requireAdmin();

        $row = $this->find($trustMarkID);
        if ($row === null) {
            return $this->notFound(sprintf('Trust mark "%s" not found.', $trustMarkID));
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        if (($err = $this->validate($body)) !== null) {
            return $this->badRequest($err);
        }

        // Replace semantics: unset members return to their defaults.
        $fields = $this->normalize($body) + [
            'trust_mark_type'      => null,
            'trust_mark_issuer'    => null,
            'trust_mark'           => null,
            'refresh'              => false,
            'min_lifetime'         => null,
            'refresh_grace_period' => null,
            'refresh_rate_limit'   => null,
            'self_issuance_spec'   => null,
            'last_refresh_at'      => null,
        ];

        $this->repo()->update($row['id'], $fields);
        Logger::info(sprintf('oidanchor: API entity configuration trust mark replaced: %d', $row['id']));

        return $this->json(self::toApi($this->repo()->findById($row['id'])));
    }


    /**
     * PATCH — merge the supplied members.
     */
    public function patch(Request $request, string $trustMarkID): JsonResponse
    {
        $this->requireAdmin();

        $row = $this->find($trustMarkID);
        if ($row === null) {
            return $this->notFound(sprintf('Trust mark "%s" not found.', $trustMarkID));
        }

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $fields = $this->normalize($body);
        if ($fields === []) {
            return $this->badRequest('No updatable members supplied.');
        }

        // A new JWT or self-issuance spec invalidates the refresh bookkeeping.
        if (array_key_exists('trust_mark', $fields) || array_key_exists('self_issuance_spec', $fields)) {
            $fields['last_refresh_at'] = null;
        }

        $this->repo()->update($row['id'], $fields);
        Logger::info(sprintf('oidanchor: API entity configuration trust mark patched: %d', $row['id']));

        return $this->json(self::toApi($this->repo()->findById($row['id'])));
    }


    public function delete(Request $request, string $trustMarkID): Response
    {
        $this->requireAdmin();

        $row = $this->find($trustMarkID);
        if ($row === null) {
            return $this->notFound(sprintf('Trust mark "%s" not found.', $trustMarkID));
        }

        $this->repo()->delete($row['id']);
        Logger::info(sprintf('oidanchor: API entity configuration trust mark deleted: %d', $row['id']));

        return $this->noContent();
    }


    // -------------------------------------------------------------------------

    /**
     * @param array<string,mixed> $body
     */
    private function validate(array $body): ?string
    {
        $hasType = isset($body['trust_mark_type']) && is_string($body['trust_mark_type']) && trim($body['trust_mark_type']) !== '';
        $hasJwt  = isset($body['trust_mark']) && is_string($body['trust_mark']) && trim($body['trust_mark']) !== '';
        $hasSelf = isset($body['self_issuance_spec']) && is_array($body['self_issuance_spec']);
        $hasIss  = isset($body['trust_mark_issuer']) && is_string($body['trust_mark_issuer']) && trim($body['trust_mark_issuer']) !== '';

        if ($hasSelf) {
            return $hasType ? null : 'self_issuance_spec requires trust_mark_type.';
        }
        if ($hasJwt) {
            return null;
        }
        if ($hasType && $hasIss) {
            return null;
        }

        return 'Provide either trust_mark_type + trust_mark_issuer, or trust_mark (JWT), or self_issuance_spec with trust_mark_type.';
    }


    /**
     * @param array<string,mixed> $body
     * @return array<string,mixed>
     */
    private function normalize(array $body): array
    {
        $fields = [];

        foreach (['trust_mark_type', 'trust_mark_issuer', 'trust_mark'] as $field) {
            if (array_key_exists($field, $body)) {
                $value = $body[$field];
                $fields[$field] = is_string($value) && trim($value) !== '' ? trim($value) : null;
            }
        }

        if (array_key_exists('refresh', $body)) {
            $fields['refresh'] = (bool) $body['refresh'];
        }

        foreach (['min_lifetime', 'refresh_grace_period', 'refresh_rate_limit'] as $field) {
            if (array_key_exists($field, $body)) {
                $fields[$field] = is_int($body[$field]) && $body[$field] >= 0 ? $body[$field] : null;
            }
        }

        if (array_key_exists('self_issuance_spec', $body)) {
            $fields['self_issuance_spec'] = is_array($body['self_issuance_spec']) ? $body['self_issuance_spec'] : null;
        }

        return $fields;
    }


    /**
     * @return array<string,mixed>|null
     */
    private function find(string $trustMarkID): ?array
    {
        $id = $this->internalId($trustMarkID);

        return $id !== null ? $this->repo()->findById($id) : null;
    }


    /**
     * The spec's TrustMark shape: null members are omitted.
     *
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    private static function toApi(array $row): array
    {
        $out = ['id' => $row['id']];

        foreach (['trust_mark_type', 'trust_mark_issuer', 'trust_mark', 'min_lifetime',
                  'refresh_grace_period', 'refresh_rate_limit', 'self_issuance_spec'] as $field) {
            if (($row[$field] ?? null) !== null) {
                $out[$field] = $row[$field];
            }
        }

        $out['refresh'] = (bool) $row['refresh'];

        return $out;
    }


    private function repo(): EcTrustMarkRepository
    {
        return new EcTrustMarkRepository($this->buildPdo());
    }
}
