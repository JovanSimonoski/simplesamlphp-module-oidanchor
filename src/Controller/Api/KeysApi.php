<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use InvalidArgumentException;
use SimpleSAML\Module\oidanchor\Entity\FederationKey;
use SimpleSAML\Module\oidanchor\Service\KeyManagementService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

/**
 * REST API for the TA's keys and the KMS: published JWKS, API-managed public key CRUD and
 * rotation, key revocation, signing-algorithm and RSA-key-length configuration, rotation
 * options and manual KMS rotation. Backed by KeyManagementService (DB-backed key store).
 */
class KeysApi extends ApiController
{
    /**
     * GET /entity-configuration/jwks — the published JWKS (as in the entity configuration).
     */
    public function publishedJwks(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->kms()->publicJwks());
    }


    /**
     * GET /entity-configuration/keys — every managed key with its lifecycle state.
     */
    public function listKeys(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json(array_map(
            static fn(FederationKey $key): array => $key->toPublicKeyEntry(),
            $this->kms()->listKeys(),
        ));
    }


    /**
     * POST /entity-configuration/keys — add a new public key (AddPublicKeyEntry).
     */
    public function addKey(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body) || !isset($body['key']) || !is_array($body['key'])) {
            return $this->badRequest('Body must be a JSON object with a "key" JWK member.');
        }

        try {
            $key = $this->kms()->addPublicKey(
                $body['key'],
                $this->optionalTimestamp($body, 'iat'),
                $this->optionalTimestamp($body, 'nbf'),
                $this->optionalTimestamp($body, 'exp'),
            );
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        } catch (Throwable $e) {
            return $this->serverError('Could not add key: ' . $e->getMessage());
        }

        return $this->json($key->toPublicKeyEntry(), JsonResponse::HTTP_CREATED);
    }


    /**
     * PUT /entity-configuration/keys/{kid} — update editable key metadata (nbf / exp).
     */
    public function updateKeyMetadata(Request $request, string $kid): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object.');
        }

        $setNbf = array_key_exists('nbf', $body);
        $setExp = array_key_exists('exp', $body);

        $nbf = $setNbf ? $this->optionalTimestamp($body, 'nbf') : null;
        $exp = $setExp ? $this->optionalTimestamp($body, 'exp') : null;

        if (($setNbf && $nbf === null && $body['nbf'] !== null)
            || ($setExp && $exp === null && $body['exp'] !== null)
        ) {
            return $this->badRequest('nbf and exp must be unix timestamps (or null).');
        }

        $key = $this->kms()->updateKeyValidity($kid, $nbf, $exp, $setNbf, $setExp);
        if ($key === null) {
            return $this->notFound(sprintf('Key "%s" not found.', $kid));
        }

        return $this->json($key->toPublicKeyEntry());
    }


    /**
     * POST /entity-configuration/keys/{kid} — rotate: insert the supplied replacement key and
     * mark this key expired (feeds the historical-keys state).
     */
    public function rotateKey(Request $request, string $kid): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body) || !isset($body['key']) || !is_array($body['key'])) {
            return $this->badRequest('Body must be a JSON object with a "key" JWK member.');
        }

        try {
            $key = $this->kms()->rotateKey(
                $kid,
                $body['key'],
                $this->optionalTimestamp($body, 'iat'),
                $this->optionalTimestamp($body, 'nbf'),
                $this->optionalTimestamp($body, 'exp'),
                $this->optionalTimestamp($body, 'old_key_exp'),
            );
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        } catch (Throwable $e) {
            return $this->serverError('Could not rotate key: ' . $e->getMessage());
        }

        if ($key === null) {
            return $this->notFound(sprintf('Key "%s" not found.', $kid));
        }

        return $this->json($key->toPublicKeyEntry(), JsonResponse::HTTP_CREATED);
    }


    /**
     * DELETE /entity-configuration/keys/{kid}?revoke=true&reason=... — revoke or hard-delete.
     */
    public function deleteKey(Request $request, string $kid): Response
    {
        $this->requireAdmin();

        $revoke = filter_var($request->query->get('revoke', 'false'), FILTER_VALIDATE_BOOLEAN);
        $reason = trim((string) $request->query->get('reason', '')) ?: null;

        try {
            $found = $this->kms()->deleteKey($kid, $revoke, $reason);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        } catch (Throwable $e) {
            return $this->serverError('Could not delete key: ' . $e->getMessage());
        }

        if (!$found) {
            return $this->notFound(sprintf('Key "%s" not found.', $kid));
        }

        return $this->noContent();
    }


    /**
     * GET /kms — active KMS, signing algorithm, RSA key length and rotation options.
     */
    public function kmsInfo(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->kms()->kmsInfo());
    }


    /**
     * PUT /kms/alg — switch the signing algorithm (text/plain body, JOSE alg name).
     */
    public function updateAlg(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $alg = trim($this->bodyString($request), " \t\n\r\0\x0B\"");
        if ($alg === '') {
            return $this->badRequest('Request body must contain the signature algorithm.');
        }

        try {
            $this->kms()->setAlgorithm($alg);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        } catch (Throwable $e) {
            return $this->serverError('Could not switch algorithm: ' . $e->getMessage());
        }

        return $this->json($this->kms()->kmsInfo());
    }


    /**
     * PUT /kms/rsa-key-len — set the length of newly generated RSA keys (text/plain body).
     */
    public function updateRsaKeyLen(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $raw = trim($this->bodyString($request));
        if ($raw === '' || !ctype_digit($raw)) {
            return $this->badRequest('Request body must contain the RSA key length in bits.');
        }

        try {
            $this->kms()->setRsaKeyLen((int) $raw);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        return $this->json($this->kms()->kmsInfo());
    }


    /**
     * GET /kms/rotation — rotation options.
     */
    public function getRotationOptions(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->kms()->rotationOptions());
    }


    /**
     * PUT /kms/rotation — replace rotation options.
     */
    public function putRotationOptions(Request $request): JsonResponse
    {
        return $this->writeRotationOptions($request, merge: false);
    }


    /**
     * PATCH /kms/rotation — merge rotation options.
     */
    public function patchRotationOptions(Request $request): JsonResponse
    {
        return $this->writeRotationOptions($request, merge: true);
    }


    /**
     * POST /kms/rotate?revoke=&reason= — rotate the signing key now (202).
     */
    public function triggerRotation(Request $request): Response
    {
        $this->requireAdmin();

        $revoke = filter_var($request->query->get('revoke', 'false'), FILTER_VALIDATE_BOOLEAN);
        $reason = trim((string) $request->query->get('reason', '')) ?: null;

        try {
            $this->kms()->triggerRotation($revoke, $reason);
        } catch (Throwable $e) {
            return $this->serverError('Rotation failed: ' . $e->getMessage());
        }

        return new Response('', Response::HTTP_ACCEPTED);
    }


    // -------------------------------------------------------------------------

    private function writeRotationOptions(Request $request, bool $merge): JsonResponse
    {
        $this->requireAdmin();

        $body = $this->decodeJson($request);
        if (!is_array($body)) {
            return $this->badRequest('Body must be a JSON object with rotation options.');
        }

        try {
            $options = $this->kms()->setRotationOptions($body, $merge);
        } catch (InvalidArgumentException $e) {
            return $this->badRequest($e->getMessage());
        }

        return $this->json($options);
    }


    /**
     * @param array<string,mixed> $body
     */
    private function optionalTimestamp(array $body, string $key): ?int
    {
        $value = $body[$key] ?? null;

        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && ctype_digit($value)) {
            return (int) $value;
        }
        if (is_float($value)) {
            return (int) $value;
        }

        return null;
    }


    private function kms(): KeyManagementService
    {
        return new KeyManagementService($this->moduleConfig(), $this->buildPdo());
    }
}
