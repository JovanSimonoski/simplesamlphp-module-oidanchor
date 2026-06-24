<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller\Api;

use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Read-only REST API for keys, backed by the existing FederationKeyService (single signing key,
 * filesystem-managed). Mutation/rotation/KMS-management endpoints are intentionally out of scope
 * (no managed-key/KMS service exists yet).
 */
class KeysApi extends ApiController
{
    /**
     * GET /entity-configuration/jwks — the published JWKS (as in the entity configuration).
     */
    public function publishedJwks(Request $request): JsonResponse
    {
        $this->requireAdmin();

        return $this->json($this->keys()->publicJwks());
    }


    /**
     * GET /entity-configuration/keys — the API-managed public keys (currently the single signing key).
     */
    public function listKeys(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $keys = $this->keys();
        $jwks = $keys->publicJwks();
        $jwk  = $jwks['keys'][0] ?? null;

        if ($jwk === null) {
            return $this->json([]);
        }

        return $this->json([
            [
                'kid' => $keys->kid(),
                'key' => $jwk,
            ],
        ]);
    }


    /**
     * GET /kms — information about the active KMS and signing algorithm.
     */
    public function kmsInfo(Request $request): JsonResponse
    {
        $this->requireAdmin();

        $moduleConfig = $this->moduleConfig();

        return $this->json([
            'kms'         => 'filesystem',
            'alg'         => $this->keys()->algorithm()->value,
            'rsa_key_len' => $moduleConfig->getOptionalInteger('signing_rsa_key_len', 2048) ?? 2048,
            'rotation'    => ['enabled' => false],
        ]);
    }


    private function keys(): FederationKeyService
    {
        return new FederationKeyService($this->moduleConfig());
    }
}
