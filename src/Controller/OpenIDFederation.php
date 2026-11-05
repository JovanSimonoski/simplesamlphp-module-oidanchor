<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\EntityConfigurationService;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\Module\oidanchor\Service\SubordinateStatementService;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller for OpenID Federation endpoints.
 *
 * Claim assembly is delegated to EntityConfigurationService / SubordinateStatementService so the
 * signed wire output here and the read-only admin API stay in sync.
 */
class OpenIDFederation
{
    use JwtResponseTrait;


    public function __construct(
        protected Configuration $config,
    ) {
    }


    /**
     * Serve the Entity Configuration JWT at /.well-known/openid-federation.
     */
    public function entityConfiguration(Request $request): Response
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');
        $pdo          = PdoFactory::get($moduleConfig);
        $keys         = new FederationKeyService($moduleConfig, $pdo);

        $claims = (new EntityConfigurationService($keys))->buildClaims($moduleConfig, $pdo);

        $token = $keys->signEntityStatement($claims);

        return $this->jwtResponse($token, 'application/entity-statement+jwt');
    }


    /**
     * Serve the Subordinate Listing endpoint — returns entity IDs of active subordinates only.
     */
    public function subordinateList(Request $request): JsonResponse
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');

        // OpenID Federation 1.0 §8.2.1. `intermediate` is not supported: the TA does not know which
        // subordinates are intermediates, and the spec requires rejecting an unsupported parameter.
        if ($request->query->has('intermediate')) {
            return $this->federationError(
                'unsupported_parameter',
                'The intermediate parameter is not supported by this Trust Anchor.',
                Response::HTTP_BAD_REQUEST,
            );
        }

        $trustMarked = $request->query->get('trust_marked');
        if ($trustMarked !== null && !in_array($trustMarked, ['true', 'false'], true)) {
            return $this->federationError(
                'invalid_request',
                'trust_marked must be true or false',
                Response::HTTP_BAD_REQUEST,
            );
        }

        $entityType    = trim((string) $request->query->get('entity_type', '')) ?: null;
        $trustMarkType = trim((string) $request->query->get('trust_mark_type', '')) ?: null;

        $pdo     = PdoFactory::get($moduleConfig);
        $service = new SubordinateService(new SubordinateRepository($pdo));

        return new JsonResponse($service->listSubordinates(
            entityType:    $entityType,
            trustMarked:   $trustMarked === 'true',
            trustMarkType: $trustMarkType,
            issuedMarks:   new IssuedTrustMarkRepository($pdo),
        ));
    }


    /**
     * Serve the Subordinate Statement endpoint.
     *
     * Only active subordinates are served. The metadata_policy claim is the result of
     * merging the federation-wide policy for the subordinate's entity type with the
     * per-subordinate policy stored in oidanchor_subordinates.
     */
    public function fetch(Request $request): Response
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');
        $entityId     = $moduleConfig->getString('entity_id');

        // iss is optional: this TA is always the issuer, so default it to our entity_id when the
        // caller omits it (the Federation Gateway's chain inspector calls /fetch?sub=… with no iss).
        // An explicitly-supplied iss must still match this TA.
        $iss = (string) $request->query->get('iss', '');
        $sub = (string) $request->query->get('sub', '');

        if ($iss === '') {
            $iss = $entityId;
        }

        if ($iss !== $entityId) {
            return $this->federationError(
                'invalid_request',
                sprintf("iss must be '%s'", $entityId),
                Response::HTTP_BAD_REQUEST,
            );
        }

        if ($sub === '') {
            return $this->federationError(
                'invalid_request',
                'sub parameter is required',
                Response::HTTP_BAD_REQUEST,
            );
        }

        $pdo = PdoFactory::get($moduleConfig);

        $service = new SubordinateService(
            new SubordinateRepository($pdo),
        );

        $subordinate = $service->findSubordinate($sub);

        if ($subordinate === null) {
            return $this->federationError(
                'not_found',
                sprintf("No subordinate registered for '%s'", $sub),
                Response::HTTP_NOT_FOUND,
            );
        }

        if ($subordinate->status !== 'active') {
            return $this->federationError(
                'not_found',
                sprintf("Subordinate '%s' is not active", $sub),
                Response::HTTP_NOT_FOUND,
            );
        }

        if (empty($subordinate->jwks)) {
            return $this->federationError(
                'not_found',
                sprintf("No JWKS stored for subordinate '%s'", $sub),
                Response::HTTP_NOT_FOUND,
            );
        }

        try {
            $claims = (new SubordinateStatementService())->buildClaims($subordinate, $moduleConfig, $pdo);
        } catch (MetadataPolicyException $e) {
            return $this->federationError(
                'server_error',
                'Incompatible metadata policies for this subordinate: ' . $e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        $token = (new FederationKeyService($moduleConfig, $pdo))->signEntityStatement($claims);

        return $this->jwtResponse($token, 'application/entity-statement+jwt');
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Return a spec-compliant JSON error response.
     */
    private function federationError(string $error, string $description, int $status): JsonResponse
    {
        return new JsonResponse(
            ['error' => $error, 'error_description' => $description],
            $status,
        );
    }
}
