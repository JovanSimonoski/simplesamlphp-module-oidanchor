<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
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
        $pdo          = $this->buildPdo($moduleConfig);
        $keys         = new FederationKeyService($moduleConfig, $pdo);

        $claims = (new EntityConfigurationService($keys))->buildClaims($moduleConfig, $pdo);

        $token = $keys->signEntityStatement($claims);

        return new Response($token, Response::HTTP_OK, ['Content-Type' => 'application/entity-statement+jwt']);
    }


    /**
     * Serve the Subordinate Listing endpoint — returns entity IDs of active subordinates only.
     */
    public function subordinateList(Request $request): JsonResponse
    {
        $moduleConfig = Configuration::getConfig('module_oidanchor.php');

        $service = new SubordinateService(
            new SubordinateRepository($this->buildPdo($moduleConfig)),
        );

        return new JsonResponse($service->listSubordinates());
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

        $iss = $request->query->get('iss', '');
        $sub = $request->query->get('sub', '');

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

        $pdo = $this->buildPdo($moduleConfig);

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

        return new Response($token, Response::HTTP_OK, ['Content-Type' => 'application/entity-statement+jwt']);
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Build a PDO connection from the module configuration.
     */
    private function buildPdo(Configuration $moduleConfig): PDO
    {
        try {
            return new PDO(
                $moduleConfig->getString('database_dsn'),
                $moduleConfig->getOptionalString('database_username', null),
                $moduleConfig->getOptionalString('database_password', null),
                [
                    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES   => false,
                ],
            );
        } catch (PDOException $e) {
            throw new RuntimeException('oidanchor: cannot connect to database: ' . $e->getMessage(), 0, $e);
        }
    }


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
