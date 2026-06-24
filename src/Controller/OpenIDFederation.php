<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Logger;
use SimpleSAML\Module\oidanchor\Repository\FederationPolicyRepository;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkTypeRepository;
use SimpleSAML\Module\oidanchor\Service\MetadataPolicyMerger;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\OpenID\Exceptions\MetadataPolicyException;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\Claims\TrustMarksClaimValue;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
use Throwable;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Controller for OpenID Federation endpoints.
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

        $entityId       = $moduleConfig->getString('entity_id');
        $baseUrl        = $moduleConfig->getString('base_url');
        $lifetime       = $moduleConfig->getOptionalInteger('entity_configuration_lifetime', 86400) ?? 86400;
        /** @var string[] $authorityHints */
        $authorityHints = $moduleConfig->getOptionalArray('authority_hints', []) ?? [];

        $fetchEndpoint = $moduleConfig->getOptionalString('federation_fetch_endpoint', null)
            ?? $baseUrl . '/federation/fetch';
        $listEndpoint  = $moduleConfig->getOptionalString('federation_list_endpoint', null)
            ?? $baseUrl . '/federation/list';

        ['signingKey' => $signingKey, 'kid' => $kid, 'publicJwkData' => $publicJwkData, 'algorithm' => $algorithm]
            = $this->loadSigningContext($moduleConfig);

        $now = time();

        $payload = [
            ClaimsEnum::Iss->value  => $entityId,
            ClaimsEnum::Sub->value  => $entityId,
            ClaimsEnum::Iat->value  => $now,
            ClaimsEnum::Exp->value  => $now + $lifetime,
            ClaimsEnum::Jwks->value => ['keys' => [$publicJwkData]],
            ClaimsEnum::Metadata->value => [
                EntityTypesEnum::FederationEntity->value => [
                    ClaimsEnum::FederationFetchEndpoint->value => $fetchEndpoint,
                    ClaimsEnum::FederationListEndpoint->value  => $listEndpoint,
                ],
            ],
        ];

        if ($authorityHints !== []) {
            $payload[ClaimsEnum::AuthorityHints->value] = $authorityHints;
        }

        // Advertise the Trust Mark Types this TA issues via the trust_mark_issuers claim:
        // each type maps to the list of issuers permitted to issue it — here, only this TA.
        // Done defensively so the Entity Configuration never fails over a Trust Mark lookup.
        try {
            $types = (new TrustMarkTypeRepository($this->buildPdo($moduleConfig)))->findAll();

            if ($types !== []) {
                $issuers = [];
                foreach ($types as $type) {
                    $issuers[$type->trustMarkId] = [$entityId];
                }
                $payload[ClaimsEnum::TrustMarkIssuers->value] = $issuers;
            }
        } catch (Throwable $e) {
            Logger::warning('oidanchor: could not load trust mark types for entity configuration: ' . $e->getMessage());
        }

        $token = $this->signEntityStatement($signingKey, $algorithm, $payload, [ClaimsEnum::Kid->value => $kid]);

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

        // Build the merged metadata_policy claim from federation-wide + per-subordinate layers.
        $mergedPolicy = null;
        try {
            $policyRepo      = new FederationPolicyRepository($pdo);
            $federationEntry = $subordinate->entityType !== null
                ? $policyRepo->findByEntityType($subordinate->entityType)
                : null;

            $federationWidePolicy = $federationEntry !== null
                ? [$federationEntry->entityType => $federationEntry->policy]
                : null;

            $mergedPolicy = (new MetadataPolicyMerger())->merge(
                $federationWidePolicy,
                $subordinate->metadataPolicy,
            );
        } catch (MetadataPolicyException $e) {
            return $this->federationError(
                'server_error',
                'Incompatible metadata policies for this subordinate: ' . $e->getMessage(),
                Response::HTTP_INTERNAL_SERVER_ERROR,
            );
        }

        $lifetime = $moduleConfig->getOptionalInteger('subordinate_statement_lifetime', 86400) ?? 86400;

        ['signingKey' => $signingKey, 'kid' => $kid, 'algorithm' => $algorithm]
            = $this->loadSigningContext($moduleConfig);

        $now = time();

        $payload = [
            ClaimsEnum::Iss->value  => $entityId,
            ClaimsEnum::Sub->value  => $sub,
            ClaimsEnum::Iat->value  => $now,
            ClaimsEnum::Exp->value  => $now + $lifetime,
            ClaimsEnum::Jwks->value => $subordinate->jwks,
        ];

        if ($mergedPolicy !== null) {
            $payload[ClaimsEnum::MetadataPolicy->value] = $mergedPolicy;
        }

        if ($subordinate->extraClaims !== null) {
            foreach ($subordinate->extraClaims as $claim => $value) {
                $payload[$claim] = $value;
            }
        }

        // Embed the subordinate's active, unexpired Trust Marks (issued by this TA) when opted in.
        // Each entry uses the library's spec-correct { trust_mark_type, trust_mark } shape.
        if ($subordinate->includeTrustMarks) {
            $activeMarks = (new IssuedTrustMarkRepository($pdo))->findActiveBySub($sub);

            if ($activeMarks !== []) {
                $payload[ClaimsEnum::TrustMarks->value] = array_map(
                    static fn($mark): array =>
                        (new TrustMarksClaimValue($mark->trustMarkId, $mark->jwt))->jsonSerialize(),
                    $activeMarks,
                );
            }
        }

        $token = $this->signEntityStatement($signingKey, $algorithm, $payload, [ClaimsEnum::Kid->value => $kid]);

        return new Response($token, Response::HTTP_OK, ['Content-Type' => 'application/entity-statement+jwt']);
    }


    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Load the signing key from config and derive the kid and public JWK data.
     *
     * @return array{signingKey: JwkDecorator, kid: string, publicJwkData: array<string,mixed>, algorithm: SignatureAlgorithmEnum}
     */
    private function loadSigningContext(Configuration $moduleConfig): array
    {
        $keyFile      = $moduleConfig->getString('signing_key_file');
        $keyPass      = $moduleConfig->getOptionalString('signing_key_passphrase', null);
        $algorithmStr = $moduleConfig->getOptionalString('signing_algorithm', 'RS256') ?? 'RS256';

        $signingKey    = (new Jwk())->jwkDecoratorFactory()->fromPkcs1Or8KeyFile($keyFile, $keyPass, ['use' => 'sig']);
        $publicJwk     = $signingKey->jwk()->toPublic();
        $kid           = $publicJwk->thumbprint('sha256');
        $publicJwkData = $publicJwk->jsonSerialize();
        $publicJwkData['kid'] = $kid;

        return [
            'signingKey'    => $signingKey,
            'kid'           => $kid,
            'publicJwkData' => $publicJwkData,
            'algorithm'     => SignatureAlgorithmEnum::from($algorithmStr),
        ];
    }


    /**
     * Build a signed compact entity-statement+jwt from the given payload and header.
     */
    private function signEntityStatement(
        JwkDecorator $signingKey,
        SignatureAlgorithmEnum $algorithm,
        array $payload,
        array $header,
    ): string {
        $federation = new Federation(
            new SupportedAlgorithms(new SignatureAlgorithmBag($algorithm)),
        );

        return $federation->entityStatementFactory()->fromData(
            $signingKey,
            $algorithm,
            $payload,
            $header,
        )->getToken();
    }


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
