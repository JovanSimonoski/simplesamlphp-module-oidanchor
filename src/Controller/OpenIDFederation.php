<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\EntityTypesEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;
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
     *
     * The JWT is self-signed with the TA's federation signing key and contains
     * iss, sub (both = entity_id), iat, exp, jwks, and federation_entity metadata.
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

        $token = $this->signEntityStatement($signingKey, $algorithm, $payload, [ClaimsEnum::Kid->value => $kid]);

        return new Response($token, Response::HTTP_OK, ['Content-Type' => 'application/entity-statement+jwt']);
    }


    /**
     * Serve the Subordinate Listing endpoint (federation_list_endpoint).
     *
     * Returns a JSON array of entity identifiers for which this TA has issued
     * (or is prepared to issue) Subordinate Statements.
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
     * Serve the Subordinate Statement endpoint (federation_fetch_endpoint).
     *
     * Issues a signed JWT asserting the subordinate's keys and (optionally) metadata.
     * Query parameters: iss (must equal this TA's entity_id), sub (the subordinate's entity_id).
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

        $service = new SubordinateService(
            new SubordinateRepository($this->buildPdo($moduleConfig)),
        );

        $subordinate = $service->findSubordinate($sub);

        if ($subordinate === null) {
            return $this->federationError(
                'not_found',
                sprintf("No subordinate registered for '%s'", $sub),
                Response::HTTP_NOT_FOUND,
            );
        }

        if (empty($subordinate['jwks'])) {
            return $this->federationError(
                'not_found',
                sprintf("No JWKS stored for subordinate '%s'", $sub),
                Response::HTTP_NOT_FOUND,
            );
        }

        /** @var array<string,mixed> $jwks */
        $jwks = json_decode($subordinate['jwks'], true);

        $lifetime = $moduleConfig->getOptionalInteger('subordinate_statement_lifetime', 86400) ?? 86400;

        ['signingKey' => $signingKey, 'kid' => $kid, 'algorithm' => $algorithm]
            = $this->loadSigningContext($moduleConfig);

        $now = time();

        $payload = [
            ClaimsEnum::Iss->value  => $entityId,
            ClaimsEnum::Sub->value  => $sub,
            ClaimsEnum::Iat->value  => $now,
            ClaimsEnum::Exp->value  => $now + $lifetime,
            ClaimsEnum::Jwks->value => $jwks,
        ];

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
