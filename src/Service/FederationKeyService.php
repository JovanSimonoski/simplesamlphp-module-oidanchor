<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use PDO;
use PDOException;
use RuntimeException;
use SimpleSAML\Configuration;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\Serializers\JwsSerializerEnum;
use SimpleSAML\OpenID\SupportedAlgorithms;

/**
 * Centralises the TA's federation signing key handling and JWT signing.
 *
 * Every federation object the TA signs — Entity Configuration, Subordinate Statements,
 * Trust Marks and Trust Mark Status Responses — is produced here with the same key,
 * kid and algorithm, using the simplesamlphp/openid factories so the JOSE headers
 * (typ, alg, kid) are always spec-correct and consistent across endpoints.
 *
 * Key material comes from the database-backed KeyManagementService (which imports the
 * config-file key on first use), so API-driven rotation / algorithm changes take effect
 * immediately on every signing endpoint.
 */
class FederationKeyService
{
    /**
     * Resolve Response JOSE `typ`. The library has no JwtTypesEnum case for it
     * (OpenID Federation 1.0 §8.2: media type application/resolve-response+jwt).
     */
    public const RESOLVE_RESPONSE_TYP = 'resolve-response+jwt';

    /**
     * @var array{
     *     signingKey: JwkDecorator,
     *     kid: string,
     *     publicJwkData: array<string,mixed>,
     *     algorithm: SignatureAlgorithmEnum
     * }|null
     */
    private ?array $context = null;

    private ?Federation $federation = null;

    private ?KeyManagementService $keyManagement = null;


    public function __construct(
        private readonly Configuration $moduleConfig,
        private ?PDO $pdo = null,
    ) {
    }


    public function entityId(): string
    {
        return $this->moduleConfig->getString('entity_id');
    }


    public function kid(): string
    {
        return $this->context()['kid'];
    }


    public function algorithm(): SignatureAlgorithmEnum
    {
        return $this->context()['algorithm'];
    }


    /**
     * The TA's public federation JWKS in {"keys":[...]} form: every published key
     * (active signing key, API-managed keys, rotated-out keys still in their overlap window).
     *
     * @return array{keys: list<array<string,mixed>>}
     */
    public function publicJwks(): array
    {
        return $this->keyManagement()->publicJwks();
    }


    /**
     * Sign an Entity Statement (typ: entity-statement+jwt, set by the library factory).
     * Used for both the Entity Configuration and Subordinate Statements.
     *
     * @param array<non-empty-string,mixed> $payload
     * @param array<non-empty-string,mixed> $extraHeader
     */
    public function signEntityStatement(array $payload, array $extraHeader = []): string
    {
        $ctx = $this->context();

        return $this->federation()->entityStatementFactory()->fromData(
            $ctx['signingKey'],
            $ctx['algorithm'],
            $payload,
            $this->header($extraHeader),
        )->getToken();
    }


    /**
     * Sign a Trust Mark Delegation (typ: trust-mark-delegation+jwt, set by the library factory).
     * Only possible when this TA is the Trust Mark owner (we hold no other private keys).
     *
     * @param array<non-empty-string,mixed> $payload
     * @param array<non-empty-string,mixed> $extraHeader
     */
    public function signTrustMarkDelegation(array $payload, array $extraHeader = []): string
    {
        $ctx = $this->context();

        return $this->federation()->trustMarkDelegationFactory()->fromData(
            $ctx['signingKey'],
            $ctx['algorithm'],
            $payload,
            $this->header($extraHeader),
        )->getToken();
    }


    public function keyManagement(): KeyManagementService
    {
        return $this->keyManagement ??= new KeyManagementService($this->moduleConfig, $this->pdoConnection());
    }


    /**
     * Sign a Trust Mark (typ: trust-mark+jwt).
     *
     * Worked around a bug in simplesamlphp/openid v0.1.x: TrustMarkFactory::fromData sets the
     * `typ` header to the JwtTypesEnum *case object* instead of its `->value` string
     * (`$header[typ] = $expectedJwtType;` — missing `->value`). Its own validate-on-construct
     * then reads that header back and throws `InvalidValueException: Unsafe string casting`
     * before getToken() can serialise. EntityStatementFactory and TrustMarkDelegationFactory set
     * `->value` correctly; only TrustMarkFactory is affected. We reproduce exactly what a fixed
     * factory would emit — the same `jwsDecoratorBuilder` and compact serializer it uses
     * internally — with `typ` set as a string, so the output is byte-identical and the broken
     * validation is skipped.
     *
     * @param array<non-empty-string,mixed> $payload
     * @param array<non-empty-string,mixed> $extraHeader
     */
    public function signTrustMark(array $payload, array $extraHeader = []): string
    {
        $ctx = $this->context();

        $header = [ClaimsEnum::Typ->value => JwtTypesEnum::TrustMarkJwt->value] + $this->header($extraHeader);

        $federation   = $this->federation();
        $jwsDecorator = $federation->jwsDecoratorBuilder()->fromData(
            $ctx['signingKey'],
            $ctx['algorithm'],
            $payload,
            $header,
        );

        return $federation->jwsSerializerManagerDecorator()->serialize(
            JwsSerializerEnum::Compact->value,
            $jwsDecorator,
        );
    }


    /**
     * Sign a Trust Mark Status Response (typ: trust-mark-status-response+jwt).
     *
     * The status-response factory inherits the generic builder and does not set typ,
     * so we set it explicitly here.
     *
     * @param array<non-empty-string,mixed> $payload
     * @param array<non-empty-string,mixed> $extraHeader
     */
    public function signTrustMarkStatusResponse(array $payload, array $extraHeader = []): string
    {
        return $this->signWithTyp(JwtTypesEnum::TrustMarkStatusResponseJwt->value, $payload, $extraHeader);
    }


    /**
     * Sign a Resolve Response (typ: resolve-response+jwt).
     *
     * @param array<non-empty-string,mixed> $payload
     * @param array<non-empty-string,mixed> $extraHeader
     */
    public function signResolveResponse(array $payload, array $extraHeader = []): string
    {
        return $this->signWithTyp(self::RESOLVE_RESPONSE_TYP, $payload, $extraHeader);
    }


    /**
     * Sign an arbitrary federation JWT with an explicit typ header.
     *
     * The status-response factory inherits the generic ParsedJws builder (it does not force a
     * typ), so it serves as the vehicle for signing federation JWTs whose typ the library does
     * not model with a dedicated factory (status responses, resolve responses).
     *
     * @param array<non-empty-string,mixed> $payload
     * @param array<non-empty-string,mixed> $extraHeader
     */
    private function signWithTyp(string $typ, array $payload, array $extraHeader): string
    {
        $ctx = $this->context();

        return $this->federation()->trustMarkStatusResponseFactory()->fromData(
            $ctx['signingKey'],
            $ctx['algorithm'],
            $payload,
            $this->header([ClaimsEnum::Typ->value => $typ] + $extraHeader),
        )->getToken();
    }


    /**
     * @param array<non-empty-string,mixed> $extraHeader
     * @return array<non-empty-string,mixed>
     */
    private function header(array $extraHeader): array
    {
        return [ClaimsEnum::Kid->value => $this->context()['kid']] + $extraHeader;
    }


    private function federation(): Federation
    {
        return $this->federation ??= new Federation(
            new SupportedAlgorithms(new SignatureAlgorithmBag($this->algorithm())),
        );
    }


    /**
     * The active signing context from the DB-backed key store (memoised per request).
     *
     * @return array{
     *     signingKey: JwkDecorator,
     *     kid: string,
     *     publicJwkData: array<string,mixed>,
     *     algorithm: SignatureAlgorithmEnum
     * }
     */
    private function context(): array
    {
        return $this->context ??= $this->keyManagement()->activeSigningContext();
    }


    private function pdoConnection(): PDO
    {
        if ($this->pdo !== null) {
            return $this->pdo;
        }

        try {
            return $this->pdo = new PDO(
                $this->moduleConfig->getString('database_dsn'),
                $this->moduleConfig->getOptionalString('database_username', null),
                $this->moduleConfig->getOptionalString('database_password', null),
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
}
