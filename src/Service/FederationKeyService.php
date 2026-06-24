<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Service;

use SimpleSAML\Configuration;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmEnum;
use SimpleSAML\OpenID\Codebooks\ClaimsEnum;
use SimpleSAML\OpenID\Codebooks\JwtTypesEnum;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Jwk;
use SimpleSAML\OpenID\Jwk\JwkDecorator;
use SimpleSAML\OpenID\SupportedAlgorithms;

/**
 * Centralises the TA's federation signing key handling and JWT signing.
 *
 * Every federation object the TA signs — Entity Configuration, Subordinate Statements,
 * Trust Marks and Trust Mark Status Responses — is produced here with the same key,
 * kid and algorithm, using the simplesamlphp/openid factories so the JOSE headers
 * (typ, alg, kid) are always spec-correct and consistent across endpoints.
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


    public function __construct(
        private readonly Configuration $moduleConfig,
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
     * The TA's public federation JWKS in {"keys":[...]} form, with kid populated.
     *
     * @return array{keys: list<array<string,mixed>>}
     */
    public function publicJwks(): array
    {
        return ['keys' => [$this->context()['publicJwkData']]];
    }


    /**
     * Sign a Trust Mark (typ: trust-mark+jwt, set by the library factory).
     *
     * @param array<non-empty-string,mixed> $payload
     * @param array<non-empty-string,mixed> $extraHeader
     */
    public function signTrustMark(array $payload, array $extraHeader = []): string
    {
        $ctx = $this->context();

        return $this->federation()->trustMarkFactory()->fromData(
            $ctx['signingKey'],
            $ctx['algorithm'],
            $payload,
            $this->header($extraHeader),
        )->getToken();
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
     * Load the signing key from config and derive the kid and public JWK data (memoised).
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
        if ($this->context !== null) {
            return $this->context;
        }

        $keyFile      = $this->moduleConfig->getString('signing_key_file');
        $keyPass      = $this->moduleConfig->getOptionalString('signing_key_passphrase', null);
        $algorithmStr = $this->moduleConfig->getOptionalString('signing_algorithm', 'RS256') ?? 'RS256';

        $signingKey = (new Jwk())->jwkDecoratorFactory()->fromPkcs1Or8KeyFile($keyFile, $keyPass, ['use' => 'sig']);
        $publicJwk  = $signingKey->jwk()->toPublic();
        $kid        = $publicJwk->thumbprint('sha256');

        $publicJwkData        = $publicJwk->jsonSerialize();
        $publicJwkData['kid'] = $kid;

        return $this->context = [
            'signingKey'    => $signingKey,
            'kid'           => $kid,
            'publicJwkData' => $publicJwkData,
            'algorithm'     => SignatureAlgorithmEnum::from($algorithmStr),
        ];
    }
}
