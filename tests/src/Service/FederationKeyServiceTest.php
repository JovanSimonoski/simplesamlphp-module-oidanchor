<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use InvalidArgumentException;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Service\EntityConfigurationService;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\KeyManagementService;
use SimpleSAML\OpenID\Algorithms\SignatureAlgorithmBag;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\SupportedAlgorithms;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Throwable;

#[CoversClass(FederationKeyService::class)]
final class FederationKeyServiceTest extends TestCase
{
    public function testEntityConfigurationIsSignedByAKeyInItsOwnJwks(): void
    {
        $config = $this->moduleConfig();
        $keys   = $this->keys($config);

        $token = $this->signEntityConfiguration($keys);

        $this->assertSignedByPublishedKey($token);
    }


    public function testRotationBetweenClaimAssemblyAndSigningKeepsTheStatementSelfVerifiable(): void
    {
        $config = $this->moduleConfig();
        $keys   = $this->keys($config);
        $claims = (new EntityConfigurationService($keys))->buildClaims($config, $this->pdo);

        // Another request (cron, an admin) rotates the key in between.
        (new KeyManagementService($config, $this->pdo))->triggerRotation(false, 'test');

        $this->assertSignedByPublishedKey($keys->signEntityStatement($claims));
    }


    public function testRotationBeforeTheRequestIsPickedUpBothInJwksAndSignature(): void
    {
        $config = $this->moduleConfig();
        $kms    = new KeyManagementService($config, $this->pdo);
        $old    = $kms->activeSigningContext()['kid'];
        $new    = $kms->triggerRotation(false, 'test')->kid;

        $token = $this->signEntityConfiguration($this->keys($config));

        $this->assertSame($new, self::decodeJwt($token)['header']['kid']);
        $this->assertNotSame($old, $new);
        $this->assertSignedByPublishedKey($token);
    }


    public function testVerificationAcceptsEveryAsymmetricAlgorithmByDefault(): void
    {
        $names = $this->keys()->verificationAlgorithms()->getSignatureAlgorithmBag()->getAllNamesUnique();

        foreach (['RS256', 'PS256', 'ES256', 'ES384', 'ES512', 'EdDSA'] as $alg) {
            $this->assertContains($alg, $names);
        }
        $this->assertNotContains('none', $names);
    }


    public function testConfiguredVerificationAlgorithmsAlwaysIncludeTheSigningAlgorithm(): void
    {
        $keys  = $this->keys($this->moduleConfig(['verification_algorithms' => ['ES256']]));
        $names = $keys->verificationAlgorithms()->getSignatureAlgorithmBag()->getAllNamesUnique();

        $this->assertEqualsCanonicalizing(['RS256', 'ES256'], $names);
    }


    public function testInvalidVerificationAlgorithmIsRejected(): void
    {
        $keys = $this->keys($this->moduleConfig(['verification_algorithms' => ['none']]));

        $this->expectException(InvalidArgumentException::class);
        $keys->verificationAlgorithms();
    }


    public function testAnRs256AnchorParsesAnEs256SignedTrustMark(): void
    {
        // Another entity, signing with ES256 (its own database and key).
        $otherConfig = $this->moduleConfig(['entity_id' => 'https://issuer.example.org']);
        $other       = new FederationKeyService($otherConfig, new PDO('sqlite::memory:'));
        $other->keyManagement()->setAlgorithm('ES256');
        $token = (new FederationKeyService($otherConfig, $other->pdoConnection()))->signTrustMark([
            'iss'             => 'https://issuer.example.org',
            'sub'             => self::ENTITY_ID,
            'trust_mark_type' => 'https://issuer.example.org/tm',
            'iat'             => time(),
            'exp'             => time() + 3600,
        ]);

        $issuerJwks = $other->publicJwks();

        $keys = $this->keys();
        $this->assertSame('RS256', $keys->algorithm()->value);

        $mark = (new Federation($keys->verificationAlgorithms()))->trustMarkFactory()->fromToken($token);
        $mark->verifyWithKeySet($issuerJwks);
        $this->assertSame('https://issuer.example.org', $mark->getIssuer());

        // What the TA did before: verification restricted to its own signing algorithm.
        $this->expectException(Throwable::class);
        (new Federation(new SupportedAlgorithms(new SignatureAlgorithmBag($keys->algorithm()))))
            ->trustMarkFactory()->fromToken($token)->verifyWithKeySet($issuerJwks);
    }


    private function signEntityConfiguration(FederationKeyService $keys): string
    {
        $config = $this->moduleConfig();

        return $keys->signEntityStatement((new EntityConfigurationService($keys))->buildClaims($config, $this->pdo));
    }


    private function assertSignedByPublishedKey(string $token): void
    {
        $decoded = self::decodeJwt($token);

        $this->assertContains(
            $decoded['header']['kid'],
            array_column($decoded['payload']['jwks']['keys'], 'kid'),
            'The Entity Configuration is signed by a key missing from its own jwks claim.',
        );
    }
}
