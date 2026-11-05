<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use InvalidArgumentException;
use Jose\Component\KeyManagement\JWKFactory;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SimpleSAML\Module\oidanchor\Entity\FederationKey;
use SimpleSAML\Module\oidanchor\Repository\FederationKeyRepository;
use SimpleSAML\Module\oidanchor\Service\KeyManagementService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(KeyManagementService::class)]
final class KeyManagementServiceTest extends TestCase
{
    public function testConfigKeyIsImportedAsTheActiveSigningKey(): void
    {
        $kms = $this->kms();
        $ctx = $kms->activeSigningContext();

        $this->assertSame('RS256', $ctx['algorithm']->value);
        $this->assertSame([$ctx['kid']], array_column($kms->publicJwks()['keys'], 'kid'));
    }


    public function testSigningNeverRotatesEvenWhenRotationIsDue(): void
    {
        $kms = $this->kms();
        $kid = $kms->activeSigningContext()['kid'];
        $this->makeRotationDue($kms);

        $this->assertSame($kid, $kms->activeSigningContext()['kid']);
        $this->assertCount(1, $this->keyRepo()->findAll());
    }


    public function testRotateIfDueDoesNothingWhenDisabledOrNotDue(): void
    {
        $kms = $this->kms();
        $kms->activeSigningContext();

        $this->assertNull($kms->rotateIfDue());

        $kms->setRotationOptions(['enabled' => true, 'interval' => 86400], merge: false);
        $this->assertNull($kms->rotateIfDue());
        $this->assertCount(1, $this->keyRepo()->findAll());
    }


    public function testRotateIfDueRotatesAndLeavesExactlyOneActiveSigningKey(): void
    {
        $kms = $this->kms();
        $old = $kms->activeSigningContext()['kid'];
        $this->makeRotationDue($kms);

        $new = $kms->rotateIfDue();

        $this->assertInstanceOf(FederationKey::class, $new);
        $this->assertNotSame($old, $new->kid);
        $this->assertSame($new->kid, $kms->activeSigningContext()['kid']);

        $active = array_filter(
            $this->keyRepo()->findAll(),
            static fn(FederationKey $key): bool => $key->kmsManaged && $key->status === 'active',
        );
        $this->assertSame([$new->kid], array_values(array_map(static fn(FederationKey $k): string => $k->kid, $active)));
    }


    public function testSwitchingWithinTheKeyFamilyKeepsTheKeyAndKeepsSigningWorking(): void
    {
        $config = $this->moduleConfig();
        $kms    = new KeyManagementService($config, $this->pdo);
        $kms->activeSigningContext();
        // A KMS-generated key: its JWK material carries "alg": "RS256".
        $kid = $kms->triggerRotation(false, 'test')->kid;

        $kms->setAlgorithm('PS256');

        $key = $this->keyRepo()->findByKid($kid);
        $this->assertNotNull($key);
        $this->assertSame('active', $key->status);
        $this->assertSame('PS256', $key->alg);
        $this->assertSame('PS256', $key->publicJwk['alg']);
        $this->assertSame('PS256', $key->privateJwk['alg'] ?? null);

        $token  = $this->keys($config)->signEntityStatement($this->minimalStatement());
        $header = self::decodeJwt($token)['header'];
        $this->assertSame('PS256', $header['alg']);
        $this->assertSame($kid, $header['kid']);
    }


    public function testSwitchingTheKeyFamilyRotatesToANewKey(): void
    {
        $config = $this->moduleConfig();
        $kms    = new KeyManagementService($config, $this->pdo);
        $old    = $kms->activeSigningContext()['kid'];

        $kms->setAlgorithm('ES256');

        $ctx = $kms->activeSigningContext();
        $this->assertNotSame($old, $ctx['kid']);
        $this->assertSame('ES256', $ctx['algorithm']->value);
        $this->assertSame('ES256', self::decodeJwt($this->keys($config)->signEntityStatement($this->minimalStatement()))['header']['alg']);
    }


    /**
     * @return array<string,array{?int, ?int, bool, bool}>
     */
    public static function unpublishableValidity(): array
    {
        return [
            'past exp'   => [null, time() - 60, false, true],
            'future exp' => [null, time() + 3600, false, true],
            'future nbf' => [time() + 3600, null, true, false],
        ];
    }


    #[DataProvider('unpublishableValidity')]
    public function testActiveSigningKeyCannotBeMadeUnpublishable(?int $nbf, ?int $exp, bool $setNbf, bool $setExp): void
    {
        $kms = $this->kms();
        $kid = $kms->activeSigningContext()['kid'];

        try {
            $kms->updateKeyValidity($kid, $nbf, $exp, $setNbf, $setExp);
            $this->fail('Expected the validity change to be rejected.');
        } catch (InvalidArgumentException) {
            // expected
        }

        $this->assertSame([$kid], array_column($kms->publicJwks()['keys'], 'kid'));
    }


    public function testActiveSigningKeyValidityCanBeClearedOrBackdated(): void
    {
        $kms = $this->kms();
        $kid = $kms->activeSigningContext()['kid'];

        $key = $kms->updateKeyValidity($kid, time() - 60, null, true, true);

        $this->assertNotNull($key);
        $this->assertTrue($key->isPublishable(time()));
    }


    public function testOtherKeysMayBeGivenAnExp(): void
    {
        $kms = $this->kms();
        $kms->activeSigningContext();
        $kms->addPublicKey(
            JWKFactory::createECKey('P-256', ['kid' => 'external-1', 'use' => 'sig'])->toPublic()->all(),
            null,
            null,
            null,
        );

        $key = $kms->updateKeyValidity('external-1', null, time() - 60, false, true);

        $this->assertNotNull($key);
        $this->assertNotContains('external-1', array_column($kms->publicJwks()['keys'], 'kid'));
    }


    /**
     * @return array<non-empty-string,mixed>
     */
    private function minimalStatement(): array
    {
        return [
            'iss'  => self::ENTITY_ID,
            'sub'  => self::ENTITY_ID,
            'iat'  => time(),
            'exp'  => time() + 60,
            'jwks' => (new KeyManagementService($this->moduleConfig(), $this->pdo))->publicJwks(),
        ];
    }


    private function makeRotationDue(KeyManagementService $kms): void
    {
        $kms->setRotationOptions(['enabled' => true, 'interval' => 3600, 'overlap' => 600], merge: false);
        $this->pdo->exec('UPDATE oidanchor_federation_keys SET iat = iat - 7200, created_at = created_at - 7200');
    }


    private function kms(): KeyManagementService
    {
        return new KeyManagementService($this->moduleConfig(), $this->pdo);
    }


    private function keyRepo(): FederationKeyRepository
    {
        return new FederationKeyRepository($this->pdo);
    }
}
