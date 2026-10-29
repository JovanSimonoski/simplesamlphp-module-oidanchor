<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Service\EntityConfigurationService;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\KeyManagementService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

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
