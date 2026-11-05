<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
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
