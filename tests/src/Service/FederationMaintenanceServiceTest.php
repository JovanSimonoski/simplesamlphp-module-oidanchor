<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Service\FederationMaintenanceService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(FederationMaintenanceService::class)]
final class FederationMaintenanceServiceTest extends TestCase
{
    public function testSelfIssuedMarksAreIssued(): void
    {
        $repo = new EcTrustMarkRepository($this->pdo);
        $id   = $repo->create(['trust_mark_type' => 'https://ta.example.org/tm', 'self_issuance_spec' => []]);

        $summary = $this->service()->run();

        $this->assertNotNull($repo->findById($id)['trust_mark']);
        $this->assertContains('entity configuration trust marks: 1 refreshed, 0 failed', $summary);
    }


    public function testDueRotationRotatesAndReissuesSelfIssuedMarksWithTheNewKey(): void
    {
        $config = $this->moduleConfig();
        $keys   = $this->keys($config);
        $repo   = new EcTrustMarkRepository($this->pdo);
        $id     = $repo->create(['trust_mark_type' => 'https://ta.example.org/tm', 'self_issuance_spec' => []]);

        (new FederationMaintenanceService($config, $keys))->run();
        $oldKid = self::decodeJwt((string) $repo->findById($id)['trust_mark'])['header']['kid'];

        $keys->keyManagement()->setRotationOptions(['enabled' => true, 'interval' => 3600], merge: false);
        $this->pdo->exec('UPDATE oidanchor_federation_keys SET iat = iat - 7200');

        $summary = $this->service()->run();

        $newKid = self::decodeJwt((string) $repo->findById($id)['trust_mark'])['header']['kid'];
        $this->assertNotSame($oldKid, $newKid);
        $this->assertContains('signing key rotated to ' . $newKid, $summary);
    }


    private function service(): FederationMaintenanceService
    {
        $config = $this->moduleConfig();

        return new FederationMaintenanceService($config, $this->keys($config));
    }
}
