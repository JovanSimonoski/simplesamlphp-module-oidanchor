<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Service\EcTrustMarkService;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(EcTrustMarkService::class)]
final class EcTrustMarkServiceTest extends TestCase
{
    private const string TYPE = 'https://ta.example.org/trust-marks/self';


    private FederationKeyService $keys;

    private EcTrustMarkRepository $repo;


    protected function setUp(): void
    {
        parent::setUp();

        $this->keys = $this->keys();
        $this->repo = new EcTrustMarkRepository($this->pdo);
    }


    public function testClaimValuesNeverSelfIssuesOrWrites(): void
    {
        $id = $this->repo->create(['trust_mark_type' => self::TYPE, 'self_issuance_spec' => ['lifetime' => 3600]]);

        $this->assertSame([], $this->service()->claimValues());
        $this->assertNull($this->repo->findById($id)['trust_mark']);
        $this->assertNull($this->repo->findById($id)['last_refresh_at']);
    }


    public function testClaimValuesNeverFetchesExternalMarks(): void
    {
        $id = $this->repo->create([
            'trust_mark_type'   => 'https://issuer.example.org/tm',
            'trust_mark_issuer' => 'https://127.0.0.1:9',
            'refresh'           => true,
        ]);

        $this->assertSame([], $this->service()->claimValues());
        $this->assertNull($this->repo->findById($id)['last_refresh_at']);
    }


    public function testRefreshSelfIssuesAndClaimValuesServesTheStoredMark(): void
    {
        $id = $this->repo->create([
            'trust_mark_type'    => self::TYPE,
            'self_issuance_spec' => ['lifetime' => 3600, 'ref' => 'https://ta.example.org/ref'],
        ]);

        $this->assertTrue($this->service()->refresh((array) $this->repo->findById($id)));

        $row = (array) $this->repo->findById($id);
        $this->assertNotNull($row['trust_mark']);
        $payload = self::decodeJwt($row['trust_mark'])['payload'];
        $this->assertSame(self::ENTITY_ID, $payload['iss']);
        $this->assertSame(self::ENTITY_ID, $payload['sub']);
        $this->assertSame(self::TYPE, $payload['trust_mark_type']);
        $this->assertSame(3600, $payload['exp'] - $payload['iat']);

        $this->assertSame(
            [['trust_mark_type' => self::TYPE, 'trust_mark' => $row['trust_mark']]],
            $this->service()->claimValues(),
        );
    }


    public function testSelfIssuedMarkIsNotReissuedBeforeHalfItsLifetime(): void
    {
        $id = $this->repo->create(['trust_mark_type' => self::TYPE, 'self_issuance_spec' => ['lifetime' => 3600]]);
        $this->service()->refresh((array) $this->repo->findById($id));

        $this->assertNull($this->service()->refresh((array) $this->repo->findById($id)));
        $this->assertTrue($this->service()->refresh((array) $this->repo->findById($id), force: true));
    }


    public function testFailedExternalRefreshIsRecordedSoTheRateLimitApplies(): void
    {
        $id = $this->repo->create([
            'trust_mark_type'    => 'https://issuer.example.org/tm',
            'trust_mark_issuer'  => 'https://127.0.0.1:9',
            'refresh'            => true,
            'refresh_rate_limit' => 3600,
        ]);

        $this->assertFalse($this->service()->refresh((array) $this->repo->findById($id)));
        $this->assertNotNull($this->repo->findById($id)['last_refresh_at']);

        // Within the rate limit the broken issuer is not contacted again.
        $this->assertNull($this->service()->refresh((array) $this->repo->findById($id)));
    }


    public function testExpiredMarksAreNotPublished(): void
    {
        $expired = $this->keys->signTrustMark([
            'iss' => 'https://issuer.example.org', 'sub' => self::ENTITY_ID, 'trust_mark_type' => 'https://issuer.example.org/tm',
            'iat' => time() - 7200, 'exp' => time() - 3600,
        ]);
        $this->repo->create(['trust_mark_type' => 'https://issuer.example.org/tm', 'trust_mark' => $expired]);

        $this->assertSame([], $this->service()->claimValues());
    }


    public function testExpiredMarksArePublishedWithinTheGracePeriod(): void
    {
        $expired = $this->keys->signTrustMark([
            'iss' => 'https://issuer.example.org', 'sub' => self::ENTITY_ID, 'trust_mark_type' => 'https://issuer.example.org/tm',
            'iat' => time() - 7200, 'exp' => time() - 60,
        ]);
        $this->repo->create([
            'trust_mark_type'      => 'https://issuer.example.org/tm',
            'trust_mark'           => $expired,
            'refresh_grace_period' => 3600,
        ]);

        $this->assertCount(1, $this->service()->claimValues());
    }


    private function service(): EcTrustMarkService
    {
        return new EcTrustMarkService($this->keys, $this->repo, $this->moduleConfig([
            'resolve' => ['http_connect_timeout' => 1, 'http_read_timeout' => 1],
        ]));
    }
}
