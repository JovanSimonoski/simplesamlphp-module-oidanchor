<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SimpleSAML\Module\oidanchor\Repository\EcTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Service\EcTrustMarkService;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\OpenID\Federation;
use SimpleSAML\OpenID\Federation\EntityStatement;
use SimpleSAML\OpenID\Federation\TrustMark;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Throwable;

#[CoversClass(EcTrustMarkService::class)]
final class EcTrustMarkServiceTest extends TestCase
{
    private const string TYPE = 'https://ta.example.org/trust-marks/self';

    private const string ISSUER = 'https://issuer.example.org';

    private const string EXTERNAL_TYPE = 'https://issuer.example.org/tm/member';


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


    public function testAVerifiedExternalMarkIsAccepted(): void
    {
        $issuer = $this->issuer();

        $this->assertSame(
            $issuer['mark'],
            $this->service()->verifiedExternalMark(
                $this->parseMark($issuer['mark']),
                $this->parseStatement($issuer['configuration']),
                self::EXTERNAL_TYPE,
                self::ISSUER,
            ),
        );
    }


    /**
     * @return array<string,array{array<string,mixed>, ?string, string}>
     */
    public static function rejectedExternalMarks(): array
    {
        return [
            'issued for another entity' => [['sub' => 'https://other.example.org'], null, 'issued for'],
            'of another type'           => [['trust_mark_type' => 'https://issuer.example.org/tm/other'], null, 'of type'],
            'issued by another entity'  => [['iss' => 'https://other.example.org'], null, 'issued by'],
            'not signed by the issuer'  => [[], 'forged', 'Could not verify JWS signature'],
            'issuer EC not its own'     => [[], 'foreign-configuration', 'not that issuer'],
        ];
    }


    /**
     * @param array<string,mixed> $markOverrides
     */
    #[DataProvider('rejectedExternalMarks')]
    public function testUnverifiedExternalMarksAreRejected(array $markOverrides, ?string $variant, string $reason): void
    {
        $issuer = $this->issuer($markOverrides);
        $mark   = $issuer['mark'];
        $config = $issuer['configuration'];

        if ($variant === 'forged') {
            // Claims are right, but the signature is this TA's, not the issuer's.
            $mark = $this->keys->signTrustMark($this->markPayload([]));
        }
        if ($variant === 'foreign-configuration') {
            $config = $this->issuer([], 'https://other.example.org')['configuration'];
        }

        $error = null;
        try {
            $this->service()->verifiedExternalMark(
                $this->parseMark($mark),
                $this->parseStatement($config),
                self::EXTERNAL_TYPE,
                self::ISSUER,
            );
        } catch (Throwable $e) {
            $error = $e->getMessage();
        }

        $this->assertNotNull($error, 'The mark was accepted.');
        $this->assertStringContainsString($reason, (string) $error);
    }


    /**
     * A separate issuer entity with its own key store: its signed Entity Configuration and a
     * trust mark it issued for this TA.
     *
     * @param array<string,mixed> $markOverrides
     * @return array{configuration: string, mark: string}
     */
    private function issuer(array $markOverrides = [], string $entityId = self::ISSUER): array
    {
        $keys = new FederationKeyService($this->moduleConfig(['entity_id' => $entityId]), new PDO('sqlite::memory:'));
        // Its own key: the test config file key is shared with this TA.
        $keys->keyManagement()->setAlgorithm('ES256');

        $configuration = $keys->signEntityStatement([
            'iss'  => $entityId,
            'sub'  => $entityId,
            'iat'  => time(),
            'exp'  => time() + 3600,
            'jwks' => $keys->publicJwks(),
        ]);

        return ['configuration' => $configuration, 'mark' => $keys->signTrustMark($this->markPayload($markOverrides))];
    }


    /**
     * @param array<string,mixed> $overrides
     * @return array<non-empty-string,mixed>
     */
    private function markPayload(array $overrides): array
    {
        return $overrides + [
            'iss'             => self::ISSUER,
            'sub'             => self::ENTITY_ID,
            'trust_mark_type' => self::EXTERNAL_TYPE,
            'iat'             => time(),
            'exp'             => time() + 3600,
        ];
    }


    /**
     * Parsed the way the service's own fetchers parse: with this TA's verification algorithms.
     */
    private function parseMark(string $jwt): TrustMark
    {
        return (new Federation($this->keys->verificationAlgorithms()))->trustMarkFactory()->fromToken($jwt);
    }


    private function parseStatement(string $jwt): EntityStatement
    {
        return (new Federation($this->keys->verificationAlgorithms()))->entityStatementFactory()->fromToken($jwt);
    }


    private function service(): EcTrustMarkService
    {
        return new EcTrustMarkService($this->keys, $this->repo, $this->moduleConfig([
            'resolve' => ['http_connect_timeout' => 1, 'http_read_timeout' => 1],
        ]));
    }
}
