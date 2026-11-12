<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\CoversClass;
use RuntimeException;
use SimpleSAML\Module\oidanchor\Entity\TrustMarkType;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSpecRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\Module\oidanchor\Service\TrustMarkIssuanceService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(TrustMarkIssuanceService::class)]
#[CoversClass(TrustMarkSpecRepository::class)]
final class TrustMarkIssuanceServiceTest extends TestCase
{
    private const string TYPE = 'https://ta.example.org/tm/member';

    private const string SUB = 'https://leaf.example.org';


    public function testIssueForEntityRegistersAnActiveSubjectAndIssues(): void
    {
        $this->spec(['lifetime' => 3600, 'ref' => 'https://ta.example.org/ref']);

        $mark    = $this->service()->issueForEntity(self::TYPE, self::SUB);
        $payload = self::decodeJwt($mark->jwt)['payload'];

        $this->assertSame(self::ENTITY_ID, $payload['iss']);
        $this->assertSame(self::SUB, $payload['sub']);
        $this->assertSame(self::TYPE, $payload['trust_mark_type']);
        $this->assertSame('https://ta.example.org/ref', $payload['ref']);
        $this->assertSame(3600, $payload['exp'] - $payload['iat']);
        $this->assertSame('active', (new TrustMarkSubjectRepository($this->pdo))->findByTypeAndEntity(self::TYPE, self::SUB)['status'] ?? null);
        $this->assertNotNull((new IssuedTrustMarkRepository($this->pdo))->findActive(self::TYPE, self::SUB));
    }


    public function testPerIssuanceLifetimeAndClaimsOverrideTheSpec(): void
    {
        $this->spec(['lifetime' => 3600, 'additional_claims' => ['level' => 'basic', 'kept' => true]]);

        $mark    = $this->service()->issueForEntity(self::TYPE, self::SUB, 60, ['level' => 'gold', 'iss' => 'https://evil.example.org']);
        $payload = self::decodeJwt($mark->jwt)['payload'];

        $this->assertSame(60, $payload['exp'] - $payload['iat']);
        $this->assertSame('gold', $payload['level']);
        $this->assertTrue($payload['kept']);
        $this->assertSame(self::ENTITY_ID, $payload['iss'], 'Issuer-controlled claims must always win.');
    }


    public function testSubjectClaimsReplaceTheSpecClaims(): void
    {
        $specId = $this->spec(['additional_claims' => ['level' => 'basic', 'spec_only' => 1]]);
        (new TrustMarkSubjectRepository($this->pdo))->create($specId, self::SUB, 'active', null, ['level' => 'silver']);

        $payload = self::decodeJwt($this->service()->issueForEntity(self::TYPE, self::SUB)->jwt)['payload'];

        $this->assertSame('silver', $payload['level']);
        $this->assertArrayNotHasKey('spec_only', $payload);
    }


    public function testABlockedSubjectCannotBeIssuedAMark(): void
    {
        $specId = $this->spec([]);
        (new TrustMarkSubjectRepository($this->pdo))->create($specId, self::SUB, 'blocked', null, null);

        $this->expectException(InvalidArgumentException::class);
        $this->service()->issueForEntity(self::TYPE, self::SUB);
    }


    public function testATypeWithoutASpecCannotBeIssued(): void
    {
        $this->expectException(RuntimeException::class);
        $this->service()->issueForEntity(self::TYPE, self::SUB);
    }


    public function testCatalogEditsAreMirroredIntoTheSpecWithoutTouchingSpecOnlySettings(): void
    {
        $repo   = new TrustMarkSpecRepository($this->pdo);
        $specId = $repo->syncFromType($this->type(lifetime: 3600, logo: 'https://ta.example.org/logo.png'));
        $repo->update($specId, ['delegation_jwt' => 'a.b.c', 'cache_ttl' => 30]);

        $this->assertSame($specId, $repo->syncFromType($this->type(lifetime: 60, logo: null)));

        $spec = $repo->findById($specId);
        $this->assertSame(60, $spec['lifetime'] ?? null);
        $this->assertArrayNotHasKey('logo_uri', (array) $spec);
        $this->assertSame('a.b.c', $spec['delegation_jwt'] ?? null);
        $this->assertSame(30, $spec['cache_ttl'] ?? null);
    }


    /**
     * @param array<string,mixed> $fields
     */
    private function spec(array $fields): int
    {
        return (new TrustMarkSpecRepository($this->pdo))->create($fields + ['trust_mark_type' => self::TYPE]);
    }


    private function type(?int $lifetime, ?string $logo): TrustMarkType
    {
        return new TrustMarkType(
            trustMarkType:   self::TYPE,
            name:            'Member',
            description:     null,
            logoUri:         $logo,
            refUri:          null,
            defaultLifetime: $lifetime,
            extraClaims:     null,
            createdAt:       time(),
            updatedAt:       null,
        );
    }


    private function service(): TrustMarkIssuanceService
    {
        return new TrustMarkIssuanceService($this->keys(), $this->pdo);
    }
}
