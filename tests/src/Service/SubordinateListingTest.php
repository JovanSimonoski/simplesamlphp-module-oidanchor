<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Entity\IssuedTrustMark;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\SubordinateService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

/**
 * The federation list endpoint's filters (OpenID Federation 1.0 §8.2.1).
 */
#[CoversClass(SubordinateService::class)]
final class SubordinateListingTest extends TestCase
{
    private const string OP = 'https://op.example.org';

    private const string RP = 'https://rp.example.org';

    private const string BOTH = 'https://both.example.org';

    private const string BLOCKED = 'https://blocked.example.org';

    private const string TYPE = 'https://ta.example.org/tm/member';


    private SubordinateService $service;

    private IssuedTrustMarkRepository $issued;


    protected function setUp(): void
    {
        parent::setUp();

        $this->service = new SubordinateService(new SubordinateRepository($this->pdo));
        $this->issued  = new IssuedTrustMarkRepository($this->pdo);

        $this->service->create(['entity_id' => self::OP, 'entity_types' => ['openid_provider']]);
        $this->service->create(['entity_id' => self::RP, 'entity_types' => ['openid_relying_party']]);
        $this->service->create(['entity_id' => self::BOTH, 'entity_types' => ['openid_provider', 'openid_relying_party']]);
        $this->service->create(['entity_id' => self::BLOCKED, 'entity_types' => ['openid_provider'], 'status' => 'blocked']);
    }


    public function testWithoutFiltersAllActiveSubordinatesAreListed(): void
    {
        $this->assertEqualsCanonicalizing([self::OP, self::RP, self::BOTH], $this->service->listSubordinates());
    }


    public function testEntityTypeFilterMatchesAnyRegisteredType(): void
    {
        $this->assertEqualsCanonicalizing(
            [self::OP, self::BOTH],
            $this->service->listSubordinates(entityType: 'openid_provider'),
        );
    }


    public function testTrustMarkedOnlyListsSubordinatesWithAnActiveMark(): void
    {
        $this->issue(self::RP, self::TYPE);
        $this->issue(self::OP, self::TYPE, exp: time() - 60);

        $this->assertSame([self::RP], $this->service->listSubordinates(trustMarked: true, issuedMarks: $this->issued));
    }


    public function testTrustMarkTypeFilter(): void
    {
        $this->issue(self::RP, self::TYPE);
        $this->issue(self::BOTH, 'https://ta.example.org/tm/other');

        $this->assertSame([self::RP], $this->service->listSubordinates(trustMarkType: self::TYPE, issuedMarks: $this->issued));
    }


    public function testFiltersCombine(): void
    {
        $this->issue(self::RP, self::TYPE);
        $this->issue(self::BOTH, self::TYPE);

        $this->assertSame(
            [self::BOTH],
            $this->service->listSubordinates(entityType: 'openid_provider', trustMarkType: self::TYPE, issuedMarks: $this->issued),
        );
    }


    private function issue(string $sub, string $type, ?int $exp = null): void
    {
        $this->issued->create(new IssuedTrustMark(
            id:               null,
            trustMarkType:    $type,
            sub:              $sub,
            jwt:              'x.y.z',
            iat:              time() - 120,
            exp:              $exp ?? time() + 3600,
            status:           'active',
            revokedAt:        null,
            revocationReason: null,
        ));
    }
}
