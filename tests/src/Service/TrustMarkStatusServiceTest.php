<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Entity\IssuedTrustMark;
use SimpleSAML\Module\oidanchor\Repository\IssuedTrustMarkRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSpecRepository;
use SimpleSAML\Module\oidanchor\Repository\TrustMarkSubjectRepository;
use SimpleSAML\Module\oidanchor\Service\FederationKeyService;
use SimpleSAML\Module\oidanchor\Service\TrustMarkStatusService;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(TrustMarkStatusService::class)]
final class TrustMarkStatusServiceTest extends TestCase
{
    private const string TYPE = 'https://ta.example.org/trust-marks/member';

    private const string SUB = 'https://leaf.example.org';


    private FederationKeyService $keys;

    private IssuedTrustMarkRepository $issued;


    protected function setUp(): void
    {
        parent::setUp();

        $this->keys   = $this->keys();
        $this->issued = new IssuedTrustMarkRepository($this->pdo);
    }


    public function testActiveMark(): void
    {
        $jwt = $this->issue();

        $result = $this->service()->getStatus(self::TYPE, self::SUB);

        $this->assertSame('active', $result['status']);
        $this->assertTrue($result['active']);
        $this->assertSame($jwt, $result['trust_mark']);
    }


    public function testExpiredMark(): void
    {
        $this->issue(exp: time() - 10);

        $result = $this->service()->getStatus(self::TYPE, self::SUB);

        $this->assertSame('expired', $result['status']);
        $this->assertFalse($result['active']);
    }


    public function testRevokedMark(): void
    {
        $this->issue();
        $row = $this->issued->findLatest(self::TYPE, self::SUB);
        $this->assertNotNull($row);
        $this->issued->revoke((int) $row->id, 'misbehaviour');

        $result = $this->service()->getStatus(self::TYPE, self::SUB);

        $this->assertSame('revoked', $result['status']);
        $this->assertSame('misbehaviour', $result['reason']);
        $this->assertNotNull($result['revoked_at']);
    }


    public function testWithdrawnSubjectReportsRevokedEvenWhenTheRowIsActive(): void
    {
        $this->issue();
        $this->setSubjectStatus('blocked');

        $result = $this->service()->getStatus(self::TYPE, self::SUB);

        $this->assertSame('revoked', $result['status']);
        $this->assertStringContainsString('blocked', (string) $result['reason']);
    }


    public function testActiveSubjectDoesNotWithdrawTheMark(): void
    {
        $this->issue();
        $this->setSubjectStatus('active');

        $this->assertSame('active', $this->service()->getStatus(self::TYPE, self::SUB)['status']);
    }


    public function testUnknownMarkIsInvalid(): void
    {
        $result = $this->service()->getStatus(self::TYPE, self::SUB);

        $this->assertSame('invalid', $result['status']);
        $this->assertFalse($result['active']);
    }


    public function testMissingLookupKeysAreInvalid(): void
    {
        $this->assertSame('invalid', $this->service()->getStatus(self::TYPE, null)['status']);
        $this->assertSame('invalid', $this->service()->getStatus(null, self::SUB)['status']);
    }


    public function testSuppliedJwtProvidesTheLookupKeys(): void
    {
        $jwt = $this->issue();

        $result = $this->service()->getStatus(null, null, $jwt);

        $this->assertSame('active', $result['status']);
        $this->assertSame(self::TYPE, $result['trust_mark_type']);
        $this->assertSame(self::SUB, $result['sub']);
    }


    public function testJwtFromAnotherIssuerIsInvalid(): void
    {
        $jwt = $this->keys->signTrustMark($this->payload(iss: 'https://other.example.org'));

        $result = $this->service()->getStatus(null, null, $jwt);

        $this->assertSame('invalid', $result['status']);
        $this->assertStringContainsString('not issued by this Trust Anchor', (string) $result['message']);
    }


    public function testUnparseableJwtIsInvalid(): void
    {
        $this->assertSame('invalid', $this->service()->getStatus(null, null, 'not-a-jwt')['status']);
    }


    private function service(): TrustMarkStatusService
    {
        return new TrustMarkStatusService($this->keys, $this->issued, new TrustMarkSubjectRepository($this->pdo));
    }


    /**
     * Create the issuance spec for TYPE and give SUB the given subject status. Constructing the
     * subject repository backfills a subject from the issued marks, so update it if present.
     */
    private function setSubjectStatus(string $status): void
    {
        $specId   = (new TrustMarkSpecRepository($this->pdo))->create(['trust_mark_type' => self::TYPE]);
        $subjects = new TrustMarkSubjectRepository($this->pdo);
        $subject  = $subjects->findByTypeAndEntity(self::TYPE, self::SUB);

        if ($subject === null) {
            $subjects->create($specId, self::SUB, $status, null, null);
        } else {
            $subjects->setStatus((int) $subject['id'], $status);
        }
    }


    /**
     * Sign a mark with the TA key and record it in the registry. Returns the JWT.
     */
    private function issue(?int $exp = null): string
    {
        $exp ??= time() + 3600;
        $jwt   = $this->keys->signTrustMark($this->payload(exp: $exp));

        $this->issued->create(new IssuedTrustMark(
            id:               null,
            trustMarkType:    self::TYPE,
            sub:              self::SUB,
            jwt:              $jwt,
            iat:              time() - 60,
            exp:              $exp,
            status:           'active',
            revokedAt:        null,
            revocationReason: null,
        ));

        return $jwt;
    }


    /**
     * @return array<non-empty-string,mixed>
     */
    private function payload(string $iss = self::ENTITY_ID, ?int $exp = null): array
    {
        return [
            'iss'             => $iss,
            'sub'             => self::SUB,
            'trust_mark_type' => self::TYPE,
            'iat'             => time() - 60,
            'exp'             => $exp ?? time() + 3600,
        ];
    }
}
