<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SimpleSAML\Module\oidanchor\Exception\EntityCollectionException;
use SimpleSAML\Module\oidanchor\Service\EntityCollectionRequest;

#[CoversClass(EntityCollectionRequest::class)]
final class EntityCollectionRequestTest extends TestCase
{
    public function testRepeatedParametersKeepEveryValue(): void
    {
        $this->assertSame(
            [
                'entity_type' => ['openid_provider', 'openid_relying_party'],
                'query'       => ['two words'],
                'from'        => ['https://op.example.org'],
                'flag'        => [''],
            ],
            EntityCollectionRequest::parseFormEncoded(
                'entity_type=openid_provider&entity_type=openid_relying_party&query=two+words&from=https%3A%2F%2Fop.example.org&flag',
            ),
        );
    }


    public function testParametersAreRead(): void
    {
        $request = EntityCollectionRequest::fromParameters([
            'from'            => ['https://op.example.org'],
            'limit'           => ['10'],
            'entity_type'     => ['openid_provider', 'openid_provider', ''],
            'trust_mark_type' => ['https://ta.example.org/marks/a', 'https://ta.example.org/marks/b'],
            'trust_anchor'    => ['https://ta.example.org'],
            'query'           => ['university'],
            'entity_claims'   => ['trust_marks'],
            'info_claims'     => ['display_name'],
            'locale'          => ['DE', 'en-GB'],
        ]);

        $this->assertSame('https://op.example.org', $request->from);
        $this->assertSame(10, $request->limit);
        $this->assertSame(['openid_provider'], $request->entityTypes);
        $this->assertSame(['https://ta.example.org/marks/a', 'https://ta.example.org/marks/b'], $request->trustMarkTypes);
        $this->assertSame('https://ta.example.org', $request->trustAnchor);
        $this->assertSame('university', $request->query);
        $this->assertSame(['entity_id', 'trust_marks'], $request->entityClaims);
        $this->assertSame(['de', 'en-gb'], $request->locales);
    }


    public function testDefaultsWhenNothingIsRequested(): void
    {
        $request = EntityCollectionRequest::fromParameters([]);

        $this->assertTrue($request->wantsEntityClaim('entity_infos'));
        $this->assertFalse($request->wantsEntityClaim('trust_marks'));
        $this->assertTrue($request->wantsInfoClaim('logo_uri'));
        $this->assertTrue($request->wantsInfoClaim('display_name#fr'));
    }


    public function testLocalesUseBasicFiltering(): void
    {
        $request = EntityCollectionRequest::fromParameters(['locale' => ['en']]);

        $this->assertTrue($request->wantsInfoClaim('display_name'));
        $this->assertTrue($request->wantsInfoClaim('display_name#en'));
        $this->assertTrue($request->wantsInfoClaim('display_name#EN-us'));
        $this->assertFalse($request->wantsInfoClaim('display_name#eng'));
        $this->assertFalse($request->wantsInfoClaim('display_name#de'));

        $this->assertTrue(EntityCollectionRequest::fromParameters(['locale' => ['*']])->wantsInfoClaim('display_name#de'));
    }


    /**
     * @return array<string,array{array<string,list<string>>, string}>
     */
    public static function invalidRequests(): array
    {
        return [
            'limit of zero'                   => [['limit' => ['0']], 'invalid_request'],
            'limit that is not a number'      => [['limit' => ['ten']], 'invalid_request'],
            'single-valued parameter repeated' => [['query' => ['a', 'b']], 'invalid_request'],
            'not a language range'            => [['locale' => ['en_US!']], 'invalid_request'],
            'unknown entity claim'            => [['entity_claims' => ['metadata']], 'unsupported_claim'],
            'unknown info claim'              => [['info_claims' => ['client_secret']], 'unsupported_claim'],
        ];
    }


    /**
     * @param array<string,list<string>> $params
     */
    #[DataProvider('invalidRequests')]
    public function testInvalidRequestsAreRejected(array $params, string $error): void
    {
        try {
            EntityCollectionRequest::fromParameters($params);
            $this->fail('The request was accepted.');
        } catch (EntityCollectionException $e) {
            $this->assertSame($error, $e->errorCode);
            $this->assertSame(400, $e->httpStatus);
        }
    }
}
