<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Exception\EntityCollectionException;
use SimpleSAML\Module\oidanchor\Exception\ResolveException;
use SimpleSAML\Module\oidanchor\Repository\EntityCollectionRepository;
use SimpleSAML\Module\oidanchor\Repository\SettingsRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Module\oidanchor\Service\EntityCollectionRequest;
use SimpleSAML\Module\oidanchor\Service\EntityCollectionService;
use SimpleSAML\Module\oidanchor\Service\FederationResolver;
use SimpleSAML\Module\oidanchor\Service\ResolveResult;
use SimpleSAML\OpenID\Federation\TrustChain;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(EntityCollectionService::class)]
#[CoversClass(EntityCollectionRepository::class)]
final class EntityCollectionServiceTest extends TestCase
{
    private const string AS = 'https://as.example.org';

    private const string OP = 'https://op.example.org';

    private const string RP1 = 'https://rp1.example.org';

    private const string RP2 = 'https://rp2.example.org';

    private const string CERTIFIED = 'https://ta.example.org/marks/certified';

    private const string AUDITED = 'https://ta.example.org/marks/audited';


    private SubordinateRepository $subordinates;

    private EntityCollectionRepository $collection;


    protected function setUp(): void
    {
        parent::setUp();

        $this->subordinates = new SubordinateRepository($this->pdo);
        $this->collection   = new EntityCollectionRepository($this->pdo);
    }


    // ---- refresh ------------------------------------------------------------

    public function testRefreshStoresWhatTheResolutionVerified(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $mark = $this->markEntry(self::CERTIFIED);

        $counts = $this->service()->refresh($this->resolver([
            self::OP => $this->resolved(self::OP, [
                'openid_provider'   => [
                    'issuer'          => self::OP,
                    'display_name'    => 'Example OP',
                    'display_name#mk' => 'Пример OP',
                    'logo_uri'        => 'https://op.example.org/logo.png',
                ],
                'federation_entity' => [
                    'organization_name'         => 'Example Org',
                    'federation_fetch_endpoint' => 'https://op.example.org/fetch',
                ],
            ], [$mark]),
        ]), 1000);

        $this->assertSame(['resolved' => 1, 'failed' => 0], $counts);

        $snapshot = $this->collection->all()[self::OP];
        $this->assertSame(['openid_provider', 'federation_entity'], $snapshot['entity_types']);
        $this->assertSame([
            'openid_provider'   => [
                'display_name'    => 'Example OP',
                'display_name#mk' => 'Пример OP',
                'logo_uri'        => 'https://op.example.org/logo.png',
            ],
            'federation_entity' => ['organization_name' => 'Example Org'],
        ], $snapshot['entity_infos']);
        $this->assertSame([$mark], $snapshot['trust_marks']);
        $this->assertNull($snapshot['error']);
        $this->assertSame(1000, (new SettingsRepository($this->pdo))->getInt(SettingsRepository::ENTITY_COLLECTION_REFRESHED_AT));
    }


    public function testAnEntityThatNoLongerResolvesLosesItsInfosAndTrustMarks(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $this->collection->save(
            self::OP,
            ['openid_provider'],
            ['openid_provider' => ['display_name' => 'Old name']],
            [$this->markEntry(self::CERTIFIED)],
            null,
            1,
        );

        $this->assertSame(['resolved' => 0, 'failed' => 1], $this->service()->refresh($this->resolver([])));

        $snapshot = $this->collection->all()[self::OP];
        $this->assertSame([], $snapshot['entity_infos']);
        $this->assertSame([], $snapshot['trust_marks']);
        $this->assertStringContainsString('no chain in this test', (string) $snapshot['error']);
    }


    public function testOnlyActiveSubordinatesAreResolvedAndKept(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $this->register(self::RP1, ['openid_relying_party'], 'pending');
        $this->collection->save(self::RP1, [], [], [], null, 1);

        $resolved = [];
        $resolver = $this->createStub(FederationResolver::class);
        $resolver->method('resolve')->willReturnCallback(function (string $sub) use (&$resolved): ResolveResult {
            $resolved[] = $sub;

            return $this->resolved($sub, []);
        });

        $this->service()->refresh($resolver);

        $this->assertSame([self::OP], $resolved);
        $this->assertSame([self::OP], array_keys($this->collection->all()));
    }


    public function testDisplayNameFallsBackToTheClientOrResourceName(): void
    {
        $this->assertSame(
            ['openid_relying_party' => ['logo_uri' => 'https://rp/logo.png', 'display_name' => 'My RP', 'display_name#de' => 'Mein RP']],
            EntityCollectionService::entityInfos(['openid_relying_party' => [
                'client_name'    => 'My RP',
                'client_name#de' => 'Mein RP',
                'logo_uri'       => 'https://rp/logo.png',
                'redirect_uris'  => ['https://rp/callback'],
            ]]),
        );

        $this->assertSame(
            ['oauth_client' => ['display_name' => 'Shown']],
            EntityCollectionService::entityInfos(['oauth_client' => ['client_name' => 'Client', 'display_name' => 'Shown']]),
        );
        $this->assertSame(
            ['oauth_resource' => ['display_name' => 'Example API']],
            EntityCollectionService::entityInfos(['oauth_resource' => ['resource_name' => 'Example API']]),
        );
        $this->assertSame([], EntityCollectionService::entityInfos(['openid_provider' => ['issuer' => self::OP]]));
    }


    // ---- page ---------------------------------------------------------------

    public function testEveryActiveSubordinateIsListedInEntityIdOrder(): void
    {
        $this->register(self::RP2, ['openid_relying_party']);
        $this->register(self::OP, ['openid_provider']);
        $this->register(self::RP1, ['openid_relying_party'], 'blocked');

        $page = $this->page([]);

        $this->assertSame([
            ['entity_id' => self::OP, 'entity_types' => ['openid_provider']],
            ['entity_id' => self::RP2, 'entity_types' => ['openid_relying_party']],
        ], $page['entities']);
        $this->assertArrayNotHasKey('next', $page);
    }


    public function testRefreshedInformationIsServedByDefaultButTrustMarksOnlyOnRequest(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $mark = $this->markEntry(self::CERTIFIED);
        $this->collection->save(
            self::OP,
            ['openid_provider', 'federation_entity'],
            ['openid_provider' => ['display_name' => 'Example OP']],
            [$mark],
            null,
            1,
        );

        $this->assertSame([[
            'entity_id'    => self::OP,
            'entity_types' => ['openid_provider', 'federation_entity'],
            'entity_infos' => ['openid_provider' => ['display_name' => 'Example OP']],
        ]], $this->page([])['entities']);

        $this->assertSame(
            [['entity_id' => self::OP, 'trust_marks' => [$mark]]],
            $this->page(['entity_claims' => ['trust_marks']])['entities'],
        );
    }


    public function testEntityTypeFiltersMatchAnyOfTheRequestedTypes(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $this->register(self::RP1, ['openid_relying_party']);
        $this->register(self::AS, ['oauth_authorization_server']);

        $this->assertSame([self::OP, self::RP1], $this->ids(['entity_type' => ['openid_provider', 'openid_relying_party']]));
        $this->assertSame([self::OP], $this->ids(['entity_type' => ['openid_provider']]));
    }


    public function testTrustMarkTypeFiltersNeedAnUnexpiredMarkOfEveryType(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $this->register(self::RP1, ['openid_relying_party']);
        $this->register(self::RP2, ['openid_relying_party']);
        $this->collection->save(self::OP, [], [], [$this->markEntry(self::CERTIFIED), $this->markEntry(self::AUDITED)], null, 1);
        $this->collection->save(self::RP1, [], [], [$this->markEntry(self::CERTIFIED)], null, 1);
        $this->collection->save(self::RP2, [], [], [$this->markEntry(self::CERTIFIED, time() - 1)], null, 1);

        $this->assertSame([self::OP, self::RP1], $this->ids(['trust_mark_type' => [self::CERTIFIED]]));
        $this->assertSame([self::OP], $this->ids(['trust_mark_type' => [self::CERTIFIED, self::AUDITED]]));
    }


    public function testQueryMatchesEntityIdsNamesAndKeywordsInAnyCase(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $this->register(self::RP1, ['openid_relying_party']);
        $this->collection->save(self::OP, [], ['openid_provider' => [
            'display_name#mk' => 'Универзитетски OP',
            'keywords'        => ['university', 'login'],
        ]], [], null, 1);

        $this->assertSame([self::OP], $this->ids(['query' => ['УНИВЕРЗИТЕТСКИ']]));
        $this->assertSame([self::OP], $this->ids(['query' => ['Login']]));
        $this->assertSame([self::RP1], $this->ids(['query' => ['rp1.example']]));
        $this->assertSame([], $this->ids(['query' => ['nothing matches']]));
    }


    public function testPagesFollowTheNextPointer(): void
    {
        foreach ([self::OP, self::RP1, self::RP2] as $entityId) {
            $this->register($entityId, ['openid_provider']);
        }

        $first = $this->page(['limit' => ['2']]);
        $this->assertSame([self::OP, self::RP1], array_column($first['entities'], 'entity_id'));
        $this->assertSame(self::RP2, $first['next'] ?? null);

        $second = $this->page(['limit' => ['2'], 'from' => [self::RP2]]);
        $this->assertSame([self::RP2], array_column($second['entities'], 'entity_id'));
        $this->assertArrayNotHasKey('next', $second);
    }


    public function testANextPointerStaysValidWhenItsEntityLeaves(): void
    {
        foreach ([self::OP, self::RP1, self::RP2] as $entityId) {
            $this->register($entityId, ['openid_provider']);
        }

        $next = $this->page(['limit' => ['1']])['next'] ?? null;
        $this->assertSame(self::RP1, $next);
        $this->subordinates->delete(self::RP1);

        $this->assertSame([self::RP2], $this->ids(['from' => [$next]]));
    }


    public function testPagesNeverExceedTheMaximumPageSize(): void
    {
        foreach ([self::OP, self::RP1, self::RP2] as $entityId) {
            $this->register($entityId, ['openid_provider']);
        }

        $service = $this->service(maxPageSize: 2);

        foreach ([[], ['limit' => ['50']]] as $params) {
            $page = $service->page(EntityCollectionRequest::fromParameters($params));
            $this->assertCount(2, $page['entities']);
            $this->assertSame(self::RP2, $page['next'] ?? null);
        }
    }


    public function testInfoClaimsLocalesAndEntityTypesNarrowTheEntityInfos(): void
    {
        $this->register(self::OP, ['openid_provider']);
        $this->collection->save(self::OP, ['openid_provider', 'federation_entity'], [
            'openid_provider'   => [
                'display_name'       => 'OP',
                'display_name#de'    => 'OP (de)',
                'display_name#de-AT' => 'OP (at)',
                'display_name#mk'    => 'OP (mk)',
                'logo_uri'           => 'https://op.example.org/logo.png',
            ],
            'federation_entity' => ['organization_name' => 'Example Org'],
        ], [], null, 1);

        $infos = static fn(array $page): mixed => $page['entities'][0]['entity_infos'] ?? null;

        $this->assertSame(
            ['openid_provider' => ['display_name' => 'OP', 'display_name#de' => 'OP (de)', 'display_name#de-AT' => 'OP (at)']],
            $infos($this->page(['info_claims' => ['display_name'], 'locale' => ['de']])),
        );
        $this->assertSame(
            ['openid_provider' => ['logo_uri' => 'https://op.example.org/logo.png']],
            $infos($this->page(['info_claims' => ['logo_uri']])),
        );
        $this->assertSame(
            ['openid_provider'],
            array_keys((array) $infos($this->page(['entity_type' => ['openid_provider']]))),
        );
    }


    public function testOnlyThisTrustAnchorsCollectionIsServed(): void
    {
        $this->assertSame([], $this->page(['trust_anchor' => [self::ENTITY_ID]])['entities']);

        try {
            $this->page(['trust_anchor' => ['https://other-ta.example.org']]);
            $this->fail('Another trust anchor was accepted.');
        } catch (EntityCollectionException $e) {
            $this->assertSame('invalid_trust_anchor', $e->errorCode);
            $this->assertSame(404, $e->httpStatus);
        }
    }


    public function testLastUpdatedCoversRefreshesAndRegistryChanges(): void
    {
        $this->assertArrayNotHasKey('last_updated', $this->page([]));

        (new SettingsRepository($this->pdo))->set(SettingsRepository::ENTITY_COLLECTION_REFRESHED_AT, 1000);
        $this->assertSame(1000, $this->page([])['last_updated'] ?? null);

        $this->register(self::OP, ['openid_provider'], registeredAt: 2000);
        $this->assertSame(2000, $this->page([])['last_updated'] ?? null);
    }


    // -------------------------------------------------------------------------

    /**
     * @param list<string> $types
     */
    private function register(string $entityId, array $types, string $status = 'active', int $registeredAt = 100): void
    {
        $this->subordinates->create(new Subordinate(
            entityId:       $entityId,
            entityType:     $types[0] ?? null,
            jwks:           null,
            metadataPolicy: null,
            extraClaims:    null,
            status:         $status,
            registeredAt:   $registeredAt,
            updatedAt:      null,
            entityTypes:    $types,
        ));
    }


    /**
     * A stored Trust Mark entry. The collection only reads `exp` from it: marks are verified
     * by the resolver before they are stored.
     *
     * @return array{trust_mark_type: string, trust_mark: string}
     */
    private function markEntry(string $type, ?int $exp = null): array
    {
        $payload = rtrim(strtr(base64_encode((string) json_encode([
            'trust_mark_type' => $type,
            'exp'             => $exp ?? time() + 3600,
        ])), '+/', '-_'), '=');

        return ['trust_mark_type' => $type, 'trust_mark' => 'eyJhbGciOiJub25lIn0.' . $payload . '.sig'];
    }


    /**
     * A resolver that resolves only the given subjects.
     *
     * @param array<string,\SimpleSAML\Module\oidanchor\Service\ResolveResult> $results
     */
    private function resolver(array $results): FederationResolver
    {
        $resolver = $this->createStub(FederationResolver::class);
        $resolver->method('resolve')->willReturnCallback(
            static fn(string $sub): ResolveResult => $results[$sub]
                ?? throw ResolveException::invalidTrustChain('no chain in this test'),
        );

        return $resolver;
    }


    /**
     * @param array<string,array<string,mixed>> $metadata
     * @param list<array{trust_mark_type: string, trust_mark: string}> $trustMarks
     */
    private function resolved(string $sub, array $metadata, array $trustMarks = []): ResolveResult
    {
        return new ResolveResult($sub, $this->createStub(TrustChain::class), [], $metadata, $trustMarks, [], time() + 3600);
    }


    private function service(int $maxPageSize = 100): EntityCollectionService
    {
        return new EntityCollectionService(
            self::ENTITY_ID,
            $this->subordinates,
            $this->collection,
            new SettingsRepository($this->pdo),
            $maxPageSize,
        );
    }


    /**
     * @param array<string,list<string>> $params
     * @return array{entities: list<array<string,mixed>>, next?: string, last_updated?: int}
     */
    private function page(array $params): array
    {
        return $this->service()->page(EntityCollectionRequest::fromParameters($params));
    }


    /**
     * @param array<string,list<string>> $params
     * @return list<mixed>
     */
    private function ids(array $params): array
    {
        return array_column($this->page($params)['entities'], 'entity_id');
    }
}
