<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\OpenIDFederation;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Module\oidanchor\Entity\Subordinate;
use SimpleSAML\Module\oidanchor\Repository\EntityCollectionRepository;
use SimpleSAML\Module\oidanchor\Repository\SubordinateRepository;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(OpenIDFederation::class)]
final class EntityCollectionEndpointTest extends TestCase
{
    private const string OP = 'https://op.example.org';

    private const string RP = 'https://rp.example.org';


    protected function setUp(): void
    {
        parent::setUp();

        $pdo          = PdoFactory::get($this->preloadModuleConfig());
        $subordinates = new SubordinateRepository($pdo);
        foreach ([self::OP => 'openid_provider', self::RP => 'openid_relying_party', 'https://as.example.org' => 'oauth_authorization_server'] as $entityId => $type) {
            $subordinates->create(new Subordinate($entityId, $type, null, null, null, 'active', 100, null));
        }

        (new EntityCollectionRepository($pdo))->save(
            self::OP,
            ['openid_provider'],
            ['openid_provider' => ['display_name' => 'Пример OP', 'logo_uri' => 'https://op.example.org/logo.png']],
            [],
            null,
            100,
        );
    }


    public function testRepeatedQueryParametersAreAllApplied(): void
    {
        $response = $this->get('entity_type=openid_provider&entity_type=openid_relying_party');

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame('application/json', $response->headers->get('Content-Type'));
        $this->assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        $this->assertSame([self::OP, self::RP], array_column($this->body($response)['entities'], 'entity_id'));
    }


    public function testTheResponseIsTheSpecificationsShape(): void
    {
        $response = $this->get('entity_type=openid_provider');

        $this->assertSame([
            'entities'     => [[
                'entity_id'    => self::OP,
                'entity_types' => ['openid_provider'],
                'entity_infos' => ['openid_provider' => ['display_name' => 'Пример OP', 'logo_uri' => 'https://op.example.org/logo.png']],
            ]],
            'last_updated' => 100,
        ], $this->body($response));
        $this->assertStringContainsString('"entity_id":"https://op.example.org"', (string) $response->getContent());
        $this->assertStringContainsString('Пример OP', (string) $response->getContent());
    }


    public function testFormEncodedPostIsAccepted(): void
    {
        $response = (new OpenIDFederation(Configuration::loadFromArray([])))->collection(Request::create(
            '/federation/collection',
            'POST',
            server: ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'],
            content: 'entity_type=openid_relying_party&entity_type=oauth_authorization_server',
        ));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(['https://as.example.org', self::RP], array_column($this->body($response)['entities'], 'entity_id'));
    }


    public function testOtherPostBodiesAreRejected(): void
    {
        $response = (new OpenIDFederation(Configuration::loadFromArray([])))->collection(Request::create(
            '/federation/collection',
            'POST',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: '{"entity_type":"openid_provider"}',
        ));

        $this->assertError($response, 400, 'invalid_request');
    }


    public function testErrorsUseTheSpecificationsCodes(): void
    {
        $this->assertError($this->get('trust_anchor=https%3A%2F%2Fother-ta.example.org'), 404, 'invalid_trust_anchor');
        $this->assertError($this->get('entity_claims=metadata'), 400, 'unsupported_claim');
        $this->assertError($this->get('limit=0'), 400, 'invalid_request');
    }


    public function testADisabledEndpointAnswersNotFound(): void
    {
        $this->preloadModuleConfig(['federation_collection_endpoint_enabled' => false]);

        $this->assertError($this->get(''), 404, 'not_found');
    }


    /**
     * A GET request as the web server delivers it: the raw query string, repeated names included.
     */
    private function get(string $queryString): Response
    {
        $request = new Request(server: [
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI'    => '/federation/collection?' . $queryString,
            'QUERY_STRING'   => $queryString,
        ]);

        return (new OpenIDFederation(Configuration::loadFromArray([])))->collection($request);
    }


    private function assertError(Response $response, int $status, string $error): void
    {
        $this->assertSame($status, $response->getStatusCode());
        $this->assertSame($error, $this->body($response)['error'] ?? null);
        $this->assertNotEmpty($this->body($response)['error_description'] ?? null);
    }


    /**
     * @return array<string,mixed>
     */
    private function body(Response $response): array
    {
        return (array) json_decode((string) $response->getContent(), true);
    }
}
