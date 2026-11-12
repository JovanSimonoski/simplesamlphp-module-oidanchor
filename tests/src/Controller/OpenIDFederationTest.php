<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\OpenIDFederation;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(OpenIDFederation::class)]
final class OpenIDFederationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->preloadModuleConfig();
    }


    public function testIntermediateFilterIsRejectedAsUnsupported(): void
    {
        $response = $this->list(['intermediate' => 'true']);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('unsupported_parameter', json_decode((string) $response->getContent(), true)['error']);
    }


    public function testTrustMarkedMustBeABoolean(): void
    {
        $response = $this->list(['trust_marked' => 'yes']);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertSame('invalid_request', json_decode((string) $response->getContent(), true)['error']);
    }


    public function testSupportedFiltersAreAccepted(): void
    {
        $response = $this->list(['entity_type' => 'openid_provider', 'trust_marked' => 'true', 'trust_mark_type' => 'https://x']);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame([], json_decode((string) $response->getContent(), true));
    }


    public function testDisabledListEndpointAnswersNotFound(): void
    {
        $this->preloadModuleConfig(['federation_list_endpoint_enabled' => false]);

        $response = $this->list([]);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame('not_found', json_decode((string) $response->getContent(), true)['error']);
    }


    public function testDisabledFetchEndpointAnswersNotFound(): void
    {
        $this->preloadModuleConfig(['federation_fetch_endpoint_enabled' => false]);

        $response = (new OpenIDFederation(Configuration::loadFromArray([])))
            ->fetch(Request::create('/federation/fetch', 'GET', ['sub' => 'https://leaf.example.org']));

        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame('not_found', json_decode((string) $response->getContent(), true)['error']);
    }


    public function testEnabledFetchEndpointStillValidatesTheRequest(): void
    {
        $response = (new OpenIDFederation(Configuration::loadFromArray([])))
            ->fetch(Request::create('/federation/fetch', 'GET'));

        $this->assertSame(400, $response->getStatusCode());
    }


    /**
     * @param array<string,string> $query
     */
    private function list(array $query): \Symfony\Component\HttpFoundation\JsonResponse
    {
        return (new OpenIDFederation(Configuration::loadFromArray([])))
            ->subordinateList(Request::create('/federation/list', 'GET', $query));
    }
}
