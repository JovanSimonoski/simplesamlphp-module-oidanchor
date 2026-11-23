<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Service;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use SimpleSAML\Module\oidanchor\Service\FederationHttpClient;
use SimpleSAML\Test\Module\oidanchor\TestCase;

#[CoversClass(FederationHttpClient::class)]
final class FederationHttpClientTest extends TestCase
{
    /**
     * @return array<string,array{string}>
     */
    public static function nonPublicHosts(): array
    {
        return [
            'loopback'            => ['127.0.0.1'],
            'private 10/8'        => ['10.1.2.3'],
            'private 192.168/16'  => ['192.168.1.10'],
            'cloud metadata'      => ['169.254.169.254'],
            'unspecified'         => ['0.0.0.0'],
            'IPv6 loopback'       => ['::1'],
            'IPv6 bracketed'      => ['[::1]'],
            'IPv6 unique local'   => ['fd00::1'],
            'localhost name'      => ['localhost'],
            'unresolvable name'   => ['does-not-exist.invalid'],
        ];
    }


    #[DataProvider('nonPublicHosts')]
    public function testNonPublicHostsAreRefused(string $host): void
    {
        $this->expectException(RuntimeException::class);
        FederationHttpClient::publicAddress($host);
    }


    public function testPublicAddressesAreAllowed(): void
    {
        $this->assertSame('8.8.8.8', FederationHttpClient::publicAddress('8.8.8.8'));
        $this->assertSame('2001:4860:4860::8888', FederationHttpClient::publicAddress('[2001:4860:4860::8888]'));
    }


    public function testRequestsToInternalHostsAreRefusedBeforeConnecting(): void
    {
        $mock   = new MockHandler([new Response(200)]);
        $client = FederationHttpClient::create($this->moduleConfig(), 'test', $mock);

        try {
            $client->get('https://169.254.169.254/latest/meta-data/');
            $this->fail('The request reached the handler.');
        } catch (ConnectException $e) {
            $this->assertStringContainsString('non-public', $e->getMessage());
        }

        $this->assertCount(1, $mock, 'The handler must not have been called.');
    }


    public function testRequestsArePinnedToTheCheckedAddress(): void
    {
        $mock   = new MockHandler([new Response(200)]);
        $client = FederationHttpClient::create($this->moduleConfig(), 'test', $mock);

        $client->get('https://8.8.8.8/.well-known/openid-federation');

        $this->assertSame(['8.8.8.8:443:8.8.8.8'], $mock->getLastOptions()['curl'][CURLOPT_RESOLVE] ?? null);
    }


    public function testPrivateNetworksCanBeAllowedForDevelopment(): void
    {
        $mock   = new MockHandler([new Response(200)]);
        $config = $this->moduleConfig(['resolve' => ['allow_private_networks' => true]]);

        $response = FederationHttpClient::create($config, 'test', $mock)->get('https://127.0.0.1/');

        $this->assertSame(200, $response->getStatusCode());
    }
}
