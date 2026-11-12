<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\Resolve;
use SimpleSAML\Module\oidanchor\Database\PdoFactory;
use SimpleSAML\Module\oidanchor\Repository\RateLimitRepository;
use SimpleSAML\Module\oidanchor\Repository\ResolveCacheRepository;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(Resolve::class)]
#[CoversClass(RateLimitRepository::class)]
#[CoversClass(ResolveCacheRepository::class)]
final class ResolveTest extends TestCase
{
    /** A subject the outbound guard refuses, so a resolution fails without any network access. */
    private const string INTERNAL_SUB = 'https://127.0.0.1/leaf';


    public function testFetchFailuresDoNotRevealNetworkDetail(): void
    {
        $this->preloadModuleConfig();

        $body = $this->body($response = $this->resolve(self::INTERNAL_SUB));

        $this->assertSame(404, $response->getStatusCode());
        $this->assertSame('not_found', $body['error']);
        $this->assertSame('The Entity Configuration of the subject could not be fetched.', $body['error_description']);
    }


    public function testCacheMissesAreRateLimitedPerClient(): void
    {
        $this->preloadModuleConfig(['resolve' => ['rate_limit' => 2]]);

        $this->assertSame(404, $this->resolve(self::INTERNAL_SUB)->getStatusCode());
        $this->assertSame(404, $this->resolve(self::INTERNAL_SUB)->getStatusCode());

        $limited = $this->resolve(self::INTERNAL_SUB);
        $this->assertSame(429, $limited->getStatusCode());
        $this->assertSame('temporarily_unavailable', $this->body($limited)['error']);
        $this->assertGreaterThan(0, (int) $limited->headers->get('Retry-After'));

        // Another client is unaffected.
        $this->assertSame(404, $this->resolve(self::INTERNAL_SUB, '198.51.100.7')->getStatusCode());
    }


    public function testCachedResponsesAreServedWithoutResolvingOrCounting(): void
    {
        $config = $this->preloadModuleConfig(['resolve' => ['rate_limit' => 1]]);
        $cached = 'eyJhbGciOiJub25lIn0.' . rtrim(strtr(base64_encode((string) json_encode(['exp' => time() + 300])), '+/', '-_'), '=') . '.sig';
        (new ResolveCacheRepository(PdoFactory::get($config)))->put(
            ResolveCacheRepository::keyFor(self::INTERNAL_SUB, self::ENTITY_ID, null),
            $cached,
            time() + 300,
        );

        foreach ([1, 2, 3] as $attempt) {
            $response = $this->resolve(self::INTERNAL_SUB);
            $this->assertSame(200, $response->getStatusCode(), "attempt $attempt");
            $this->assertSame($cached, $response->getContent());
        }
    }


    public function testRateLimitWindowsReset(): void
    {
        $repo = new RateLimitRepository($this->pdo);

        $this->assertNull($repo->hit('b', 1, 60, 1000));
        $this->assertSame(59, $repo->hit('b', 1, 60, 1001));
        $this->assertNull($repo->hit('b', 1, 60, 1060));
    }


    private function resolve(string $sub, string $clientIp = '203.0.113.10'): Response
    {
        $request = Request::create('/resolve', 'GET', ['sub' => $sub, 'trust_anchor' => self::ENTITY_ID], server: [
            'REMOTE_ADDR' => $clientIp,
        ]);

        return (new Resolve(Configuration::loadFromArray([])))->resolve($request);
    }


    /**
     * @return array<string,mixed>
     */
    private function body(Response $response): array
    {
        return (array) json_decode((string) $response->getContent(), true);
    }
}
