<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller\Api;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\Api\EcTrustMarksApi;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

#[CoversClass(EcTrustMarksApi::class)]
final class EcTrustMarksApiTest extends TestCase
{
    private const string TYPE = 'https://issuer.example.org/tm/member';


    protected function setUp(): void
    {
        parent::setUp();

        $this->preloadModuleConfig([
            'database_dsn'       => $this->useFileDatabase(),
            'api_admin_username' => 'gateway',
            'api_admin_password' => 's3cret',
        ]);
    }


    public function testAMarkAboutThisTrustAnchorIsAccepted(): void
    {
        $response = $this->create(['trust_mark_type' => self::TYPE, 'trust_mark' => $this->mark()]);

        $this->assertSame(201, $response->getStatusCode());
    }


    public function testAMarkAboutAnotherEntityIsRejected(): void
    {
        $response = $this->create(['trust_mark' => $this->mark(['sub' => 'https://other.example.org'])]);

        $this->assertSame(400, $response->getStatusCode());
        $this->assertStringContainsString('issued for this Trust Anchor', (string) $response->getContent());
    }


    public function testAMarkOfAnotherTypeThanDeclaredIsRejected(): void
    {
        $response = $this->create(['trust_mark_type' => 'https://issuer.example.org/tm/other', 'trust_mark' => $this->mark()]);

        $this->assertSame(400, $response->getStatusCode());
    }


    public function testSomethingThatIsNotATrustMarkIsRejected(): void
    {
        $this->assertSame(400, $this->create(['trust_mark' => 'not.a.jwt'])->getStatusCode());
    }


    public function testPatchingInAMarkAboutAnotherEntityIsRejected(): void
    {
        $created = $this->create(['trust_mark_type' => self::TYPE, 'trust_mark' => $this->mark()]);
        $id      = (string) json_decode((string) $created->getContent(), true)['id'];

        $response = (new EcTrustMarksApi(Configuration::loadFromArray([])))->patch(
            $this->request('PATCH', ['trust_mark' => $this->mark(['sub' => 'https://other.example.org'])]),
            $id,
        );

        $this->assertSame(400, $response->getStatusCode());
    }


    /**
     * @param array<string,mixed> $overrides
     */
    private function mark(array $overrides = []): string
    {
        return $this->keys(Configuration::getConfig('module_oidanchor.php'))->signTrustMark($overrides + [
            'iss'             => 'https://issuer.example.org',
            'sub'             => self::ENTITY_ID,
            'trust_mark_type' => self::TYPE,
            'iat'             => time(),
            'exp'             => time() + 3600,
        ]);
    }


    /**
     * @param array<string,mixed> $body
     */
    private function create(array $body): Response
    {
        return (new EcTrustMarksApi(Configuration::loadFromArray([])))->create($this->request('POST', $body));
    }


    /**
     * @param array<string,mixed> $body
     */
    private function request(string $method, array $body): Request
    {
        return Request::create('/api/v1/admin/entity-configuration/trust-marks', $method, server: [
            'PHP_AUTH_USER' => 'gateway',
            'PHP_AUTH_PW'   => 's3cret',
        ], content: (string) json_encode($body));
    }
}
