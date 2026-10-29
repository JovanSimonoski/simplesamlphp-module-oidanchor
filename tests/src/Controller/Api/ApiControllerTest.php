<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller\Api;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\Api\ApiController;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(ApiController::class)]
final class ApiControllerTest extends TestCase
{
    public function testMatchingCredentialsAreAccepted(): void
    {
        $this->preloadModuleConfig(['api_admin_username' => 'gateway', 'api_admin_password' => 's3cret']);

        $this->assertTrue($this->controller()->basicAuthMatches($this->request('gateway', 's3cret')));
    }


    /**
     * @return array<string,array{?string, ?string}>
     */
    public static function wrongCredentials(): array
    {
        return [
            'wrong password' => ['gateway', 'nope'],
            'wrong user'     => ['admin', 's3cret'],
            'no header'      => [null, null],
        ];
    }


    #[DataProvider('wrongCredentials')]
    public function testWrongOrMissingCredentialsAreRejected(?string $user, ?string $pass): void
    {
        $this->preloadModuleConfig(['api_admin_username' => 'gateway', 'api_admin_password' => 's3cret']);

        $this->assertFalse($this->controller()->basicAuthMatches($this->request($user, $pass)));
    }


    /**
     * @return array<string,array{array<string,mixed>}>
     */
    public static function unconfiguredCredentials(): array
    {
        return [
            'none set'      => [[]],
            'only username' => [['api_admin_username' => 'gateway']],
            'only password' => [['api_admin_password' => 's3cret']],
            'empty strings' => [['api_admin_username' => '', 'api_admin_password' => '']],
        ];
    }


    /**
     * @param array<string,mixed> $config
     */
    #[DataProvider('unconfiguredCredentials')]
    public function testBasicAuthIsDisabledUnlessBothCredentialsAreConfigured(array $config): void
    {
        $this->preloadModuleConfig($config);

        // Even a request whose credentials match the configured half must not pass.
        $this->assertFalse($this->controller()->basicAuthMatches($this->request('gateway', 's3cret')));
    }


    public function testCredentialsAreReadFromTheAuthorizationHeader(): void
    {
        $request = Request::create('/', 'GET', server: [
            'HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('gateway:pa:ss'),
        ]);

        $this->assertSame(['gateway', 'pa:ss'], $this->controller()->basicCredentials($request));
    }


    public function testCredentialsAreReadFromTheRedirectedAuthorizationHeader(): void
    {
        $request = Request::create('/', 'GET', server: [
            'REDIRECT_HTTP_AUTHORIZATION' => 'Basic ' . base64_encode('gateway:s3cret'),
        ]);

        $this->assertSame(['gateway', 's3cret'], $this->controller()->basicCredentials($request));
    }


    public function testNonBasicAuthorizationYieldsNoCredentials(): void
    {
        $request = Request::create('/', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer abc']);

        $this->assertNull($this->controller()->basicCredentials($request));
    }


    /**
     * @return array<string,array{array<string,string>, bool}>
     */
    public static function originHeaders(): array
    {
        return [
            'same origin'                 => [['HTTP_ORIGIN' => 'https://ta.example.org'], true],
            'same origin, trailing slash' => [['HTTP_ORIGIN' => 'https://ta.example.org/'], true],
            'configured extra origin'     => [['HTTP_ORIGIN' => 'https://proxy.example.org'], true],
            'foreign origin'              => [['HTTP_ORIGIN' => 'https://evil.example.org'], false],
            'other scheme'                => [['HTTP_ORIGIN' => 'http://ta.example.org'], false],
            'opaque origin'               => [['HTTP_ORIGIN' => 'null'], false],
            'origin wins over fetch site' => [['HTTP_ORIGIN' => 'https://evil.example.org', 'HTTP_SEC_FETCH_SITE' => 'same-origin'], false],
            'fetch site same-origin'      => [['HTTP_SEC_FETCH_SITE' => 'same-origin'], true],
            'fetch site none'             => [['HTTP_SEC_FETCH_SITE' => 'none'], true],
            'fetch site cross-site'       => [['HTTP_SEC_FETCH_SITE' => 'cross-site'], false],
            'fetch site same-site'        => [['HTTP_SEC_FETCH_SITE' => 'same-site'], false],
            'no browser headers'          => [[], false],
        ];
    }


    /**
     * @param array<string,string> $headers
     */
    #[DataProvider('originHeaders')]
    public function testSessionWritesMustComeFromThisOrigin(array $headers, bool $expected): void
    {
        $this->preloadModuleConfig(['api_allowed_origins' => ['https://proxy.example.org/']]);
        $request = Request::create('https://ta.example.org/api/v1/admin/kms/rotate', 'POST', server: $headers);

        $this->assertSame($expected, $this->controller()->isSameOrigin($request));
    }


    private function request(?string $user, ?string $pass): Request
    {
        $server = $user === null ? [] : ['PHP_AUTH_USER' => $user, 'PHP_AUTH_PW' => (string) $pass];

        return Request::create('/api/v1/admin/subordinates', 'GET', server: $server);
    }


    /**
     * The auth helpers are protected; expose them through a minimal subclass.
     */
    private function controller(): object
    {
        return new class (Configuration::loadFromArray([])) extends ApiController {
            public function basicAuthMatches(Request $request): bool
            {
                return parent::basicAuthMatches($request);
            }


            /**
             * @return array{0: string, 1: string}|null
             */
            public function basicCredentials(Request $request): ?array
            {
                return parent::basicCredentials($request);
            }


            public function isSameOrigin(Request $request): bool
            {
                return parent::isSameOrigin($request);
            }
        };
    }
}
