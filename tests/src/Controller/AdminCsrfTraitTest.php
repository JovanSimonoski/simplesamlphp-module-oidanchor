<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller;

use PHPUnit\Framework\Attributes\CoversTrait;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\AdminCsrfTrait;
use SimpleSAML\Session;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversTrait(AdminCsrfTrait::class)]
final class AdminCsrfTraitTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Configuration::setPreLoadedConfig(Configuration::loadFromArray([]), 'config.php');
        Session::useTransientSession();
    }


    protected function tearDown(): void
    {
        Session::clearInternalState();
        parent::tearDown();
    }


    public function testTokenIsStableWithinASession(): void
    {
        $csrf  = $this->csrf();
        $token = $csrf->token();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $token);
        $this->assertSame($token, $csrf->token());
    }


    public function testMatchingTokenIsAccepted(): void
    {
        $csrf = $this->csrf();

        $this->assertTrue($csrf->check($this->post(['csrf_token' => $csrf->token()])));
    }


    public function testMissingOrWrongTokenIsRejected(): void
    {
        $csrf = $this->csrf();
        $csrf->token();

        $this->assertFalse($csrf->check($this->post([])));
        $this->assertFalse($csrf->check($this->post(['csrf_token' => str_repeat('0', 64)])));
    }


    public function testTokenInTheQueryStringIsNotAccepted(): void
    {
        $csrf    = $this->csrf();
        $request = Request::create('/?csrf_token=' . $csrf->token(), 'POST');

        $this->assertFalse($csrf->check($request));
    }


    public function testNoTokenIsAcceptedBeforeOneWasIssued(): void
    {
        $this->assertFalse($this->csrf()->check($this->post(['csrf_token' => ''])));
    }


    /**
     * @param array<string,string> $body
     */
    private function post(array $body): Request
    {
        return Request::create('/oidanchor/admin/subordinates/x/delete', 'POST', $body);
    }


    private function csrf(): object
    {
        return new class {
            use AdminCsrfTrait;


            public function token(): string
            {
                return $this->csrfToken();
            }


            public function check(Request $request): bool
            {
                return $this->assertCsrf($request);
            }
        };
    }
}
