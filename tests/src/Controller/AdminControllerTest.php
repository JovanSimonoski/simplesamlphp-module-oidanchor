<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller;

use PHPUnit\Framework\Attributes\CoversClass;
use SimpleSAML\Configuration;
use SimpleSAML\Module\oidanchor\Controller\AdminController;
use SimpleSAML\Session;
use SimpleSAML\Test\Module\oidanchor\TestCase;
use Symfony\Component\HttpFoundation\Request;

#[CoversClass(AdminController::class)]
final class AdminControllerTest extends TestCase
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


    public function testCsrfTokenIsStableWithinASession(): void
    {
        $controller = $this->controller();
        $token      = $controller->token();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $token);
        $this->assertSame($token, $controller->token());
    }


    public function testMatchingCsrfTokenIsAccepted(): void
    {
        $controller = $this->controller();

        $this->assertTrue($controller->check($this->post(['csrf_token' => $controller->token()])));
    }


    public function testMissingOrWrongCsrfTokenIsRejected(): void
    {
        $controller = $this->controller();
        $controller->token();

        $this->assertFalse($controller->check($this->post([])));
        $this->assertFalse($controller->check($this->post(['csrf_token' => str_repeat('0', 64)])));
    }


    public function testCsrfTokenInTheQueryStringIsNotAccepted(): void
    {
        $controller = $this->controller();
        $request    = Request::create('/?csrf_token=' . $controller->token(), 'POST');

        $this->assertFalse($controller->check($request));
    }


    public function testNoCsrfTokenIsAcceptedBeforeOneWasIssued(): void
    {
        $this->assertFalse($this->controller()->check($this->post(['csrf_token' => ''])));
    }


    public function testFlashMessageIsShownOnce(): void
    {
        $controller = $this->controller();
        $controller->flash('success', 'Saved.');

        $this->assertSame(['type' => 'success', 'text' => 'Saved.'], $controller->takeFlash());
        $this->assertNull($controller->takeFlash());
    }


    public function testControllersDoNotConsumeEachOthersFlashMessages(): void
    {
        $this->controller()->flash('success', 'Saved.');

        $this->assertNull($this->controller('oidanchor_other_flash')->takeFlash());
        $this->assertNotNull($this->controller()->takeFlash());
    }


    /**
     * @param array<string,string> $body
     */
    private function post(array $body): Request
    {
        return Request::create('/oidanchor/admin/subordinates/x/delete', 'POST', $body);
    }


    /**
     * A concrete admin controller exposing the protected helpers.
     */
    private function controller(string $flashKey = 'oidanchor_test_flash'): object
    {
        $controller = $flashKey === 'oidanchor_test_flash'
            ? new class (Configuration::loadFromArray([])) extends AdminController {
                use ExposesAdminHelpers;


                protected const string FLASH_KEY = 'oidanchor_test_flash';
            }
            : new class (Configuration::loadFromArray([])) extends AdminController {
                use ExposesAdminHelpers;


                protected const string FLASH_KEY = 'oidanchor_other_flash';
            };

        return $controller;
    }
}
