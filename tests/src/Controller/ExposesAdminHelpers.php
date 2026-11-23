<?php

declare(strict_types=1);

namespace SimpleSAML\Test\Module\oidanchor\Controller;

use Symfony\Component\HttpFoundation\Request;

/**
 * Public wrappers around AdminController's protected helpers, for test doubles.
 */
trait ExposesAdminHelpers
{
    public function token(): string
    {
        return $this->csrfToken();
    }


    public function check(Request $request): bool
    {
        return $this->assertCsrf($request);
    }


    public function flash(string $type, string $message): void
    {
        $this->pushFlash($type, $message);
    }


    /**
     * @return array{type: string, text: string}|null
     */
    public function takeFlash(): ?array
    {
        return $this->popFlash();
    }
}
