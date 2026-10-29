<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use SimpleSAML\Session;
use Symfony\Component\HttpFoundation\Request;

/**
 * Per-session CSRF token for the admin UI. Every state-changing admin form posts the token as
 * `csrf_token`; controllers reject the POST when it does not match the session's token.
 */
trait AdminCsrfTrait
{
    private function csrfToken(): string
    {
        $session = Session::getSessionFromRequest();
        $token   = $session->getData('oidanchor_csrf', 'token');

        if (!is_string($token) || $token === '') {
            $token = bin2hex(random_bytes(32));
            $session->setData('oidanchor_csrf', 'token', $token);
        }

        return $token;
    }


    private function assertCsrf(Request $request): bool
    {
        $session  = Session::getSessionFromRequest();
        $expected = $session->getData('oidanchor_csrf', 'token');
        $provided = (string) $request->request->get('csrf_token', '');

        return is_string($expected) && $expected !== '' && hash_equals($expected, $provided);
    }
}
