<?php

declare(strict_types=1);

namespace SimpleSAML\Module\oidanchor\Controller;

use SimpleSAML\Configuration;
use SimpleSAML\Locale\Translate;
use SimpleSAML\Module;
use SimpleSAML\Module\admin\Controller\Menu;
use SimpleSAML\Session;
use SimpleSAML\Utils;
use SimpleSAML\XHTML\Template;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Throwable;

/**
 * Base class for the admin UI controllers: admin authentication, the per-session CSRF token
 * that every state-changing form posts as `csrf_token`, flash messages, and the common page
 * chrome (logout link, admin menu, translations).
 */
abstract class AdminController
{
    /** Session data type holding this controller's flash message; each controller has its own. */
    protected const string FLASH_KEY = 'oidanchor_admin_flash';


    public function __construct(
        protected Configuration $config,
    ) {
    }


    protected function requireAdmin(): void
    {
        (new Utils\Auth())->requireAdmin();
    }


    /**
     * Finish an admin page: logout link, pending flash message, CSRF token, the module's
     * translations and the admin menu.
     */
    protected function page(Template $t): Template
    {
        $authUtils = new Utils\Auth();

        $t->data['logouturl'] = $authUtils->getAdminLogoutURL();
        $t->data['flash']     = $this->popFlash();
        $t->data['csrfToken'] = $this->csrfToken();

        $t->getLocalization()->addModuleDomain('oidanchor');

        $menu = new Menu();
        $menu->addOption('logout', $authUtils->getAdminLogoutURL(), Translate::noop('Log out'));

        return $menu->insert($t);
    }


    protected function csrfToken(): string
    {
        $session = Session::getSessionFromRequest();
        $token   = $session->getData('oidanchor_csrf', 'token');

        if (!is_string($token) || $token === '') {
            $token = bin2hex(random_bytes(32));
            $session->setData('oidanchor_csrf', 'token', $token);
        }

        return $token;
    }


    protected function assertCsrf(Request $request): bool
    {
        $session  = Session::getSessionFromRequest();
        $expected = $session->getData('oidanchor_csrf', 'token');
        $provided = (string) $request->request->get('csrf_token', '');

        return is_string($expected) && $expected !== '' && hash_equals($expected, $provided);
    }


    /**
     * Reject a POST whose CSRF token is missing or wrong: flash an error and go back to $path.
     */
    protected function csrfFailure(string $path): RedirectResponse
    {
        $this->pushFlash('error', 'Invalid or missing CSRF token. Please try again.');

        return new RedirectResponse(Module::getModuleURL($path));
    }


    protected function pushFlash(string $type, string $message): void
    {
        Session::getSessionFromRequest()->setData(static::FLASH_KEY, 'msg', ['type' => $type, 'text' => $message]);
    }


    /**
     * @return array{type: string, text: string}|null
     */
    protected function popFlash(): ?array
    {
        $session = Session::getSessionFromRequest();

        /** @var array{type: string, text: string}|null $flash */
        $flash = $session->getData(static::FLASH_KEY, 'msg');

        if ($flash !== null) {
            $session->deleteData(static::FLASH_KEY, 'msg');
        }

        return $flash;
    }


    /**
     * The logged-in admin's uid, for audit log lines (best-effort).
     */
    protected function getAdminUsername(): string
    {
        try {
            $authId = Session::getSessionFromRequest()->getAuthData('admin', 'Attributes');

            if (is_array($authId) && isset($authId['uid'][0])) {
                return (string) $authId['uid'][0];
            }
        } catch (Throwable) {
            // Best-effort.
        }

        return 'admin';
    }
}
